# evtxkit — Windows Security/Sysmon Event Log Detection Toolkit — Build Spec

Implementation-ready spec for **evtxkit**: a Windows host-log detection
toolkit built from four TryHackMe rooms: **Windows Logging for SOC**
(fundamentals), **Windows Threat Detection 1** (Initial Access), **Windows
Threat Detection 2** (Persistence, Command and Control), and **Windows
Threat Detection 3** (Discovery, Collection, Credential Access,
Exfiltration). Companion to **nsmkit** (firewall/IDS/VPN log analysis),
**phishkit** (email/phishing analysis), **trafkit** (packet-native traffic
analysis), and **waapkit** (web application attack / WAF analysis). Where
those read network- or application-layer artifacts, evtxkit reads the
host itself — Windows Security, System, and Sysmon Operational event logs
— and is the first toolkit in the family that needs a real correlation
layer (process tree, Logon ID) as first-class infrastructure rather than
per-record matching.

This document specifies everything needed to reimplement the toolkit from
scratch: data model, ingestion formats, the correlation layer, every
detector's logic and thresholds, and the implementation traps found while
building the reference implementation in `evtxkit/`.

## 1. Scope and its limits

- **This is host-log detection, not live EDR.** Everything here reads
  already-collected event records — exported JSON, a real `.evtx` file, or
  a PowerShell history file. There's no process injection, no memory
  scanning, no live hooking. If an attacker's tooling never generates a
  qualifying Event ID (a fileless technique that leaves no Sysmon 11/13
  trace, disables Sysmon before acting, or clears the event log outright),
  this toolkit sees nothing — a stated limitation of log-based detection
  in general, and of every room this was built from.
- **PowerShell history has no timestamps.** `ConsoleHost_history.txt`
  records commands typed, in order, with no per-line time. Every event
  parsed from it gets `ts=0.0`; detectors that need `ts` (brute force,
  archive-then-execution correlation, transfer-to-network correlation)
  simply can't use it for that purpose, so the discovery detector groups
  PowerShell-history commands by session (no window check) rather than
  silently pretending a `ts=0.0` window check would mean anything.
- **PID reuse is a real correlation limitation, not a hidden one.** Windows
  reuses PIDs; the Security log's 4688 (unlike Sysmon 1) carries no
  ProcessGuid, so `ProcessTree`'s `pid:<ProcessId>` fallback key can, in a
  long-running log, join two genuinely unrelated processes that happened
  to reuse the same PID at different times. Sysmon's GUID keying doesn't
  have this problem — which is the room material's own stated reason to
  prefer Sysmon over bare 4688 wherever both are available.
- **A non-C: drive letter is not proof of a USB device.** `E:\malware.exe`
  matches `RemovableDriveExecutionDetector` the same way a mapped network
  drive would. The room material states this signal's own limitation
  ("you may find evidence of execution from external drives"); it isn't
  resolved here, just documented and left as one signal among several.

## 2. Package layout

```
evtxkit/
  evtxkit/
    models.py         EventRecord, Finding, AnalysisResult, Event ID constants
    config.py          Config dataclass -- every threshold, single source of truth
    util.py             IP classification, path/substring helpers, sliding-window aggregation
    parsers.py           JSON-Lines / .evtx / PowerShell-history ingestion, format auto-detection
    processtree.py       ProcessTree (ProcessGuid-keyed), Logon ID correlation helpers
    detectors/
      base.py           Detector ABC + @register + REGISTRY + run_detectors()
      logon.py           RdpBruteForceDetector, SuccessfulLogonAfterBruteForceDetector
      usermgmt.py         NewUserCreatedDetector, BackdooredAdminUserDetector,
                          PrivilegedGroupModificationDetector, PasswordResetDetector
      persistence.py      ServicePersistenceDetector, ScheduledTaskPersistenceDetector,
                          StartupFolderPersistenceDetector, RunKeyPersistenceDetector
      execution.py         DoubleExtensionExecutionDetector, ArchiveAttachmentExecutionDetector,
                          LnkPhishingDetector, RemovableDriveExecutionDetector
      discovery.py         DiscoveryCommandSequenceDetector
      collection.py        SensitiveDataAccessDetector, DataStagingArchiveDetector,
                          CredentialKeywordSearchDetector, PossibleDataStealerDetector
      c2_transfer.py       IngressToolTransferDetector, SuspiciousNetworkProcessDetector
    report.py            console / json / markdown / html renderers, chronological timeline
    cli.py               argparse subcommands (analyze / overview / sessions / rules)
    __init__.py           analyze() top-level entry point
  make_events.py          synthetic JSON-Lines generator (one scenario per detector + clean baseline)
  tests/test_evtxkit.py    unit + integration tests
  docs/WINDOWS_THREAT_DETECTION_BUILD_SPEC.md  this file
  README.md, pyproject.toml, .gitignore
```

Zero hard dependencies — everything is Python 3.10+ standard library
(`re`, `json`, `ipaddress`, `dataclasses`, `argparse`, `xml.etree.
ElementTree`, `collections`, `datetime`). `python-evtx` is an optional
extra (`pip install evtxkit[evtx]`) needed only to read a real binary
`.evtx` file directly; every detector and the full test suite run without
it against the normalized JSON-Lines format.

## 3. Data model (`models.py`)

```python
# Event ID constants, named everywhere instead of bare integers:
EVT_LOGON_SUCCESS = 4624;  EVT_LOGON_FAILURE = 4625
EVT_USER_CREATED = 4720;   EVT_USER_ENABLED = 4722;    EVT_USER_CHANGED = 4738
EVT_USER_DISABLED = 4725;  EVT_USER_DELETED = 4726
EVT_PASSWORD_CHANGED = 4723; EVT_PASSWORD_RESET = 4724
EVT_GROUP_MEMBER_ADDED = 4732; EVT_GROUP_MEMBER_REMOVED = 4733
EVT_PROCESS_CREATED_SECURITY = 4688
EVT_SERVICE_INSTALLED_SECURITY = 4697; EVT_SERVICE_INSTALLED_SYSTEM = 7045
EVT_SCHEDULED_TASK_CREATED = 4698
SYSMON_PROCESS_CREATE = 1; SYSMON_NETWORK_CONNECT = 3
SYSMON_FILE_CREATE = 11;   SYSMON_REGISTRY_SET = 13;   SYSMON_DNS_QUERY = 22

@dataclass
class EventRecord:
    index: int; event_id: int; channel: str   # "Security" | "System" | "Sysmon" | "PowerShellHistory"
    ts: float; computer: str = ""
    data: dict[str, str] = field(default_factory=dict)   # EventData Name/Value pairs, verbatim
    raw: str = ""
    # .time -> datetime; .get(*names, default="") reads the first present field
    # among aliases (e.g. e.get("IpAddress", "SourceNetworkAddress"));
    # .get_int(*names); convenience properties: logon_type, logon_id, source_ip,
    # target_user, subject_user, image, parent_image, command_line,
    # parent_command_line, process_id, parent_process_id, process_guid,
    # parent_process_guid, target_filename, target_object

@dataclass
class Finding:
    rule_id: str; title: str; tactic: str    # MITRE tactic name
    severity: str; confidence: str; description: str
    events: list[int] = field(default_factory=list)   # EventRecord.index values
    evidence: dict = field(default_factory=dict)
    recommendation: str = ""

@dataclass
class AnalysisResult:
    path: str; events: list[EventRecord] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    # .worst_severity ("info" if no findings); .findings_by_tactic
```

**Why one generic `EventRecord` instead of a dataclass per Event ID**:
there are 500+ documented Security Event IDs alone (Windows Logging for
SOC, task 2); only a couple dozen matter to the detectors here. A generic
record with a flexible `data` dict plus typed accessor properties scales
to "whatever Event ID shows up" without a combinatorial explosion of
near-identical dataclasses, and it's exactly the shape Event Viewer's own
XML "Details" tab already presents the data in.

**Why `.get()` takes multiple field-name aliases**: the same logical field
is spelled differently across event sources — a source IP is
`IpAddress` on a 4624/4625 logon event but `SourceNetworkAddress` on some
other channels; a Logon ID is `TargetLogonId` on a logon event but
`SubjectLogonId` on an action taken *by* an already-logged-on session.
Centralizing the alias list in the property once means every detector
gets the right field automatically instead of each one re-deriving which
Windows-version-dependent name applies.

## 4. Ingestion (`parsers.py`)

Three formats, one normalized output shape:

1. **Normalized JSON-Lines** (primary, zero dependencies) — one JSON
   object per line: `{"EventID": 4625, "Channel": "Security",
   "TimeCreated": "2026-09-06T09:00:01.1234567Z", "Computer": "...",
   "EventData": {"IpAddress": "203.0.113.77", "LogonType": "10", ...}}`,
   the shape `Get-WinEvent ... | ConvertTo-Json` or a Winlogbeat/Elastic
   export produces. `_parse_iso_ts` trims sub-microsecond digits (Windows
   emits 7 fractional digits; `datetime.fromisoformat` handles at most 6)
   before parsing, with a `strptime` fallback for anything else.
2. **Real `.evtx` binary files** — Windows' actual on-disk chunk/template
   format, what Event Viewer itself opens. Parsing that from scratch is a
   project of its own, so this path lazy-imports `Evtx.Evtx` from the
   optional `python-evtx` package and raises a clear, actionable
   `ImportError` naming the install command if it's missing — the same
   posture trafkit takes with `scapy` for pcap: a purpose-built external
   library handles the native binary container format, all detection
   logic stays the toolkit's own. Every record `python-evtx` yields is
   already XML (the same XML Event Viewer's "Details" tab shows), handed
   to `_xml_to_event_record`, which parses it with the standard library —
   nothing evtx-specific about the XML step itself.
3. **`ConsoleHost_history.txt`** — not an event log at all, but the room
   material calls it out as an essential companion source. One command per
   non-blank line, parsed into `EventRecord(event_id=-1,
   channel="PowerShellHistory", ts=0.0, data={"CommandLine": ..., "Image":
   "powershell.exe"})` so every command-line-matching detector (discovery,
   collection, C2 transfer) runs against it automatically, no separate
   code path — at the honest cost that `ts=0.0` means no time-windowed
   correlation can apply to entries from this source.

`detect_format(path)` picks by filename: `.evtx` suffix → `"evtx"`;
`consolehost_history` substring or `_history.txt` suffix → `"pshistory"`;
else → `"jsonl"`. `parse_event_file(path, format_hint=None)` dispatches,
letting the CLI's `--format` flag override auto-detection.

## 5. Correlation layer (`processtree.py`)

Two join keys, both lifted directly from the room material's own worked
techniques rather than invented:

- **Logon ID.** Windows Logging for SOC's own workbook step: "Copy the
  Logon ID field from the logon event... open Sysmon logs and search
  events with the same Logon ID." `events_for_logon_id(events, logon_id)`
  returns every event (any channel) carrying that ID in `LogonId`/
  `TargetLogonId`/`SubjectLogonId`; `find_logon_event(events, logon_id,
  event_id=4624)` finds the originating logon event itself. `evtxkit
  sessions <path> <logon_id>` is a direct CLI wrapper around this — the
  toolkit's answer to "what did this login session do."
- **ProcessGuid / ParentProcessGuid** (Sysmon-only). `ProcessTree` is
  built once per analysis run from every Sysmon 1 and Security 4688 event,
  keyed by `ProcessGuid` when present, falling back to `pid:<ProcessId>`
  otherwise (4688 carries no GUID at all). `parent_of`, `children_of`,
  `ancestry` (walks up to a max depth, breaking on a cycle), and `root_of`
  reconstruct "what launched what" — used by `ArchiveAttachmentExecutionDetector`
  and `LnkPhishingDetector` to confirm a specific parent (`explorer.exe`)
  launched a specific child, and available generally for any detector that
  needs lineage rather than a flat event list.

`run_detectors(events, config)` in `detectors/base.py` builds exactly one
`ProcessTree` per run and hands it to every registered detector alongside
the full event list — detectors that don't need lineage just ignore the
argument.

## 6. Detector catalogue

All thresholds live in `Config` (`config.py`); nothing here is a magic
number buried in detector code. Every `Finding.description` names the
concrete process/IP/user involved plus one sentence of *why this matters*
in the finding text itself (not left implicit), and every finding carries
a `recommendation`.

### Initial Access

- **`EVTX-LOGON-BRUTE`** (`RdpBruteForceDetector`) — groups failed 4625
  events by source IP, filtered to `REMOTE_LOGON_TYPES = (3, 10)`
  (Network, RemoteInteractive/RDP) and, when `external_ip_only` (default
  True), to non-private/non-reserved source IPs only. Fires when one IP's
  count within `brute_force_window_s` (default 300s) meets
  `brute_force_attempts_threshold` (default 15; the room's own worked
  example is "around 100 attempts," 15 is a conservative triage floor
  for a 5-minute window instead of demanding the room's full count).
- **`EVTX-LOGON-BRUTE-SUCCESS`** (`SuccessfulLogonAfterBruteForceDetector`)
  — correlates a 4624 success from a source IP that was just flagged as
  brute-forcing, within `successful_logon_correlation_window_s` (default
  1h) after that cluster. Elevated severity versus the brute-force finding
  alone: a successful logon following a brute-force cluster is
  materially worse than the brute force by itself.
- **`EVTX-EXEC-DOUBLEEXT`** (`DoubleExtensionExecutionDetector`) — a
  Sysmon 1 process image or command line matching
  `\.[A-Za-z0-9]{2,5}\.(exe|com|scr|cpl|bat|...)$` (e.g.
  `photo_2024_1_12.jpg.exe` — the room's own USB/phishing example).
- **`EVTX-EXEC-DOWNLOADED-ATTACHMENT`** (`ArchiveAttachmentExecutionDetector`)
  — correlates a Sysmon 11 file-create in a `download_dir_markers` path
  (Downloads) with a *later* Sysmon 1 execution of that exact same path,
  launched by `explorer.exe`, within `archive_to_execution_window_s`
  (default 600s). Requires the drop-then-execute pair specifically —
  execution alone or a drop with no follow-up execution doesn't fire this.
- **`EVTX-EXEC-LNK-PHISHING`** (`LnkPhishingDetector`) — correlates a
  preceding `.lnk` file-create in Downloads with a script-host process
  (matches `lnk_extension`/known script hosts) launched by `explorer.exe`
  within `lnk_to_execution_window_s` (default 120s). A bare script-host
  launch with no preceding LNK drop does not fire this detector (see trap
  #2 below) — that's `IngressToolTransferDetector`'s territory instead if
  the command line also matches a transfer pattern.
- **`EVTX-EXEC-REMOVABLE`** (`RemovableDriveExecutionDetector`) — a
  Sysmon 1 image/command line path whose drive letter is in
  `removable_drive_letters` (everything but `C:`). See the scope note
  above on this signal's own limitation.

### Persistence

- **`EVTX-USER-NEW`** (`NewUserCreatedDetector`) — always fires per 4720
  (informational baseline finding); attempts to correlate the creating
  account's own logon (via `SubjectLogonId`) to surface the creator's
  source IP as evidence when available.
- **`EVTX-USER-BACKDOOR-ADMIN`** (`BackdooredAdminUserDetector`) —
  correlates a 4720 creation with a 4732 addition of *the same account
  name* to a `sensitive_groups` group, within `backdoor_privilege_window_s`
  (default 1h). This is the specific "new user → made privileged fast"
  pattern the room calls "Making Users Privileged"; higher severity than
  either event alone.
- **`EVTX-USER-GROUP`** (`PrivilegedGroupModificationDetector`) — any
  4732 into a `sensitive_groups` group, independent of account age.
- **`EVTX-USER-PWRESET`** (`PasswordResetDetector`) — a 4724 event;
  description explicitly notes this alone can't distinguish a legitimate
  admin reset from an attacker resetting a dormant account's password —
  a stated limitation, not a claim of certainty.
- **`EVTX-PERSIST-SERVICE`** (`ServicePersistenceDetector`) — matches
  `sc.exe`/`sc create` Sysmon 1 launches (extracting the `binpath=`
  argument via regex) or native 4697/System-7045 service-install events;
  severity scaled up when the service binary path is in
  `suspicious_persistence_dirs` (Temp, ProgramData, AppData, Public,
  PerfLogs) and down when it's in `legitimate_service_dirs`
  (System32, Program Files).
- **`EVTX-PERSIST-TASK`** (`ScheduledTaskPersistenceDetector`) —
  `schtasks.exe` launches or native 4698 events, same directory-based
  severity scaling as the service detector.
- **`EVTX-PERSIST-STARTUP`** (`StartupFolderPersistenceDetector`) —
  Sysmon 11 file-create whose `TargetFilename` matches
  `startup_folder_markers` (`...\Start Menu\Programs\Startup\`).
- **`EVTX-PERSIST-RUNKEY`** (`RunKeyPersistenceDetector`) — Sysmon 13
  registry-set whose `TargetObject` matches `run_key_markers` (the
  `...\CurrentVersion\Run`/`RunOnce` keys).

### Discovery

- **`EVTX-DISCOVERY-SEQ`** (`DiscoveryCommandSequenceDetector`) — groups
  Sysmon 1 + PowerShell-history events by a group key (`ParentProcessGuid`
  → `ParentProcessId` → `LogonId` → `"global"` fallback, first one
  present), matches each command's `Image`+`CommandLine` against
  `discovery_commands` (five categories: files, users, system, network,
  antivirus — each a tuple of literal substrings, matched case-
  insensitively), and fires when a group accumulates at least
  `discovery_min_distinct_commands` (default 3) distinct matched commands
  spanning at least `discovery_min_categories` (default 2) categories
  within `discovery_window_s` (default 300s). A single isolated `whoami`
  never fires this by design — the point is the *sequence*, not any one
  command; `whoami` + `net user` + `ipconfig` (users + network) does.

### Collection / Credential Access

- **`EVTX-COLLECT-SENSITIVE`** (`SensitiveDataAccessDetector`) — a Sysmon
  11 file-create/access whose path matches `sensitive_data_paths`
  (browser profile dirs, `.ssh`, `wallet.dat`, Signal/Telegram/Discord
  app-data, SQL Server data dirs).
- **`EVTX-COLLECT-ARCHIVE`** (`DataStagingArchiveDetector`) — a command
  line matching `archive_staging_commands` (`Compress-Archive`, `7za.exe`,
  `7z.exe`, `rar.exe`, `winrar`) — the "stage before exfil" step.
- **`EVTX-COLLECT-CREDSEARCH`** (`CredentialKeywordSearchDetector`) — a
  command line matching `credential_keyword_commands` (`findstr password`,
  `Select-String password`, etc.).
- **`EVTX-COLLECT-STEALER`** (`PossibleDataStealerDetector`) —
  deliberately reads **only** Sysmon 11 file-create events, grouped by the
  writing process image, and fires when one process's file-create events
  touch at least `stealer_distinct_category_threshold` (default 3)
  distinct `sensitive_data_paths` categories within `stealer_window_s`
  (default 60s) — **no command-line matching at all**. This is a direct
  implementation of the room's own stated observation that stealers
  "rarely use CMD or PowerShell commands but rely on their own code," so
  a detector that only ever looks at command lines would structurally
  never catch one; this detector's evidence is file-system behavior only.

### Command and Control

- **`EVTX-C2-TRANSFER`** (`IngressToolTransferDetector`) — a command line
  matching `tool_transfer_patterns` (`certutil.exe -urlcache`, `curl.exe`,
  `Invoke-WebRequest`/` iwr `, `.DownloadFile(`/`.DownloadString(`,
  `bitsadmin`). Base severity/confidence is raised further when a Sysmon
  3 (network connect) or 22 (DNS query) event from the *same process ID*
  follows within `transfer_to_network_window_s` (default 30s) — command
  line alone is suggestive, a same-process network event right after it
  is confirmation.
- **`EVTX-C2-SUSPICIOUS-NETWORK`** (`SuspiciousNetworkProcessDetector`) —
  a Sysmon 3/22 event whose process image is (a) not in
  `known_benign_network_images` (browsers, svchost, OneDrive, etc.) and
  (b) running from a `suspicious_network_process_dirs` path (Temp,
  AppData, ProgramData, Public). Explicitly lower confidence in its own
  description text — "not conclusive alone, since plenty of legitimate
  installers also run from AppData" — because this is a location
  heuristic, not a signature match.

## 7. Reporting (`report.py`)

Four formats behind one `render(result, fmt)` dispatcher: `console`
(includes a chronological **attack timeline** section — every finding's
earliest evidence-event timestamp, sorted — which is the single most
useful view for reconstructing "what happened, in order" across tactics),
`json` (full round-trip via `Finding.to_dict()`), `markdown`, `html`.
Findings within a tactic group are ordered most-severe-first;
`TACTIC_ORDER` fixes tactic *section* order to the kill-chain sequence
(Initial Access → Persistence → Discovery → Credential Access →
Collection → Command and Control → Unknown/Internal) rather than
alphabetical, so the console/markdown/html views read as a narrative.

## 8. CLI (`cli.py`)

`analyze <path> [-f console|json|markdown|html] [-v]` — full detector run,
exit 1 on high/critical. `overview <path>` — event counts by ID and
channel, time range, no detectors (fast triage before running the full
analysis). `sessions <path> <logon_id>` — every event sharing a Logon ID,
the CLI's direct implementation of the room's own workbook technique.
`rules` — lists every registered detector's ID/tactic/title. All four
subcommands accept `--format jsonl|evtx|pshistory` to override
auto-detection.

## 9. Implementation traps found while building this

1. **RFC 5737 documentation ranges are not private, and the stdlib's
   `is_private` says they are.** `ipaddress.IPv4Address('203.0.113.77')
   .is_private` returns `True` — that flag covers the *entire* IANA
   special-purpose registry, not just RFC1918 space, and 192.0.2.0/24,
   198.51.100.0/24, and 203.0.113.0/24 (the RFC 5737 "documentation"
   ranges) are in that registry. This project's own synthetic fixtures,
   across nsmkit/trafkit/waapkit and now evtxkit, use exactly those
   ranges as "the attacker" — so trusting `is_private` here silently
   classified every synthetic external attacker IP as internal and
   suppressed every brute-force finding against it. Caught only by
   directly checking `ipaddress.ip_address('203.0.113.77').is_private`
   in a REPL after a scenario that should have fired produced zero
   findings. **Fix**: don't use the broad flag. Check only
   `is_loopback`/`is_link_local`/`is_unspecified` plus explicit membership
   in the three real RFC1918 networks (`10.0.0.0/8`, `172.16.0.0/12`,
   `192.168.0.0/16`). A documentation-range address is not a private
   network; if you need a separate "this is obviously lab/synthetic data"
   classifier, build one on purpose rather than piggybacking on
   `is_private`.
2. **`ElementTree.Element.__bool__` — an element with text but no
   children is falsy.** `<EventID>4625</EventID>` parses to an `Element`
   that is `False` under `bool()`, even though `find()` genuinely located
   it, because `Element.__bool__` is defined by child-element count, not
   by whether the element exists or has text. A naive `parent.find(f"e:
   {tag}", ns) or parent.find(tag)` — meant to try the namespaced lookup
   first, falling back to a bare-tag lookup — silently discards a real
   namespaced match whenever that element has no children, and falls
   through to the second lookup instead (which then usually fails too,
   since real Windows event XML is namespaced). **Fix**: write explicit
   `is not None` checks (`_find`/`_findall` helpers in `parsers.py`)
   instead of `or`-chaining `Element` truthiness. Caught by code review
   before ever running the parser against real-shaped XML, then locked in
   with a regression test (`test_xml_element_with_only_text_is_not_falsy`)
   asserting a hand-built single-child EventID element round-trips
   correctly.
3. **The LNK-phishing detector needs the drop, not just the launch.** An
   early version fired on any script-host process launched by
   `explorer.exe`, which is also what a user double-clicking a completely
   legitimate `.ps1` shortcut looks like. Requiring a preceding `.lnk`
   file-create in Downloads *specifically* within the correlation window
   turns this from "explorer launched a script" (common, mostly benign)
   into "explorer launched a script that was just delivered as a
   shortcut file" (the room's actual LNK-phishing pattern). Locked in
   with `test_lnk_detector_needs_a_preceding_drop`, asserting the bare-
   launch case alone does not fire `EVTX-EXEC-LNK-PHISHING`.
4. **Sub-microsecond timestamp precision breaks `datetime.fromisoformat`.**
   Windows' own `TimeCreated SystemTime` attribute emits 7 fractional
   digits (`2026-09-06T09:00:01.1234567Z`); Python's `fromisoformat`
   accepts at most 6. `_parse_iso_ts` trims to 6 digits with a regex
   before parsing, with a `strptime("%Y-%m-%dT%H:%M:%S")` fallback (using
   only the first 19 characters) if that still fails.
5. **The data-stealer detector must not look at command lines at all**,
   not merely "look at them less." The temptation while building this was
   to add command-line matching as one more signal alongside the
   file-create-category count, on the theory that more signal is always
   better. But the room material's stated premise is that these tools
   *specifically avoid* CMD/PowerShell — so a detector that partially
   depends on command-line text would degrade exactly against the threat
   it's meant to catch, while looking like it's "trying harder."
   `PossibleDataStealerDetector` reads only Sysmon 11 file events by
   design, and `test_stealer_detector_needs_no_command_line` asserts it
   fires even when every event in the scenario has an empty
   `CommandLine`.
6. **PID-only correlation needs a namespaced fallback key, not a bare
   PID.** Early `ProcessTree` code keyed everything by `ProcessId`
   directly; since PIDs are OS-recycled integers, using the bare number
   as a dict key risks silently merging two unrelated processes in a
   longer log, and offers no way to tell, from the key alone, whether a
   given tree node came from a trustworthy GUID or the weaker fallback.
   **Fix**: prefix the fallback key (`f"pid:{pid}"`) so it's visually and
   programmatically distinguishable from a real ProcessGuid key, and
   document the collision risk in the module docstring rather than
   presenting the fallback as equivalent to the GUID path.

## 10. Testing strategy

`tests/test_evtxkit.py` (50 tests): utility functions (including the
RFC5737 and ElementTree regression tests above), all three parsers
(JSON-Lines, hand-built XML, PowerShell history — including a malformed-
line-returns-None case for each), `ProcessTree` (ancestry chain, children,
missing-logon-ID lookup), detector registry isolation (one detector
raising doesn't take down the run — caught into a synthetic
`{id}-ERROR` finding instead), one positive test per detector rule ID
against its dedicated scenario file in `make_events.py`, the two
scope-limiting regression tests above (LNK-needs-a-drop,
stealer-needs-no-command-line), a clean-baseline test asserting **zero**
findings against benign-but-busy activity in both JSON-Lines and
PowerShell-history form (the mandatory negative case every toolkit in
this family carries), all four report formats, and CLI subprocess smoke
tests for every subcommand including exit-code verification. Verified
in a clean `venv` with zero third-party packages installed.
