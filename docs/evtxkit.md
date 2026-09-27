# evtxkit — Windows Security/Sysmon event log detection toolkit

Reads normalized Windows event logs — Security, System, and Sysmon
Operational, plus PowerShell's `ConsoleHost_history.txt` as a companion
source — and runs detectors across the full attack lifecycle the four-room
Windows Logging series covers: initial access (RDP brute force, phishing
attachments, LNK shortcuts, USB execution), persistence (backdoored users,
services, scheduled tasks, Startup folder, Run keys), discovery, collection/
credential access/staging, and C2 ingress tool transfer.

**`docs/WINDOWS_THREAT_DETECTION_BUILD_SPEC.md` is the implementation
spec** — data model, ingestion formats, the ProcessGuid/Logon ID
correlation layer, every detector's logic and thresholds, and the
implementation traps found while building this (an IP-classification bug
that silently zeroed out every finding against this project's own
synthetic attacker IPs, and an ElementTree gotcha that can silently drop a
real XML match). Hand that file to a coding model to build from, or read
it as the reference; `evtxkit/` is the working implementation of it.

Companion to **nsmkit** (firewall/IDS/VPN log analysis), **phishkit**
(email/phishing analysis), **trafkit** (packet-native traffic analysis),
and **waapkit** (web application attack / WAF analysis). Where those read
network- and application-layer logs, evtxkit reads the host — the Windows
event log itself — and is the first of the five to need a real
correlation layer (process tree, Logon ID) as first-class infrastructure
rather than simple per-record matching.

## Install

Nothing to install: run from the `soc-workbench` folder (or `pip install -e .` there for the
`evtxkit` command). Python 3.10+, pure standard library. Real binary `.evtx`
files are read on Windows through the built-in `wevtutil` — no package
needed; only on other systems does that take the optional `python-evtx`
(`pip install -e ".[evtx]"`).

## Quick start

```bash
python -m evtxkit analyze samples/evtxkit/rdp_brute_force.jsonl -v
python -m evtxkit analyze samples/evtxkit/security_only.jsonl samples/evtxkit/log_cleared.xml
python -m evtxkit sessions samples/evtxkit/rdp_brute_force.jsonl 0x3e7abc12
python -m evtxkit overview samples/evtxkit/discovery.jsonl
python tools/make_evtx_events.py     # regenerate the samples: one scenario per detector + a clean baseline
```

## Commands

| Command | Purpose |
|---|---|
| `evtxkit analyze <path>` | Run every detector, report (`-f console\|json\|markdown\|html`) |
| `evtxkit overview <path>` | Event counts by ID/channel, time range — no detectors |
| `evtxkit sessions <path> <logon_id>` | Every event sharing one Logon ID — the room's own workbook technique |
| `evtxkit rules` | List every registered detector |

`<path>` (`analyze` takes several) accepts a `.jsonl`/`.json` file
(normalized JSON-Lines, auto-detected), a real `.evtx` file, an Event
Viewer / `wevtutil` XML export, or a `ConsoleHost_history.txt` PowerShell
history file. `--format jsonl|evtx|xml|pshistory` overrides auto-detection.
Exit code is 1 when `analyze` finds anything high/critical severity.

## Ingestion formats

1. **Normalized JSON-Lines** (primary, zero dependencies) — one JSON object
   per line: `{"EventID": 4625, "Channel": "Security", "TimeCreated": "...",
   "Computer": "...", "EventData": {...}}`, the shape `Get-WinEvent |
   ConvertTo-Json` or a Winlogbeat export produces.
2. **Real `.evtx` binary files** — Windows' actual on-disk format. Read
   through the built-in `wevtutil` on Windows; elsewhere with the optional
   `python-evtx` package. **Event Viewer XML exports** (`<Events>` files,
   `wevtutil qe /f:xml`) are read directly. JSON also covers evtx_dump,
   Winlogbeat/ECS `winlog`, EvtxECmd and flat-row shapes.
3. **`ConsoleHost_history.txt`** — PowerShell's own command history file,
   parsed into the same event shape so every command-line-matching
   detector (discovery, collection, C2 transfer) reads it for free. No
   per-command timestamps, so time-windowed correlation doesn't apply to
   it — a stated limitation of the source, not a bug.

## What it detects

**Initial Access** — RDP/network logon brute force (many failed 4625s from
one external IP within a window, remote logon types only) with correlation
to a subsequent successful 4624 from the same IP; double-extension
execution (`photo.jpg.exe`); a downloaded email attachment executed from
Downloads shortly after being written; LNK-shortcut phishing (a `.lnk`
dropped, then a script host launched by `explorer.exe` referencing it);
execution from a non-`C:` drive letter (USB/removable media).

**Persistence** — a new local user, and specifically a new user added to a
privileged group within an hour of creation (the backdoored-admin pattern);
any privileged-group membership change; password resets; a service created
via `sc.exe`/4697/System 7045 (severity scaled by install directory);
a scheduled task via `schtasks.exe`/4698; a file dropped into the Startup
folder (Sysmon 11); a Run/RunOnce registry key write (Sysmon 13).

**Discovery** — a sequence of distinct discovery commands (file/user/
system/network/AV enumeration) from one process lineage or PowerShell
session within a window — a single `whoami` doesn't fire this, a
`whoami` + `net user` + `ipconfig` burst does.

**Collection / Credential Access** — access to a catalogued
sensitive-data path (browser profiles, SSH keys, wallet files, chat-app
data); archive-staging commands (`Compress-Archive`, `7z`, `rar`);
credential-keyword searches inside files; and — deliberately independent
of command-line text, since the room material notes stealers "rarely use
CMD or PowerShell" — a single process whose Sysmon 11 file-create events
touch several distinct sensitive-data categories.

**Command and Control** — ingress tool transfer via `certutil -urlcache`,
`curl`, `Invoke-WebRequest`/`IWR`, `.DownloadFile`/`.DownloadString`, or
`bitsadmin`, with higher confidence when a same-process network/DNS event
follows shortly after; outbound network connections from a process running
out of a non-standard directory (Temp/AppData/ProgramData) that isn't a
recognized browser or system binary.

Every finding carries a MITRE tactic, severity, confidence, human-readable
description, a bounded evidence-event list, and a recommendation.

## Correlation layer

Two join keys, both taken directly from the room material's own worked
techniques:

- **Logon ID** — copy it from a 4624/4625 logon event, then pull every
  other Security/Sysmon event carrying the same ID (`evtxkit sessions`
  implements this directly). `events_for_logon_id()` / `find_logon_event()`
  in `evtxkit.processtree` expose it programmatically.
- **ProcessGuid / ParentProcessGuid** (Sysmon) — a `ProcessTree` built once
  per analysis run supports `parent_of`, `children_of`, `ancestry`, and
  `root_of`. Falls back to a `pid:<ProcessId>` key for Security 4688 events
  (which carry no GUID); this fallback can collide across unrelated
  processes in a long-running log since PIDs get reused — a real,
  documented limitation, not a hidden one.

## Tests

```bash
python tests/test_evtxkit.py     # or, for every toolkit at once: python run_tests.py
```

71 tests, zero third-party dependencies. Covers every detector (one
positive case per rule ID across the generated scenario files), Security
4688 as well as Sysmon process events, channel checks (a System-log event
ID is not a Security one), log clearing and encoded/suspicious PowerShell,
the JSON/XML/.evtx parsers, the process tree, report rendering in all
four formats, CLI subprocess smoke tests, a clean-baseline zero-findings
case in both JSON-Lines and PowerShell-history form, and regression tests
for the two bugs documented in the build spec.
