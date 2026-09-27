"""Core data model.

evtxkit reads Windows Security + Sysmon event records -- the Windows
Logging for SOC room's own framing is "every recorded event is a log with
a time, action details, and the user behind the action" -- and normalizes
every record, whatever its source Event ID, into one `EventRecord` shape:
a handful of always-present fields (event_id, channel, time, computer) plus
a flexible `data` dict holding that event's own EventData Name/Value pairs
(SubjectUserName, LogonType, Image, CommandLine, TargetFilename, ... --
whatever fields that specific Event ID carries, straight from its XML/JSON
representation, the same shape Event Viewer's own "Details" XML tab shows).

Detectors then read named fields off `data` with small helper accessors
rather than the toolkit hand-rolling a distinct dataclass per Event ID --
there are over 500 documented Security Event IDs alone (Windows Logging for
SOC, task 2), and only a couple dozen matter for the detectors here, so a
generic record with typed accessors scales far better than one class per
ID.

Two identity rules matter more than they look:

* An Event ID only means something together with its channel. Event 1 is
  Sysmon process creation -- and also "system time changed" in the System
  log; event 104 is "log cleared" only in System. `sysmon()` and
  `is_process_create` check both, so dropping a System.evtx next to a Sysmon
  log cannot fabricate process activity.
* Security 4688 names the *new* process `NewProcessId` and puts the
  *creator's* PID in `ProcessId`, both in hex; Sysmon uses decimal
  `ProcessId`/`ParentProcessId`. The accessors normalise both to decimal so
  the process tree and PID correlation work across the two sources.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Event IDs this toolkit understands, named for readability everywhere else
# in the codebase instead of bare integers scattered through detector logic.
EVT_LOGON_SUCCESS = 4624
EVT_LOGON_FAILURE = 4625
EVT_EXPLICIT_CREDENTIALS = 4648
EVT_USER_CREATED = 4720
EVT_USER_ENABLED = 4722
EVT_USER_CHANGED = 4738
EVT_USER_DISABLED = 4725
EVT_USER_DELETED = 4726
EVT_PASSWORD_CHANGED = 4723
EVT_PASSWORD_RESET = 4724
EVT_GROUP_MEMBER_ADDED = 4732
EVT_GROUP_MEMBER_REMOVED = 4733
EVT_PROCESS_CREATED_SECURITY = 4688
EVT_SERVICE_INSTALLED_SECURITY = 4697
EVT_SERVICE_INSTALLED_SYSTEM = 7045
EVT_SCHEDULED_TASK_CREATED = 4698
EVT_SECURITY_LOG_CLEARED = 1102      # Security channel (Microsoft-Windows-Eventlog)
EVT_SYSTEM_LOG_CLEARED = 104         # System channel (Microsoft-Windows-Eventlog)
EVT_PS_SCRIPT_BLOCK = 4104           # Microsoft-Windows-PowerShell/Operational

SYSMON_PROCESS_CREATE = 1
SYSMON_NETWORK_CONNECT = 3
SYSMON_FILE_CREATE = 11
SYSMON_REGISTRY_SET = 13
SYSMON_DNS_QUERY = 22

# Pseudo event ID for lines of a PowerShell ConsoleHost_history.txt.
EVT_POWERSHELL_HISTORY = -1

_UNKNOWN_CHANNELS = ("", "Unknown")

# `powershell -e/-en/-enc/.../-EncodedCommand <base64>` -- PowerShell accepts
# any unambiguous prefix of the parameter name, with - or / as the switch.
_ENCODED_ARG = re.compile(
    r"(?:^|\s)[-/](?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|"
    r"encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+['\"]?([A-Za-z0-9+/=]{16,})",
    re.IGNORECASE)


def _norm_pid(value: str) -> str:
    """'0x1a2c' / '6700' -> '6700' (decimal string), '' if empty."""
    v = (value or "").strip()
    if not v:
        return ""
    try:
        return str(int(v, 16)) if v.lower().startswith("0x") else str(int(v))
    except ValueError:
        return v


def norm_logon_id(value: str) -> str:
    """'0x3E7' / '999' -> '0x3e7'; logon IDs are hex in Security and Sysmon
    events but not always in the same case."""
    v = (value or "").strip()
    if not v:
        return ""
    try:
        n = int(v, 16) if v.lower().startswith("0x") else int(v)
    except ValueError:
        return v.lower()
    return f"0x{n:x}"


def decode_powershell_command(command_line: str) -> str:
    """Decode the base64 (UTF-16LE) argument of -EncodedCommand, or ''."""
    if not command_line:
        return ""
    m = _ENCODED_ARG.search(command_line)
    if not m:
        return ""
    blob = m.group(1)
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
    except (ValueError, TypeError):
        return ""
    for enc in ("utf-16-le", "utf-8"):
        try:
            text = raw.decode(enc)
        except UnicodeDecodeError:
            continue
        printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
        if text and printable / len(text) > 0.9:
            return text.strip("\x00")
    return ""


@dataclass
class EventRecord:
    """One normalized Windows event, from any channel (Security, System,
    Microsoft-Windows-Sysmon/Operational, ...)."""

    index: int
    event_id: int
    channel: str          # "Security" | "System" | "Sysmon" | "PowerShell" | ...
    ts: float             # UTC epoch seconds; 0.0 when the source has no time
    computer: str = ""
    data: dict[str, str] = field(default_factory=dict)
    raw: str = ""
    provider: str = ""
    source: str = ""      # which input file the record came from

    @property
    def time(self) -> datetime:
        return datetime.fromtimestamp(self.ts, tz=timezone.utc)

    @property
    def has_time(self) -> bool:
        return self.ts > 0

    def get(self, *names: str, default: str = "") -> str:
        """Read the first present EventData field among `names` -- lets
        callers write e.g. `e.get("IpAddress", "SourceNetworkAddress")`
        once, rather than every call site re-deriving which of a few
        historically-inconsistent field names this Windows version used."""
        for name in names:
            if name in self.data and self.data[name] not in (None, ""):
                return self.data[name]
        return default

    def get_int(self, *names: str, default: int = 0) -> int:
        raw = self.get(*names)
        try:
            return int(raw)
        except (TypeError, ValueError):
            return default

    # -- identity: an event ID only means something with its channel --
    @property
    def is_sysmon(self) -> bool:
        if self.channel == "Sysmon":
            return True
        if self.channel in _UNKNOWN_CHANNELS:
            return "UtcTime" in self.data or "ProcessGuid" in self.data
        return False

    def sysmon(self, event_id: int) -> bool:
        return self.event_id == event_id and self.is_sysmon

    @property
    def is_process_create(self) -> bool:
        """Sysmon 1 or Security 4688 -- the two process-creation sources."""
        if self.event_id == SYSMON_PROCESS_CREATE:
            return self.is_sysmon
        return (self.event_id == EVT_PROCESS_CREATED_SECURITY
                and self.channel in ("Security",) + _UNKNOWN_CHANNELS)

    @property
    def is_script_block(self) -> bool:
        return (self.event_id == EVT_PS_SCRIPT_BLOCK
                and self.channel in ("PowerShell",) + _UNKNOWN_CHANNELS
                and "ScriptBlockText" in self.data)

    @property
    def is_command_source(self) -> bool:
        """Anything carrying a command line a detector can pattern-match."""
        return (self.is_process_create or self.event_id == EVT_POWERSHELL_HISTORY
                or self.is_script_block)

    # -- convenience accessors for the fields detectors read constantly --
    @property
    def logon_type(self) -> int:
        return self.get_int("LogonType")

    @property
    def logon_id(self) -> str:
        """The session this event belongs to. 0x0 is the null session --
        what 4688 writes in TargetLogonId when the new process simply runs
        in its creator's session -- so it never counts as an answer."""
        order = (("SubjectLogonId", "TargetLogonId")
                 if self.event_id == EVT_PROCESS_CREATED_SECURITY
                 else ("TargetLogonId", "SubjectLogonId", "LogonId"))
        for name in order:
            value = norm_logon_id(self.data.get(name) or "")
            if value and value != "0x0":
                return value
        return ""

    @property
    def source_ip(self) -> str:
        return self.get("IpAddress", "SourceNetworkAddress")

    @property
    def target_user(self) -> str:
        return self.get("TargetUserName")

    @property
    def subject_user(self) -> str:
        return self.get("SubjectUserName")

    @property
    def image(self) -> str:
        return self.get("Image", "NewProcessName")

    @property
    def parent_image(self) -> str:
        return self.get("ParentImage", "ParentProcessName")

    @property
    def command_line(self) -> str:
        if self.is_script_block:
            return self.get("ScriptBlockText")
        return self.get("CommandLine")

    @property
    def decoded_command(self) -> str:
        """Plain text of a `-EncodedCommand` argument, if the command line
        has one (cached on first use)."""
        cached = self.data.get("_DecodedCommand")
        if cached is None:
            cached = decode_powershell_command(self.command_line)
            self.data["_DecodedCommand"] = cached
        return cached

    @property
    def command_text(self) -> str:
        """Command line plus any decoded -EncodedCommand payload -- what
        pattern-matching detectors should search, so base64 hides nothing."""
        decoded = self.decoded_command
        return f"{self.command_line}\n{decoded}" if decoded else self.command_line

    @property
    def parent_command_line(self) -> str:
        return self.get("ParentCommandLine")

    @property
    def process_id(self) -> str:
        if self.event_id == EVT_PROCESS_CREATED_SECURITY:
            return _norm_pid(self.get("NewProcessId"))
        return _norm_pid(self.get("ProcessId", "NewProcessId", "ExecutionProcessId"))

    @property
    def parent_process_id(self) -> str:
        if self.event_id == EVT_PROCESS_CREATED_SECURITY:
            return _norm_pid(self.get("ProcessId"))     # 4688: ProcessId is the creator
        return _norm_pid(self.get("ParentProcessId"))

    @property
    def process_guid(self) -> str:
        return self.get("ProcessGuid")

    @property
    def parent_process_guid(self) -> str:
        return self.get("ParentProcessGuid")

    @property
    def target_filename(self) -> str:
        return self.get("TargetFilename")

    @property
    def target_object(self) -> str:
        return self.get("TargetObject")

    def summary(self) -> str:
        """A short human description for timelines and evidence lists."""
        if self.is_process_create:
            return f"{self.image or '?'}  {self.command_line[:160]}".strip()
        if self.event_id in (EVT_LOGON_SUCCESS, EVT_LOGON_FAILURE):
            return (f"{self.target_user or '?'} logon type {self.logon_type or '?'}"
                    f" from {self.source_ip or '(local)'}")
        if self.sysmon(SYSMON_FILE_CREATE):
            return f"{self.image or '?'} created {self.target_filename}"
        if self.sysmon(SYSMON_REGISTRY_SET):
            return f"{self.image or '?'} set {self.target_object}"
        if self.sysmon(SYSMON_NETWORK_CONNECT):
            return (f"{self.image or '?'} -> {self.get('DestinationIp', 'DestinationHostname')}"
                    f":{self.get('DestinationPort')}")
        if self.sysmon(SYSMON_DNS_QUERY):
            return f"{self.image or '?'} resolved {self.get('QueryName')}"
        if self.is_script_block or self.event_id == EVT_POWERSHELL_HISTORY:
            return self.command_line[:200]
        for key in ("ServiceName", "TaskName", "TargetUserName", "MemberName", "SubjectUserName"):
            if self.get(key):
                return f"{key}={self.get(key)}"
        return ""


@dataclass
class Finding:
    rule_id: str
    title: str
    tactic: str            # MITRE tactic name, e.g. "Initial Access", "Persistence"
    severity: str
    confidence: str
    description: str
    events: list[int] = field(default_factory=list)   # EventRecord.index values
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    mitre: list[str] = field(default_factory=list)    # ATT&CK technique IDs

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id, "title": self.title, "tactic": self.tactic,
            "severity": self.severity, "confidence": self.confidence,
            "description": self.description, "events": self.events[:25],
            "evidence": self.evidence, "recommendation": self.recommendation,
            "mitre": self.mitre,
        }


@dataclass
class AnalysisResult:
    path: str
    events: list[EventRecord] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)   # parse-time counts (see parsers)

    @property
    def worst_severity(self) -> str:
        if not self.findings:
            return "info"
        rank = max(f.severity_rank for f in self.findings)
        for name, r in SEVERITY_ORDER.items():
            if r == rank:
                return name
        return "info"

    @property
    def findings_by_tactic(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {}
        for f in self.findings:
            out.setdefault(f.tactic, []).append(f)
        return out

    def event_by_index(self) -> dict[int, EventRecord]:
        return {e.index: e for e in self.events}
