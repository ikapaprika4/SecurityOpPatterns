"""Defense evasion and obfuscated execution -- three signals the original
detector set had no coverage for, all of which show up constantly in real
intrusions and in the THM Windows rooms' follow-on challenges:

* the event log itself being cleared (Security 1102, System 104) -- an
  attacker covering tracks leaves exactly one record behind, and it names
  the account that did it;
* PowerShell launched with -EncodedCommand, whose payload is decoded here so
  the analyst reads the command instead of a base64 blob (every other
  command-line detector also sees the decoded text via
  `EventRecord.command_text`);
* script-block (4104) or command-line content matching known offensive
  PowerShell tooling -- weighted, so one ordinary cmdlet in an admin script
  does not fire, but an AMSI bypass or a Mimikatz invocation always does.
"""

from __future__ import annotations

from ..models import (
    EVT_SECURITY_LOG_CLEARED,
    EVT_SYSTEM_LOG_CLEARED,
    EventRecord,
    Finding,
)
from ..processtree import ProcessTree
from .base import Detector, register


@register
class EventLogClearedDetector(Detector):
    id = "EVTX-DEFENSE-LOGCLEAR"
    title = "Windows event log cleared"
    tactic = "Defense Evasion"

    def run(self, events: list[EventRecord], tree: ProcessTree) -> list[Finding]:
        findings = []
        for e in events:
            if e.event_id == EVT_SECURITY_LOG_CLEARED and e.channel in ("Security", "Unknown"):
                log_name = "Security"
            elif e.event_id == EVT_SYSTEM_LOG_CLEARED and e.channel in ("System", "Unknown") \
                    and (not e.provider or "eventlog" in e.provider.lower()):
                log_name = e.get("Channel") or "System"
            else:
                continue
            who = "\\".join(p for p in (e.get("SubjectDomainName"), e.get("SubjectUserName")) if p)
            findings.append(Finding(
                rule_id="EVTX-DEFENSE-LOGCLEAR-01",
                title=f"{log_name} event log cleared",
                tactic="Defense Evasion",
                severity="high",
                confidence="high",
                description=(
                    f"The {log_name} log was cleared"
                    + (f" by '{who}'" if who else "")
                    + f" (event {e.event_id}). Legitimate administrators rarely clear logs; "
                    "attackers do it to erase evidence of what came before, so everything "
                    "prior to this point on this host must be treated as incomplete."),
                events=[e.index],
                evidence={"log": log_name, "cleared_by": who or "(not recorded)",
                          "logon_id": e.get("SubjectLogonId")},
                recommendation=("Pull the same log from your SIEM/forwarder, which kept a copy, "
                                "and review the clearing account's session (Logon ID) in full."),
            ))
        return findings


@register
class EncodedPowerShellDetector(Detector):
    id = "EVTX-EXEC-ENCODED-PS"
    title = "PowerShell run with an encoded command"
    tactic = "Execution"

    def run(self, events: list[EventRecord], tree: ProcessTree) -> list[Finding]:
        findings = []
        seen: set[str] = set()
        for e in events:
            if not e.is_command_source:
                continue
            decoded = e.decoded_command
            if not decoded:
                continue
            low = e.command_line.lower()
            if "powershell" not in low and "pwsh" not in low and not e.image.lower().endswith(
                    ("powershell.exe", "pwsh.exe")):
                continue
            key = f"{e.computer}|{decoded}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                rule_id="EVTX-EXEC-ENCODED-PS-01",
                title="PowerShell run with an encoded command",
                tactic="Execution",
                severity="high",
                confidence="medium",
                description=(
                    f"'{e.image or 'powershell.exe'}' was started with -EncodedCommand. Base64 "
                    "command lines exist to keep the real instruction out of logs and out of "
                    f"sight; decoded, it reads: {decoded[:300]!r}"
                    + (" (truncated)" if len(decoded) > 300 else "")),
                events=[e.index],
                evidence={"command_line": e.command_line[:500], "decoded": decoded[:2000],
                          "parent_image": e.parent_image},
                recommendation=("Review the decoded command and the parent process that launched "
                                "it; if it downloads or runs anything, treat the host as "
                                "compromised."),
            ))
        return findings


@register
class SuspiciousPowerShellDetector(Detector):
    id = "EVTX-EXEC-PSSUSPICIOUS"
    title = "Offensive PowerShell tooling or technique"
    tactic = "Execution"

    def run(self, events: list[EventRecord], tree: ProcessTree) -> list[Finding]:
        cfg = self.config
        findings = []
        seen: set[tuple] = set()
        for e in events:
            if not e.is_command_source:
                continue
            text = e.command_text.lower()
            if not text:
                continue
            strong = sorted({m for m in cfg.powershell_strong_markers if m in text})
            weak = sorted({m for m in cfg.powershell_weak_markers if m in text})
            if not strong and len(weak) < cfg.powershell_weak_marker_threshold:
                continue
            key = (e.computer, tuple(strong), tuple(weak), e.command_line[:200])
            if key in seen:
                continue
            seen.add(key)
            where = ("a PowerShell script block (4104)" if e.is_script_block
                     else "PowerShell history" if e.event_id < 0 else f"'{e.image}'")
            findings.append(Finding(
                rule_id="EVTX-EXEC-PSSUSPICIOUS-01",
                title=("Known offensive PowerShell tooling" if strong
                       else "PowerShell combining several evasion/download techniques"),
                tactic="Execution",
                severity="critical" if strong else "medium",
                confidence="high" if strong else "low",
                description=(
                    f"{where} contains "
                    + (f"signatures of offensive tooling ({', '.join(strong)})" if strong else
                       f"{len(weak)} techniques that are individually common but rarely appear "
                       f"together in legitimate scripts ({', '.join(weak)})")
                    + f": {e.command_text[:240]!r}"),
                events=[e.index],
                evidence={"strong_markers": strong, "weak_markers": weak,
                          "text": e.command_text[:2000]},
                recommendation=("Isolate the host if the strong markers are confirmed; recover the "
                                "full script (4104 splits long scripts across several events "
                                "sharing a ScriptBlockId)."),
            ))
        return findings
