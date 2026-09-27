"""Discovery detection (Windows Threat Detection 3, Task 2): a cluster of
known discovery commands (whoami, net user, ipconfig, tasklist, systeminfo,
Get-LocalUser, Get-Service, the SecurityCenter2/Get-MpPreference AV-check
pair, ...) run in a short window from what looks like one attacker session
-- grouped by parent process where Sysmon gives us one (the room's own
"invoice.pdf.exe -> cmd.exe -> {ipconfig, whoami, net user, ...}" process
tree), falling back to Logon ID, and finally to "the whole file" for a
PowerShell history source that carries neither.

Deliberately clusters rather than firing per-command: a single `ipconfig`
from an IT admin isn't a finding on its own ("you don't want to create
panic just because your coworker checked their IP," per the room) --
several *different* discovery commands together, in one short window, from
one apparent session, is the actual signal.
"""

from __future__ import annotations

from collections import defaultdict

from ..models import EventRecord, Finding, SYSMON_PROCESS_CREATE
from ..parsers import EVT_POWERSHELL_HISTORY
from ..processtree import ProcessTree
from ..util import any_substring, windowed_groups
from .base import Detector, register


def _match_categories(text: str, catalogue: dict) -> list[tuple[str, str]]:
    hits = []
    for category, commands in catalogue.items():
        hit = any_substring(text, commands)
        if hit:
            hits.append((category, hit))
    return hits


def _group_key(e: EventRecord) -> str:
    if e.parent_process_guid:
        return f"guid:{e.parent_process_guid}"
    if e.parent_process_id:
        return f"ppid:{e.parent_process_id}"
    if e.is_script_block and e.process_id:
        # 4104: every script block of one PowerShell host process is one session.
        return f"pshost:{e.computer}:{e.process_id}"
    logon_id = e.logon_id
    if logon_id:
        return f"logon:{logon_id}"
    return "global"


@register
class DiscoveryCommandSequenceDetector(Detector):
    id = "EVTX-DISCOVERY-SEQ"
    title = "Sequence of discovery commands from one session"
    tactic = "Discovery"

    def run(self, events: list[EventRecord], tree: ProcessTree) -> list[Finding]:
        candidates = [
            e for e in events
            if e.is_command_source
        ]
        by_group: dict[str, list[tuple[float, EventRecord]]] = defaultdict(list)
        for e in candidates:
            haystack = f"{e.image} {e.command_text}"
            if _match_categories(haystack, self.config.discovery_commands):
                by_group[_group_key(e)].append((e.ts, e))

        findings = []
        for group_key, items in by_group.items():
            for batch in windowed_groups(items, self.config.discovery_window_s):
                matched: dict[str, list[str]] = defaultdict(list)
                for e in batch:
                    haystack = f"{e.image} {e.command_text}"
                    for category, hit in _match_categories(haystack, self.config.discovery_commands):
                        matched[category].append(hit)

                distinct_commands = {h for hits in matched.values() for h in hits}
                if (
                    len(distinct_commands) >= self.config.discovery_min_distinct_commands
                    and len(matched) >= self.config.discovery_min_categories
                ):
                    if any(e.event_id == EVT_POWERSHELL_HISTORY for e in batch):
                        source_note = ("PowerShell history (no per-command timestamps -- "
                                       "the whole file is treated as one session)")
                    elif any(e.is_script_block for e in batch):
                        source_note = ("PowerShell script block logging (4104), grouped by "
                                       "host process")
                    else:
                        source_note = "process creation events, grouped by parent process"
                    findings.append(
                        Finding(
                            rule_id="EVTX-DISCOVERY-SEQ-01",
                            title="Sequence of discovery commands from one session",
                            tactic="Discovery",
                            severity="high" if len(matched) >= 3 else "medium",
                            confidence="medium",
                            description=(
                                f"{len(distinct_commands)} distinct "
                                f"discovery commands across "
                                f"{len(matched)} categories "
                                f"({', '.join(sorted(matched))}) ran "
                                f"within one session ({source_note}) -- "
                                f"a single command like ipconfig is "
                                f"routine, but this many different "
                                f"discovery commands together is the "
                                f"'who am I, where am I' pattern the room "
                                f"describes right after Initial Access."
                            ),
                            events=[e.index for e in batch][: self.config.max_evidence_events],
                            evidence={"categories": sorted(matched), "commands": sorted(distinct_commands)},
                            recommendation="Identify the parent/originating process; if it traces back to a phishing attachment or unexpected RDP session, treat as active compromise.",
                        )
                    )
                    break
        return findings
