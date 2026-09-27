"""Command and Control / Ingress Tool Transfer detection (Windows Threat
Detection 2, Task 2; Windows Threat Detection 3, Task 6): the
certutil/curl/PowerShell-IWR download patterns the room lists explicitly,
optionally correlated with a Sysmon network-connection or DNS-query event
from the same process, plus a broader "something not a browser, running
from a Temp/AppData-style directory, made an outbound connection" signal
for the staged-secondary-payload C2 case the room describes (download a
C2 binary, hide it in C:\\Temp, run it as a new stealthy process).
"""

from __future__ import annotations

from ..models import (
    EventRecord,
    Finding,
    SYSMON_DNS_QUERY,
    SYSMON_NETWORK_CONNECT,
    SYSMON_PROCESS_CREATE,
)
from ..parsers import EVT_POWERSHELL_HISTORY
from ..processtree import ProcessTree
from ..util import any_substring, norm_path
from .base import Detector, register


@register
class IngressToolTransferDetector(Detector):
    id = "EVTX-C2-TRANSFER"
    title = "Tool/malware download via certutil, curl, or PowerShell"
    tactic = "Command and Control"

    def run(self, events: list[EventRecord], tree: ProcessTree) -> list[Finding]:
        transfers = []
        for e in events:
            if not e.is_command_source:
                continue
            haystack = f"{e.image} {e.command_text}"
            hit = any_substring(haystack, self.config.tool_transfer_patterns)
            if hit:
                transfers.append((e, hit))

        if not transfers:
            return []

        network_events = [e for e in events if (e.sysmon(SYSMON_NETWORK_CONNECT) or e.sysmon(SYSMON_DNS_QUERY))]

        findings = []
        for e, hit in transfers:
            correlated = None
            for ne in network_events:
                if ne.process_id and ne.process_id == e.process_id:
                    if e.ts <= ne.ts <= e.ts + self.config.transfer_to_network_window_s:
                        correlated = ne
                        break
            severity = "high" if correlated is not None else "medium"
            confidence = "high" if correlated is not None else "medium"
            net_note = ""
            if correlated is not None:
                dest = correlated.get("DestinationIp", "DestinationHostname", "QueryName")
                net_note = f" Confirmed by a network/DNS event to '{dest}' from the same process."
            findings.append(
                Finding(
                    rule_id="EVTX-C2-TRANSFER-01",
                    title="Ingress tool transfer",
                    tactic="Command and Control",
                    severity=severity,
                    confidence=confidence,
                    description=(
                        f"'{e.image or 'powershell.exe'}' used a "
                        f"download pattern ('{hit}'): "
                        f"'{e.command_line[:200]}'.{net_note} Threat "
                        f"actors often split malware into stages "
                        f"specifically to bypass antivirus and limit "
                        f"exposure if the first stage is caught."
                    ),
                    events=[e.index] + ([correlated.index] if correlated else []),
                    evidence={"command_line": e.command_line, "pattern": hit},
                    recommendation="Retrieve the downloaded file for analysis if still present; block the destination domain/IP.",
                )
            )
        return findings


@register
class SuspiciousNetworkProcessDetector(Detector):
    """The staged-C2 case: a process that isn't a known browser, running
    from a Temp/AppData/ProgramData-style directory, making an outbound
    connection or DNS query -- not proof of C2 on its own (plenty of
    legitimate software installs to AppData), but a real anomaly worth
    surfacing alongside anything else in the same session."""

    id = "EVTX-C2-SUSPICIOUS-NETWORK"
    title = "Outbound connection from a non-standard process location"
    tactic = "Command and Control"

    def run(self, events: list[EventRecord], tree: ProcessTree) -> list[Finding]:
        findings = []
        for e in events:
            if not (e.sysmon(SYSMON_NETWORK_CONNECT) or e.sysmon(SYSMON_DNS_QUERY)):
                continue
            image_low = norm_path(e.image)
            if any(image_low.endswith(b) for b in self.config.known_benign_network_images):
                continue
            if not any_substring(image_low, self.config.suspicious_network_process_dirs):
                continue
            dest = e.get("DestinationIp", "DestinationHostname", "QueryName")
            findings.append(
                Finding(
                    rule_id="EVTX-C2-SUSPICIOUS-NETWORK-01",
                    title="Outbound connection from a non-standard process location",
                    tactic="Command and Control",
                    severity="medium",
                    confidence="low",
                    description=(
                        f"'{e.image}' (running from a Temp/AppData/"
                        f"ProgramData-style path, not a recognized "
                        f"browser or system process) connected to "
                        f"'{dest}'. This is the shape of a staged "
                        f"secondary C2 payload hiding in a throwaway "
                        f"directory -- not conclusive alone, since "
                        f"plenty of legitimate installers also run from "
                        f"AppData."
                    ),
                    events=[e.index],
                    evidence={"image": e.image, "destination": dest},
                    recommendation="Check the process's own file-create/parent history; if it traces back to a phishing download, treat as active C2.",
                )
            )
        return findings
