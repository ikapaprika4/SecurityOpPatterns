"""Logon-based detection (Windows Logging for SOC, Task 2; Windows Threat
Detection 1, Task 2's "Detecting RDP Breach" workbook): 4625 (failed) and
4624 (successful) logons, filtered to the remote logon types (3 = Network,
10 = RemoteInteractive/RDP) and correlated by source IP.
"""

from __future__ import annotations

from collections import defaultdict

from ..config import REMOTE_LOGON_TYPES
from ..models import EVT_LOGON_FAILURE, EVT_LOGON_SUCCESS, EventRecord, Finding
from ..processtree import ProcessTree
from ..util import is_private_or_reserved_ip, windowed_groups
from .base import Detector, register


def _remote_failed_logons(events: list[EventRecord], config) -> dict[str, list[tuple[float, EventRecord]]]:
    by_ip: dict[str, list[tuple[float, EventRecord]]] = defaultdict(list)
    for e in events:
        if e.event_id != EVT_LOGON_FAILURE or e.logon_type not in REMOTE_LOGON_TYPES:
            continue
        ip = e.source_ip
        if config.external_ip_only and is_private_or_reserved_ip(ip):
            continue
        by_ip[ip].append((e.ts, e))
    return by_ip


@register
class RdpBruteForceDetector(Detector):
    id = "EVTX-LOGON-BRUTE"
    title = "RDP/network logon brute force"
    tactic = "Initial Access"

    def run(self, events: list[EventRecord], tree: ProcessTree) -> list[Finding]:
        findings = []
        for ip, items in _remote_failed_logons(events, self.config).items():
            for batch in windowed_groups(items, self.config.brute_force_window_s):
                if len(batch) >= self.config.brute_force_attempts_threshold:
                    usernames = sorted({e.target_user for e in batch if e.target_user})
                    findings.append(
                        Finding(
                            rule_id="EVTX-LOGON-BRUTE-01",
                            title="RDP/network logon brute force",
                            tactic="Initial Access",
                            severity="high",
                            confidence="high",
                            description=(
                                f"{ip} generated {len(batch)} failed logons "
                                f"(event 4625, logon type 3/10) within "
                                f"{self.config.brute_force_window_s:.0f}s, "
                                f"trying {len(usernames)} distinct "
                                f"username(s) -- the exact 'botnet scans, "
                                f"then brute forces common usernames' "
                                f"pattern from the room's RDP breach "
                                f"workbook."
                            ),
                            events=[e.index for _, e in items][: self.config.max_evidence_events],
                            evidence={"src": ip, "attempts": len(batch), "usernames_tried": usernames},
                            recommendation=(
                                "Block or rate-limit this source IP at the "
                                "firewall; if RDP must stay internet-facing, "
                                "put it behind a VPN or enable account "
                                "lockout with MFA."
                            ),
                        )
                    )
                    break
        return findings


@register
class SuccessfulLogonAfterBruteForceDetector(Detector):
    """Step 3 of the room's workbook: "switch the event ID filter to 4624,
    check the account under which the logon was made" -- confirms Initial
    Access, not just an attempted one."""

    id = "EVTX-LOGON-BRUTE-SUCCESS"
    title = "Successful remote logon following a brute-force cluster"
    tactic = "Initial Access"

    def run(self, events: list[EventRecord], tree: ProcessTree) -> list[Finding]:
        brute_ips: dict[str, list[EventRecord]] = defaultdict(list)
        for ip, items in _remote_failed_logons(events, self.config).items():
            for batch in windowed_groups(items, self.config.brute_force_window_s):
                if len(batch) >= self.config.brute_force_attempts_threshold:
                    brute_ips[ip].extend(batch)

        if not brute_ips:
            return []

        findings = []
        for e in events:
            if e.event_id != EVT_LOGON_SUCCESS or e.logon_type not in REMOTE_LOGON_TYPES:
                continue
            ip = e.source_ip
            if ip not in brute_ips:
                continue
            cluster = brute_ips[ip]
            last_failed_ts = max(x.ts for x in cluster)
            first_failed_ts = min(x.ts for x in cluster)
            if not (first_failed_ts <= e.ts <= last_failed_ts + self.config.successful_logon_correlation_window_s):
                continue
            findings.append(
                Finding(
                    rule_id="EVTX-LOGON-BRUTE-SUCCESS-01",
                    title="Initial Access confirmed via RDP/network brute force",
                    tactic="Initial Access",
                    severity="critical",
                    confidence="high",
                    description=(
                        f"{ip} successfully logged on as "
                        f"'{e.target_user or 'unknown'}' (event 4624, "
                        f"logon type {e.logon_type}) after generating "
                        f"{len(cluster)} failed logons from the same "
                        f"source -- the brute force succeeded. Logon ID "
                        f"{e.logon_id or '(none)'} is the correlation key "
                        f"for everything the attacker does next; pass it "
                        f"to `evtxkit sessions` or "
                        f"`processtree.events_for_logon_id`."
                    ),
                    events=[e.index],
                    evidence={"src": ip, "target_user": e.target_user, "logon_id": e.logon_id},
                    recommendation=(
                        "Treat as a confirmed breach: force a password "
                        "reset on this account, review everything under "
                        "its Logon ID, and check for new users or "
                        "persistence created afterward."
                    ),
                )
            )
        return findings
