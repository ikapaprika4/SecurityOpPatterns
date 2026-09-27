"""
Host & user identification anomalies (Wireshark: Traffic Analysis, task 4) --
DHCP starvation/rogue-server signals. The *positive* identification use case
(mapping IPs/MACs to hostnames and Kerberos principals to usernames) isn't a
finding on its own, so it lives in `extract.py` as an inventory table instead
of a detector here.
"""

from __future__ import annotations

from collections import defaultdict

from ..models import Finding, PacketRecord
from .base import AnalysisContext, Detector, register

_DHCP_DISCOVER, _DHCP_REQUEST, _DHCP_NAK = 1, 3, 6


@register
class DHCPAnomalyDetector(Detector):
    id = "DHCP-ANOM-01"
    title = "DHCP starvation / rogue-server signal"

    def run(self, packets: list[PacketRecord], ctx: AnalysisContext) -> list[Finding]:
        findings = []
        findings += self._starvation(packets)
        findings += self._nak_burst(packets)
        return findings

    def _starvation(self, packets: list[PacketRecord]) -> list[Finding]:
        # One source MAC cycling through many distinct client MACs in its own
        # DHCP requests is the classic starvation-attack signature (a tool
        # like Yersinia/DHCPig exhausting the scope from one NIC).
        by_src_ip: dict[str, set] = defaultdict(set)
        frames: dict[str, list] = defaultdict(list)
        for p in packets:
            f = p.fields
            if f.get("dhcp.option.dhcp") in (_DHCP_DISCOVER, _DHCP_REQUEST) and f.get("dhcp.hw.mac_addr"):
                by_src_ip[p.src_ip].add(f["dhcp.hw.mac_addr"])
                frames[p.src_ip].append(p.frame_number)

        findings = []
        for src, macs in by_src_ip.items():
            if len(macs) < 10:
                continue
            findings.append(self._finding(
                severity="high", confidence="medium",
                description=(f"{src} sent DHCP DISCOVER/REQUEST for {len(macs)} distinct client "
                             f"MAC addresses -- consistent with a DHCP starvation attack exhausting "
                             f"the scope's address pool before standing up a rogue DHCP server."),
                frames=frames[src][:25],
                evidence={"src": src, "distinct_client_macs": len(macs)},
                recommendation="Enable DHCP snooping / port-security on the access switch if not "
                                "already on; check whether a second, unauthorised DHCP server "
                                "started answering afterward.",
                mitre="T1557 Adversary-in-the-Middle",
            ))
        return findings

    def _nak_burst(self, packets: list[PacketRecord]) -> list[Finding]:
        naks = [p for p in packets if p.fields.get("dhcp.option.dhcp") == _DHCP_NAK]
        if len(naks) < 5:
            return []
        by_reason: dict[str, list] = defaultdict(list)
        for p in naks:
            reason = p.fields.get("dhcp.option.message", "unspecified")
            by_reason[reason].append(p.frame_number)
        return [self._finding(
            rule_id="DHCP-ANOM-02", title="Elevated DHCP NAK volume",
            severity="low", confidence="low",
            description=(f"{len(naks)} DHCP NAK responses observed in this capture -- worth a "
                         f"quick look if it's outside the normal churn for this network."),
            frames=[fr for frs in by_reason.values() for fr in frs][:25],
            evidence={"nak_count": len(naks), "reasons": {k: len(v) for k, v in by_reason.items()}},
            recommendation="A handful of NAKs from normal lease renewal/roaming is expected; a "
                            "spike usually means a misconfigured or rogue server contesting leases.",
        )]


def identify_hosts_and_users(packets: list[PacketRecord]) -> dict:
    """Non-finding inventory: DHCP hostnames, NBNS names, and Kerberos
    principals seen in the clear -- the room's "host and user
    identification" walkthrough, minus the manual clicking."""
    from ..hosts import nbns_owner
    dhcp_hosts, nbns_hosts, kerberos_users, kerberos_hosts = {}, {}, set(), set()
    # DISCOVER/REQUEST come from 0.0.0.0: file the hostname under the address
    # the server hands that MAC (ACK yiaddr), else the one it asked for.
    mac_to_ip: dict[str, str] = {}
    for p in packets:
        f = p.fields
        mac = f.get("dhcp.hw.mac_addr")
        if mac and f.get("dhcp.option.dhcp") == 5 and f.get("dhcp.yiaddr"):
            mac_to_ip[mac] = f["dhcp.yiaddr"]
    for p in packets:
        f = p.fields
        if f.get("dhcp.option.hostname"):
            mac = f.get("dhcp.hw.mac_addr")
            ip = p.src_ip if p.src_ip not in (None, "0.0.0.0") else (
                mac_to_ip.get(mac) or f.get("dhcp.option.requested_ip_address")
                or (f"(MAC {mac})" if mac else "0.0.0.0"))
            dhcp_hosts.setdefault(ip, set()).add(f["dhcp.option.hostname"])
        owner = nbns_owner(p)
        if owner:
            nbns_hosts.setdefault(owner, set()).add(f["nbns.name"])
        cname = f.get("kerberos.CNameString")
        if cname:
            # The room's own heuristic: names ending in "$" are hostnames
            # (machine accounts), not users.
            for part in cname.split("/"):
                if part.endswith("$"):
                    kerberos_hosts.add(part.rstrip("$"))
                elif part:
                    kerberos_users.add(part)
        if f.get("kerberos.hostname"):
            kerberos_hosts.add(f["kerberos.hostname"].rstrip("$"))
    return {
        "dhcp_hostnames": {ip: sorted(names) for ip, names in dhcp_hosts.items()},
        "nbns_hostnames": {ip: sorted(names) for ip, names in nbns_hosts.items()},
        "kerberos_users": sorted(kerberos_users),
        "kerberos_hosts": sorted(kerberos_hosts),
    }
