"""
ARP spoofing / poisoning / flooding (Wireshark: Traffic Analysis, task 3) --
IP-to-MAC conflict tracking, request flooding, and the MITM relay pattern
the room walks through by hand (attacker's MAC becomes the destination for
traffic whose IP layer still says it's going to the real gateway).
"""

from __future__ import annotations

from collections import defaultdict

from ..models import Finding, PacketRecord
from ._window import largest_mixed_window, slide
from .base import AnalysisContext, Detector, register


@register
class ARPSpoofDetector(Detector):
    id = "ARP-SPOOF-01"
    title = "ARP spoofing (conflicting IP-to-MAC claims)"

    def run(self, packets: list[PacketRecord], ctx: AnalysisContext) -> list[Finding]:
        # ip -> [(ts, mac, frame)] for every ARP reply/announcement claiming it.
        claims: dict[str, list[tuple]] = defaultdict(list)
        for p in packets:
            if p.proto != "arp":
                continue
            f = p.fields
            if f.get("arp.opcode") != 2:  # only replies/announcements assert ownership
                continue
            ip, mac = f.get("arp.src.proto_ipv4"), f.get("arp.src.hw_mac")
            if ip and mac:
                claims[ip].append((p.ts, mac, p.frame_number))

        findings = []
        attacker_macs: set[str] = set()
        for ip, entries in claims.items():
            entries.sort()
            macs_in_window = self._conflicting_window(entries, self.cfg.arp_conflict_window_seconds)
            if macs_in_window is None:
                continue
            macs = {m for _, m, _ in macs_in_window}
            frames = [fr for _, _, fr in macs_in_window]
            attacker_macs |= macs
            findings.append(self._finding(
                severity="critical", confidence="high",
                description=(f"{len(macs)} different MAC addresses claimed to own IP {ip} within "
                             f"{self.cfg.arp_conflict_window_seconds}s: {', '.join(sorted(macs))}. "
                             f"One of them is spoofing the other's identity on the LAN."),
                frames=frames[:25],
                evidence={"ip": ip, "claiming_macs": sorted(macs)},
                recommendation="Identify the legitimate MAC (switch CAM table / DHCP lease history) "
                                "and isolate the other -- this is textbook ARP cache poisoning, "
                                "usually staged before a MITM interception.",
                mitre="T1557.002 ARP Cache Poisoning",
            ))

        if attacker_macs:
            findings += self._relay_evidence(packets, attacker_macs)
        return findings

    @staticmethod
    def _conflicting_window(entries: list[tuple], window_seconds: int):
        """Largest window (<= window seconds) in which more than one MAC
        claims the IP; entries are (ts, mac, frame) tuples (O(n))."""
        return largest_mixed_window(entries, window_seconds,
                                    ts=lambda e: e[0], key=lambda e: e[1])

    def _relay_evidence(self, packets: list[PacketRecord], attacker_macs: set[str]) -> list[Finding]:
        """If traffic's link-layer destination is one of the spoofing MACs
        while the IP-layer destination is a *different* host entirely, the
        attacker is sitting in the path -- classic MITM relay."""
        relayed: dict[str, list[PacketRecord]] = defaultdict(list)
        for p in packets:
            if p.dst_mac in attacker_macs and p.dst_ip and p.src_ip:
                relayed[p.dst_mac].append(p)

        findings = []
        for mac, pkts in relayed.items():
            if len(pkts) < 3:
                continue
            victims = {p.src_ip for p in pkts}
            findings.append(self._finding(
                rule_id="ARP-SPOOF-02", title="Traffic relayed through a spoofing host (MITM)",
                severity="critical", confidence="high",
                description=(f"{len(pkts)} packets from {len(victims)} host(s) "
                             f"({', '.join(sorted(victims))}) were addressed at the link layer to "
                             f"{mac} -- the same MAC already flagged for conflicting ARP claims -- "
                             f"while their IP destination was somewhere else entirely. Traffic is "
                             f"being funnelled through the attacker before reaching its real target."),
                frames=[p.frame_number for p in pkts[:25]],
                evidence={"attacker_mac": mac, "victims": sorted(victims)},
                recommendation="Contain the attacker's port/MAC immediately -- this confirms active "
                                "interception, not just noisy ARP traffic.",
                mitre="T1557.002 ARP Cache Poisoning",
            ))
        return findings


@register
class ARPFloodDetector(Detector):
    id = "ARP-FLOOD-01"
    title = "ARP request flood / sweep"

    def run(self, packets: list[PacketRecord], ctx: AnalysisContext) -> list[Finding]:
        by_mac: dict[str, list[PacketRecord]] = defaultdict(list)
        for p in packets:
            if p.proto == "arp" and p.fields.get("arp.opcode") == 1:
                mac = p.fields.get("arp.src.hw_mac")
                if mac:
                    by_mac[mac].append(p)

        findings = []
        for mac, pkts in by_mac.items():
            pkts.sort(key=lambda x: x.ts)
            window = self._slide(pkts, self.cfg.arp_flood_window_seconds)
            if window is None:
                continue
            targets = {p.fields.get("arp.dst.proto_ipv4") for p in window}
            targets.discard(None)
            if len(targets) < self.cfg.arp_flood_min_targets:
                continue
            findings.append(self._finding(
                severity="medium", confidence="high",
                description=(f"{mac} sent ARP requests for {len(targets)} distinct IPs within "
                             f"{self.cfg.arp_flood_window_seconds}s -- either a host/network "
                             f"discovery sweep or ARP table flooding."),
                frames=[p.frame_number for p in window[:25]],
                evidence={"mac": mac, "targets_probed": sorted(targets)[:50]},
                recommendation="Correlate with DHCP/inventory to see whether this MAC is a known "
                                "scanner; unexplained ARP sweeps often precede a spoofing attempt.",
                mitre="T1046 Network Service Discovery",
            ))
        return findings

    @staticmethod
    def _slide(pkts, window_seconds):
        return slide(pkts, window_seconds)
