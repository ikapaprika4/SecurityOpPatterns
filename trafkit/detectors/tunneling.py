"""
ICMP and DNS tunnelling (Wireshark: Traffic Analysis, task 5) -- oversized
ICMP payloads and long/high-entropy/encoded-looking DNS query names,
aggregated per source so a handful of odd packets doesn't fire but a
sustained channel does.
"""

from __future__ import annotations

from collections import defaultdict

from ..enrich import digit_ratio, looks_encoded, shannon_entropy
from ..models import Finding, PacketRecord
from ._window import slide
from .base import AnalysisContext, Detector, register

_KNOWN_TUNNEL_TOOLS = ("dnscat", "dns2tcp", "iodine", "dnscat2")


@register
class ICMPTunnelDetector(Detector):
    id = "TUNNEL-ICMP-01"
    title = "Oversized ICMP payloads (possible ICMP tunnelling)"

    def run(self, packets: list[PacketRecord], ctx: AnalysisContext) -> list[Finding]:
        # Echo request/reply is inherently bidirectional -- group by the
        # unordered {A, B} pair (a Wireshark "conversation", not a one-way
        # flow) so a tunnel's outbound and inbound legs report as one
        # finding instead of two mirror-image ones.
        by_pair: dict[tuple, list[PacketRecord]] = defaultdict(list)
        for p in packets:
            f = p.fields
            if p.proto != "icmp":
                continue
            if f.get("icmp.type") not in (0, 8):  # echo request/reply only
                continue
            if f.get("data.len", 0) <= self.cfg.icmp_tunnel_payload_len_floor:
                continue
            by_pair[tuple(sorted((p.src_ip, p.dst_ip)))].append(p)

        findings = []
        for (src, dst), pkts in by_pair.items():
            pkts.sort(key=lambda x: x.ts)
            window = _slide(pkts, self.cfg.icmp_tunnel_window_seconds)
            if window is None or len(window) < self.cfg.icmp_tunnel_min_packets:
                continue
            sizes = [p.fields.get("data.len", 0) for p in window]
            findings.append(self._finding(
                severity="high", confidence="medium",
                description=(f"{len(window)} oversized ICMP echo packets from {src} to {dst} "
                             f"within {self.cfg.icmp_tunnel_window_seconds}s (payload "
                             f"{min(sizes)}-{max(sizes)} bytes, stock ping is ~32-64 bytes). "
                             f"A sustained run of large ICMP payloads is the classic signature "
                             f"of a C2 or data-exfiltration tunnel riding on a trusted protocol."),
                frames=[p.frame_number for p in window[:25]],
                evidence={"src": src, "dst": dst, "packet_count": len(window),
                          "payload_size_range": [min(sizes), max(sizes)]},
                recommendation="Most enterprise egress filters block custom ICMP payloads by "
                                "default -- if this traffic actually left the network, that "
                                "control is missing or bypassed. Extract and inspect the payload.",
                mitre="T1095 Non-Application Layer Protocol",
            ))
        return findings


@register
class DNSTunnelDetector(Detector):
    id = "TUNNEL-DNS-01"
    title = "DNS tunnelling"

    def run(self, packets: list[PacketRecord], ctx: AnalysisContext) -> list[Finding]:
        allow = tuple(d.lower() for d in self.cfg.dns_tunnel_allowlist)
        by_src: dict[str, list[PacketRecord]] = defaultdict(list)
        for p in packets:
            f = p.fields
            qname = f.get("dns.qry.name")
            if not qname or f.get("dns.flags.response"):
                continue
            low = qname.lower().rstrip(".")
            if any(low == d or low.endswith("." + d) for d in allow):
                continue
            by_src[p.src_ip].append(p)

        findings = []
        for src, pkts in by_src.items():
            pkts.sort(key=lambda x: x.ts)
            window = _slide(pkts, self.cfg.dns_tunnel_window_seconds)
            if window is None or len(window) < self.cfg.dns_tunnel_min_queries:
                continue

            scored = [(p, self._score(p.fields.get("dns.qry.name", ""))) for p in window]
            suspicious = [p for p, s in scored if s >= 2]
            if len(suspicious) < self.cfg.dns_tunnel_min_queries:
                continue

            names = [p.fields["dns.qry.name"] for p in suspicious]
            avg_len = sum(len(n) for n in names) / len(names)
            avg_entropy = sum(shannon_entropy(n.split(".")[0]) for n in names) / len(names)
            findings.append(self._finding(
                severity="high", confidence="medium",
                description=(f"{src} issued {len(suspicious)} DNS queries within "
                             f"{self.cfg.dns_tunnel_window_seconds}s whose subdomains look encoded "
                             f"rather than human-chosen (avg length {avg_len:.0f} chars, avg "
                             f"subdomain entropy {avg_entropy:.2f} bits/char) -- consistent with "
                             f"data or C2 traffic smuggled through DNS labels."),
                frames=[p.frame_number for p in suspicious[:25]],
                evidence={"src": src, "query_count": len(suspicious),
                          "sample_queries": names[:10], "avg_query_len": round(avg_len, 1)},
                recommendation="Pull the TXT/A answers for these queries -- if they carry commands "
                                "or exfiltrated data, this is an active tunnel, not just chatty DNS.",
                mitre="T1071.004 Application Layer Protocol: DNS",
            ))
        return findings

    def _score(self, qname: str) -> int:
        """Small point score, not a single gate -- mirrors nsmkit's DNS
        tunnel scoring so one signal alone (e.g. just a long name) doesn't
        misfire on legitimate CDN/tracking subdomains."""
        score = 0
        if any(tool in qname.lower() for tool in _KNOWN_TUNNEL_TOOLS):
            score += 5
        if len(qname) >= self.cfg.dns_tunnel_qname_len_floor:
            score += 1
        label = qname.split(".")[0]
        if looks_encoded(label):
            score += 2
        if shannon_entropy(label) >= 3.5:
            score += 1
        if digit_ratio(label) > 0.4:
            score += 1
        return score


def _slide(pkts: list[PacketRecord], window_seconds: int):
    return slide(pkts, window_seconds)
