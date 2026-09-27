"""
Nmap scan fingerprinting (Wireshark: Traffic Analysis, task 2) plus the
vertical/horizontal aggregation nsmkit already does for log-derived scans --
here driven off the actual TCP flags/window and ICMP unreachable packets
instead of a firewall log line, which is what lets trafkit tell a TCP
*Connect* scan apart from a *SYN* scan in the first place (a firewall ACCEPT
log can't; a captured window size and a finished handshake can).
"""

from __future__ import annotations

from collections import defaultdict

from ..models import Finding, PacketRecord
from ._window import slide
from .base import AnalysisContext, Detector, register


@register
class NmapScanDetector(Detector):
    id = "SCAN-NMAP-01"
    title = "Nmap-style port scan"

    def run(self, packets: list[PacketRecord], ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        findings += self._vertical(packets)
        findings += self._horizontal(packets)
        findings += self._udp(packets)
        return findings

    # -- TCP Connect / SYN scans, grouped by (src -> one dst): many ports --
    def _vertical(self, packets: list[PacketRecord]) -> list[Finding]:
        by_pair: dict[tuple, list[PacketRecord]] = defaultdict(list)
        for p in packets:
            f = p.fields
            if p.proto == "tcp" and f.get("tcp.flags.syn") == 1 and f.get("tcp.flags.ack") == 0:
                by_pair[(p.src_ip, p.dst_ip)].append(p)

        findings = []
        for (src, dst), pkts in by_pair.items():
            pkts.sort(key=lambda x: x.ts)
            window = self._slide(pkts, self.cfg.vertical_scan_window_seconds)
            if window is None:
                continue
            ports = {p.dst_port for p in window}
            if len(ports) < self.cfg.vertical_scan_min_ports:
                continue
            connect_n = sum(1 for p in window
                             if p.fields.get("tcp.window_size", 0) > self.cfg.scan_connect_window_floor)
            syn_n = len(window) - connect_n
            scan_type = "TCP Connect (-sT)" if connect_n >= syn_n else "TCP SYN (-sS)"
            findings.append(self._finding(
                severity="high" if len(ports) >= self.cfg.vertical_scan_min_ports * 2 else "medium",
                confidence="high",
                description=(f"{src} probed {len(ports)} distinct TCP ports on {dst} within "
                             f"{self.cfg.vertical_scan_window_seconds}s -- fingerprint matches a "
                             f"{scan_type} scan (window size {'>' if connect_n >= syn_n else '<='} "
                             f"{self.cfg.scan_connect_window_floor} on {max(connect_n, syn_n)}/"
                             f"{len(window)} probes)."),
                frames=[p.frame_number for p in window[:25]],
                evidence={"src": src, "dst": dst, "ports_probed": sorted(ports)[:50],
                          "scan_type": scan_type},
                recommendation="Confirm the source is an authorised scanner (vuln management, "
                                "pentest). If not, treat as reconnaissance and escalate per runbook.",
                mitre="T1046 Network Service Discovery",
            ))
        return findings

    # -- one port, many destination hosts: a host sweep --
    def _horizontal(self, packets: list[PacketRecord]) -> list[Finding]:
        by_src_port: dict[tuple, list[PacketRecord]] = defaultdict(list)
        for p in packets:
            f = p.fields
            if p.proto == "tcp" and f.get("tcp.flags.syn") == 1 and f.get("tcp.flags.ack") == 0:
                by_src_port[(p.src_ip, p.dst_port)].append(p)

        findings = []
        for (src, port), pkts in by_src_port.items():
            pkts.sort(key=lambda x: x.ts)
            window = self._slide(pkts, self.cfg.horizontal_scan_window_seconds)
            if window is None:
                continue
            hosts = {p.dst_ip for p in window}
            if len(hosts) < self.cfg.horizontal_scan_min_hosts:
                continue
            findings.append(self._finding(
                rule_id="SCAN-NMAP-02", title="Horizontal port sweep",
                severity="medium", confidence="high",
                description=(f"{src} probed TCP port {port} on {len(hosts)} distinct hosts within "
                             f"{self.cfg.horizontal_scan_window_seconds}s -- a host-discovery sweep "
                             f"rather than a single-target scan."),
                frames=[p.frame_number for p in window[:25]],
                evidence={"src": src, "port": port, "hosts_probed": sorted(hosts)[:50]},
                recommendation="Identify what the source was looking for on this port; correlate "
                                "with asset inventory to see which hosts actually run that service.",
                mitre="T1046 Network Service Discovery",
            ))
        return findings

    # -- UDP scan: closed ports answer with ICMP type 3 code 3 --
    def _udp(self, packets: list[PacketRecord]) -> list[Finding]:
        by_pair: dict[tuple, list[PacketRecord]] = defaultdict(list)
        for p in packets:
            f = p.fields
            if p.proto == "icmp" and f.get("icmp.type") == 3 and f.get("icmp.code") == 3:
                orig_dst_port = f.get("icmp.orig.udp.dstport")
                orig_prober = f.get("icmp.orig.ip.src") or f.get("icmp.orig.ip.dst")
                if orig_dst_port is None:
                    continue
                # ICMP travels scanned-host -> prober; the prober is the
                # original UDP packet's source.
                prober = f.get("icmp.orig.ip.src", p.dst_ip)
                by_pair[(prober, p.src_ip)].append(p)

        findings = []
        for (prober, scanned), pkts in by_pair.items():
            pkts.sort(key=lambda x: x.ts)
            window = self._slide(pkts, self.cfg.udp_scan_window_seconds)
            if window is None:
                continue
            ports = {p.fields.get("icmp.orig.udp.dstport") for p in window}
            ports.discard(None)
            if len(ports) < self.cfg.udp_scan_min_unreachables:
                continue
            findings.append(self._finding(
                rule_id="SCAN-NMAP-03", title="UDP port scan (-sU)",
                severity="medium", confidence="high",
                description=(f"{scanned} returned ICMP port-unreachable for {len(ports)} distinct "
                             f"UDP ports probed by {prober} within {self.cfg.udp_scan_window_seconds}s "
                             f"-- consistent with `nmap -sU`."),
                frames=[p.frame_number for p in window[:25]],
                evidence={"prober": prober, "scanned": scanned, "closed_ports": sorted(ports)[:50]},
                recommendation="UDP scans are slow and noisy by nature; a real one usually means "
                                "active reconnaissance rather than a stray misconfigured client.",
                mitre="T1046 Network Service Discovery",
            ))
        return findings

    @staticmethod
    def _slide(pkts: list[PacketRecord], window_seconds: int) -> list[PacketRecord] | None:
        """The largest run of packets spanning <= window seconds (O(n))."""
        return slide(pkts, window_seconds)
