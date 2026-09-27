"""
Reconnaissance detectors.

Covers the two patterns that separate a scan from client traffic:
  one source -> many ports on one host      = vertical scan  (host footprinting)
  one source -> one port on many hosts      = horizontal scan (service hunting)

Severity is a function of direction. External->internal is Reconnaissance
(TA0043) and is routine internet noise; internal->internal is Discovery
(TA0007) and means someone already has a foothold.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Sequence

from ..enrich import in_networks, service_name
from ..models import Action, Event, EventKind, Finding
from .base import Detector, register
from ._window import best_distinct, best_count  # noqa: E402

_BLOCKED = {Action.BLOCK, Action.DROP, Action.RESET}


def _flows(events: Sequence[Event]) -> list[Event]:
    return [e for e in events
            if e.kind in (EventKind.NETWORK_FLOW, EventKind.IDS_ALERT)
            and e.src_ip and e.dst_ip]


@register
class VerticalScanDetector(Detector):
    name = "vertical_scan"
    rule_prefix = "NSM-SCAN"
    description = "One source enumerating many ports on a single destination host."

    def run(self, events: Sequence[Event]) -> list[Finding]:
        cfg = self.cfg
        pairs: dict[tuple[str, str], list[Event]] = defaultdict(list)
        for ev in _flows(events):
            if ev.dst_port is None:
                continue
            if ev.src_ip in cfg.scanner_allowlist or ev.src_ip in cfg.external_scanner_allowlist:
                continue
            pairs[(ev.src_ip, ev.dst_ip)].append(ev)

        findings: list[Finding] = []
        for (src, dst), evs in pairs.items():
            evs.sort(key=lambda e: e.timestamp)
            internal_src = in_networks(src, cfg.home_nets)
            min_ports = (cfg.internal_scan_min_ports if internal_src
                         else cfg.vertical_scan_min_ports)

            # Sliding window over the pair's events (O(n), see soccore.windows).
            best = best_distinct(evs, lambda e: e.dst_port, cfg.vertical_scan_window_s)
            if not best:
                continue

            ports = sorted({e.dst_port for e in best})
            if len(ports) < min_ports:
                continue

            blocked = sum(1 for e in best if e.action in _BLOCKED)
            block_ratio = blocked / len(best)
            # A high block ratio is the strongest separator between a scan and
            # a busy legitimate client.
            confidence = "high" if block_ratio >= cfg.scan_block_ratio else "medium"
            severity = "high" if internal_src else ("medium" if block_ratio >= cfg.scan_block_ratio else "low")

            f = Finding(
                rule_id="NSM-SCAN-001",
                title=f"Vertical port scan: {src} -> {dst} ({len(ports)} ports)",
                severity=severity,
                confidence=confidence,
                description=(
                    f"{src} touched {len(ports)} distinct ports on {dst} within "
                    f"{cfg.vertical_scan_window_s}s. {blocked}/{len(best)} attempts were denied "
                    f"({block_ratio:.0%}). Direction: "
                    f"{'internal->internal (post-compromise Discovery)' if internal_src else 'external->internal (Reconnaissance)'}."
                ),
                src_ip=src, dst_ip=dst,
                mitre=["T1046"] + (["T1595.001"] if not internal_src else []),
                kill_chain="Reconnaissance" if not internal_src else "Discovery",
                metrics={
                    "distinct_ports": len(ports),
                    "ports": ports[:40],
                    "services": sorted({service_name(p) for p in ports})[:20],
                    "attempts": len(best),
                    "blocked": blocked,
                    "block_ratio": round(block_ratio, 3),
                    "internal_source": internal_src,
                },
                recommendation=(
                    "Escalate to IR and isolate the source host; internal scanning implies an "
                    "existing foothold." if internal_src else
                    "Block the source at the perimeter and confirm no ALLOW entries exist for it."
                ),
            )
            findings.append(self._attach(f, best))
        return findings


@register
class HorizontalScanDetector(Detector):
    name = "horizontal_scan"
    rule_prefix = "NSM-SCAN"
    description = "One source probing the same port across many hosts."

    def run(self, events: Sequence[Event]) -> list[Finding]:
        cfg = self.cfg
        groups: dict[tuple[str, int], list[Event]] = defaultdict(list)
        for ev in _flows(events):
            if ev.dst_port is None:
                continue
            if ev.src_ip in cfg.scanner_allowlist or ev.src_ip in cfg.external_scanner_allowlist:
                continue
            groups[(ev.src_ip, ev.dst_port)].append(ev)

        findings: list[Finding] = []
        for (src, port), evs in groups.items():
            evs.sort(key=lambda e: e.timestamp)
            internal_src = in_networks(src, cfg.home_nets)
            min_hosts = (cfg.internal_scan_min_hosts if internal_src
                         else cfg.horizontal_scan_min_hosts)

            best = best_distinct(evs, lambda e: e.dst_ip, cfg.horizontal_scan_window_s)
            if not best:
                continue

            hosts = sorted({e.dst_ip for e in best})
            if len(hosts) < min_hosts:
                continue

            blocked = sum(1 for e in best if e.action in _BLOCKED)
            block_ratio = blocked / len(best)
            svc = service_name(port)
            severity = "high" if internal_src else "medium"
            if port in (445, 3389, 22, 23) and not internal_src:
                severity = "medium"

            f = Finding(
                rule_id="NSM-SCAN-002",
                title=f"Horizontal scan: {src} -> {len(hosts)} hosts on {port}/{svc}",
                severity=severity,
                confidence="high" if block_ratio >= cfg.scan_block_ratio else "medium",
                description=(
                    f"{src} probed port {port} ({svc}) across {len(hosts)} hosts within "
                    f"{cfg.horizontal_scan_window_s}s -- the signature of hunting for one exploitable "
                    f"service (the WannaCry/445 pattern). {blocked}/{len(best)} denied."
                ),
                src_ip=src, entity=f"{port}/{svc}",
                mitre=["T1046"] + (["T1595.001"] if not internal_src else []),
                kill_chain="Reconnaissance" if not internal_src else "Discovery",
                metrics={
                    "distinct_hosts": len(hosts), "hosts": hosts[:40],
                    "port": port, "service": svc,
                    "attempts": len(best), "blocked": blocked,
                    "block_ratio": round(block_ratio, 3),
                    "internal_source": internal_src,
                },
                recommendation=(
                    f"Confirm which hosts answered on {port}; patch or firewall them. "
                    "Internal source means IR, not just a firewall block." if internal_src else
                    f"Block the source and verify no host in the DMZ exposes {port} unintentionally."
                ),
            )
            findings.append(self._attach(f, best))
        return findings


@register
class PingSweepDetector(Detector):
    name = "ping_sweep"
    rule_prefix = "NSM-SCAN"
    description = "ICMP echo requests fanned across a subnet -- host discovery."

    def run(self, events: Sequence[Event]) -> list[Finding]:
        cfg = self.cfg
        by_src: dict[str, list[Event]] = defaultdict(list)
        for ev in events:
            is_icmp = (ev.protocol == "icmp") or ev.kind == EventKind.ICMP
            if not is_icmp or not ev.src_ip or not ev.dst_ip:
                continue
            if ev.icmp_type is not None and ev.icmp_type != 8:
                continue
            if ev.src_ip in cfg.scanner_allowlist:
                continue
            by_src[ev.src_ip].append(ev)

        findings: list[Finding] = []
        for src, evs in by_src.items():
            hosts = sorted({e.dst_ip for e in evs})
            if len(hosts) < cfg.ping_sweep_min_hosts:
                continue
            internal_src = in_networks(src, cfg.home_nets)
            f = Finding(
                rule_id="NSM-SCAN-003",
                title=f"ICMP ping sweep from {src} ({len(hosts)} hosts)",
                severity="high" if internal_src else "low",
                confidence="medium",
                description=(
                    f"{src} sent ICMP echo requests to {len(hosts)} distinct addresses -- "
                    "classic host-discovery sweep prior to port scanning."
                ),
                src_ip=src,
                mitre=["T1018"],
                kill_chain="Discovery" if internal_src else "Reconnaissance",
                metrics={"distinct_hosts": len(hosts), "hosts": hosts[:40],
                         "packets": len(evs), "internal_source": internal_src},
                recommendation="Block ICMP echo at the perimeter; investigate the host if the source is internal.",
            )
            findings.append(self._attach(f, sorted(evs, key=lambda e: e.timestamp)))
        return findings


@register
class ExposedServiceDetector(Detector):
    name = "exposed_service"
    rule_prefix = "NSM-PERIM"
    description = "High-risk management ports reachable from the internet (ALLOW at the perimeter)."

    def run(self, events: Sequence[Event]) -> list[Finding]:
        from ..enrich import HIGH_RISK_PORTS
        cfg = self.cfg
        exposures: dict[tuple[str, int], list[Event]] = defaultdict(list)
        for ev in _flows(events):
            if ev.action is not Action.ALLOW or ev.dst_port is None:
                continue
            if in_networks(ev.src_ip, cfg.home_nets):
                continue
            if not in_networks(ev.dst_ip, cfg.home_nets):
                continue
            if ev.dst_port in HIGH_RISK_PORTS:
                exposures[(ev.dst_ip, ev.dst_port)].append(ev)

        findings: list[Finding] = []
        for (dst, port), evs in exposures.items():
            sources = sorted({e.src_ip for e in evs})
            f = Finding(
                rule_id="NSM-PERIM-001",
                title=f"Internet-exposed {service_name(port)} on {dst}:{port}",
                severity="high",
                confidence="high",
                description=(
                    f"The firewall ALLOWED {len(evs)} inbound connections from {len(sources)} external "
                    f"source(s) to {dst}:{port} ({service_name(port)}). Management and database ports "
                    "should never be directly reachable from the internet -- this is the misconfiguration "
                    "attackers look for after a scan."
                ),
                dst_ip=dst, entity=f"{dst}:{port}",
                mitre=["T1133", "T1190"],
                kill_chain="Initial Access",
                metrics={"port": port, "service": service_name(port),
                         "allowed_connections": len(evs),
                         "distinct_sources": len(sources), "sources": sources[:20]},
                recommendation=(
                    f"Remove the perimeter rule permitting {port}/tcp inbound, or place the service "
                    "behind the VPN/DMZ. Review the host for prior compromise."
                ),
            )
            findings.append(self._attach(f, sorted(evs, key=lambda e: e.timestamp)))
        return findings
