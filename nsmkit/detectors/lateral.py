"""
Lateral-movement detectors.

The perimeter room's pivot: once a VPN account is cracked, the attacker's
assigned pool address starts talking to internal hosts on 22/445/3389. That
internal-to-internal fan-out on admin protocols is the signal.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Sequence

from ..enrich import LATERAL_PORTS, in_networks, service_name
from ..models import Action, Event, EventKind, Finding
from .base import Detector, register
from ._window import best_distinct, best_count  # noqa: E402


@register
class LateralMovementDetector(Detector):
    name = "lateral_movement"
    rule_prefix = "NSM-LAT"
    description = "Internal host reaching multiple internal hosts on admin protocols."

    def run(self, events: Sequence[Event]) -> list[Finding]:
        cfg = self.cfg
        by_src: dict[str, list[Event]] = defaultdict(list)
        for ev in events:
            if not (ev.src_ip and ev.dst_ip and ev.dst_port):
                continue
            if ev.dst_port not in LATERAL_PORTS:
                continue
            if not (in_networks(ev.src_ip, cfg.home_nets + cfg.vpn_pool_nets)
                    and in_networks(ev.dst_ip, cfg.home_nets)):
                continue
            if ev.src_ip in cfg.scanner_allowlist:
                continue
            by_src[ev.src_ip].append(ev)

        findings: list[Finding] = []
        for src, evs in by_src.items():
            evs.sort(key=lambda e: e.timestamp)
            best = best_distinct(evs, lambda e: e.dst_ip, cfg.lateral_window_s)
            if not best:
                continue

            targets = sorted({e.dst_ip for e in best})
            if len(targets) < cfg.lateral_min_targets:
                continue

            ports = sorted({e.dst_port for e in best})
            allowed = sum(1 for e in best if e.action is Action.ALLOW)
            from_vpn_pool = in_networks(src, cfg.vpn_pool_nets)
            exploit_alerts = [e for e in best
                              if e.kind == EventKind.IDS_ALERT
                              and any(k in (e.signature or "").lower()
                                      for k in ("exploit", "lateral", "brute", "psexec", "smb"))]

            score = 2
            if len(ports) >= 2:
                score += 2
            if from_vpn_pool:
                score += 3
            if exploit_alerts:
                score += 3
            if allowed > 0:
                score += 2
            if len(targets) >= 5:
                score += 1

            f = Finding(
                rule_id="NSM-LAT-001",
                title=f"Lateral movement from {src} to {len(targets)} internal hosts",
                severity="critical" if score >= 8 else "high",
                confidence="high" if exploit_alerts or from_vpn_pool else "medium",
                description=(
                    f"{src} connected to {len(targets)} internal hosts on "
                    f"{', '.join(f'{p}/{service_name(p)}' for p in ports)} within "
                    f"{cfg.lateral_window_s}s ({allowed} allowed). "
                    + ("The source is a VPN pool address, so this is a remote-access session pivoting "
                       "inward -- correlate back to the VPN auth log for the account. "
                       if from_vpn_pool else "")
                    + (f"IDS raised {len(exploit_alerts)} exploit/lateral signatures on this traffic."
                       if exploit_alerts else "")
                ),
                src_ip=src,
                mitre=["T1021.001", "T1021.002", "T1021.004", "T1210"],
                kill_chain="Lateral Movement",
                metrics={"targets": targets[:30], "target_count": len(targets),
                         "ports": ports, "services": [service_name(p) for p in ports],
                         "allowed": allowed, "attempts": len(best),
                         "from_vpn_pool": from_vpn_pool,
                         "ids_exploit_alerts": len(exploit_alerts),
                         "signatures": sorted({e.signature for e in exploit_alerts if e.signature})[:10],
                         "score": score},
                recommendation=(
                    "Isolate the source immediately. Pull Windows Security 4624/4625/4648 and Sysmon "
                    "from each target to confirm which sessions succeeded, and reset credentials used "
                    "on those hosts before they are reused."
                ),
            )
            findings.append(self._attach(f, best))
        return findings


@register
class InternalExploitAlertDetector(Detector):
    name = "internal_exploit"
    rule_prefix = "NSM-LAT"
    description = "IDS exploit signatures where both endpoints are internal."

    def run(self, events: Sequence[Event]) -> list[Finding]:
        cfg = self.cfg
        groups: dict[tuple[str, str], list[Event]] = defaultdict(list)
        for ev in events:
            if ev.kind != EventKind.IDS_ALERT or not (ev.src_ip and ev.dst_ip):
                continue
            sig = (ev.signature or "").lower()
            if "exploit" not in sig and "unauthorized" not in (ev.classification or "").lower():
                continue
            if in_networks(ev.src_ip, cfg.home_nets + cfg.vpn_pool_nets) and \
               in_networks(ev.dst_ip, cfg.home_nets):
                groups[(ev.src_ip, ev.dst_ip)].append(ev)

        findings = []
        for (src, dst), evs in groups.items():
            evs.sort(key=lambda e: e.timestamp)
            sigs = sorted({e.signature for e in evs if e.signature})
            f = Finding(
                rule_id="NSM-LAT-002",
                title=f"Internal exploit attempt: {src} -> {dst}",
                severity="critical",
                confidence="high",
                description=(
                    f"{len(evs)} exploit signatures fired on internal-to-internal traffic from {src} "
                    f"to {dst}: {'; '.join(sigs[:4])}. An exploit attempt where both ends are inside "
                    "the network means the attacker already has a foothold -- this is no longer a "
                    "perimeter problem."
                ),
                src_ip=src, dst_ip=dst,
                mitre=["T1210"],
                kill_chain="Lateral Movement",
                metrics={"alerts": len(evs), "signatures": sigs[:10],
                         "ports": sorted({e.dst_port for e in evs if e.dst_port})},
                recommendation="Initiate incident response; contain both hosts and preserve memory and disk.",
            )
            findings.append(self._attach(f, evs))
        return findings
