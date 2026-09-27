"""
C2 beacon detection.

The idea: humans and applications produce bursty, irregular traffic. Implants
poll on a timer. Group traffic into (src, dst, dst_port) channels, take the
inter-arrival gaps, and score how regular they are.

Two statistics are used together:
  jitter_ratio  = stdev/mean   -- sensitive, but one long gap wrecks it
  mad_ratio     = MAD/median   -- robust, survives dropped beacons
A channel is a beacon when either is tight AND the period is plausible.
Constant payload size is a third, independent confirmation.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from typing import Sequence

from ..enrich import (SUSPICIOUS_PORTS, dominant_period, in_networks, intervals,
                      jitter_ratio, mad_over_median, service_name)
from ..models import Event, EventKind, Finding
from .base import Detector, register


@register
class BeaconDetector(Detector):
    name = "beaconing"
    rule_prefix = "NSM-C2"
    description = "Periodic outbound connections to a fixed external endpoint."

    def run(self, events: Sequence[Event]) -> list[Finding]:
        cfg = self.cfg
        channels: dict[tuple[str, str, int | None], list[Event]] = defaultdict(list)

        for ev in events:
            if ev.kind not in (EventKind.NETWORK_FLOW, EventKind.HTTP,
                               EventKind.DNS, EventKind.IDS_ALERT):
                continue
            if not (ev.src_ip and ev.dst_ip and ev.timestamp):
                continue
            # Beaconing is an egress concern: internal source, external destination.
            if not in_networks(ev.src_ip, cfg.home_nets):
                continue
            if in_networks(ev.dst_ip, cfg.home_nets):
                continue
            channels[(ev.src_ip, ev.dst_ip, ev.dst_port)].append(ev)

        findings: list[Finding] = []
        for (src, dst, port), evs in channels.items():
            if len(evs) < cfg.beacon_min_events:
                continue
            evs.sort(key=lambda e: e.timestamp)

            # De-duplicate identical timestamps (one logical connection logged twice).
            seen, uniq = set(), []
            for e in evs:
                if e.timestamp not in seen:
                    seen.add(e.timestamp)
                    uniq.append(e)
            if len(uniq) < cfg.beacon_min_events:
                continue

            gaps = intervals([e.timestamp for e in uniq])
            jr = jitter_ratio(gaps)
            mr = mad_over_median(gaps)
            period = dominant_period(gaps)
            if period is None or jr is None:
                continue
            if not (cfg.beacon_min_period_s <= period <= cfg.beacon_max_period_s):
                continue

            regular = (jr <= cfg.beacon_max_jitter) or (mr is not None and mr <= cfg.beacon_max_mad_ratio)
            if not regular:
                continue

            # Payload-size consistency: implants send near-identical check-ins.
            sizes = [e.bytes_out for e in uniq if e.bytes_out > 0]
            size_cv = None
            if len(sizes) >= 3 and statistics.fmean(sizes) > 0:
                size_cv = statistics.pstdev(sizes) / statistics.fmean(sizes)

            score = 0
            if jr <= 0.10:
                score += 3
            elif jr <= cfg.beacon_max_jitter:
                score += 2
            if mr is not None and mr <= cfg.beacon_max_mad_ratio:
                score += 1
            if size_cv is not None and size_cv <= cfg.beacon_size_cv_max:
                score += 2
            if port in SUSPICIOUS_PORTS:
                score += 3
            if len(uniq) >= 20:
                score += 1
            has_c2_alert = any("c2" in (e.signature or "").lower()
                               or "trojan" in (e.signature or "").lower()
                               or "beacon" in (e.signature or "").lower() for e in uniq)
            if has_c2_alert:
                score += 3

            severity = "critical" if score >= 7 else "high" if score >= 5 else "medium"
            confidence = "high" if score >= 6 else "medium" if score >= 4 else "low"

            f = Finding(
                rule_id="NSM-C2-001",
                title=f"C2 beaconing: {src} -> {dst}:{port} every ~{period:.0f}s",
                severity=severity,
                confidence=confidence,
                description=(
                    f"{len(uniq)} connections from {src} to {dst}:{port} ({service_name(port)}) "
                    f"at a near-constant interval of {period:.0f}s "
                    f"(jitter {jr:.1%}"
                    + (f", MAD ratio {mr:.1%}" if mr is not None else "")
                    + (f", payload size CV {size_cv:.1%}" if size_cv is not None else "")
                    + "). Traffic at perfect, regular intervals is malware check-in, not human browsing."
                    + (" IDS already flagged this channel as C2/Trojan." if has_c2_alert else "")
                ),
                src_ip=src, dst_ip=dst, entity=f"{dst}:{port}",
                mitre=["T1071.001", "T1573"] + (["T1571"] if port in SUSPICIOUS_PORTS else []),
                kill_chain="Command & Control",
                metrics={
                    "connections": len(uniq),
                    "period_seconds": round(period, 1),
                    "jitter_ratio": round(jr, 4),
                    "mad_ratio": round(mr, 4) if mr is not None else None,
                    "size_cv": round(size_cv, 4) if size_cv is not None else None,
                    "port": port, "service": service_name(port),
                    "suspicious_port": port in SUSPICIOUS_PORTS,
                    "ids_confirmed": has_c2_alert,
                    "score": score,
                    "duration_hours": round((uniq[-1].timestamp - uniq[0].timestamp).total_seconds() / 3600, 1),
                },
                recommendation=(
                    f"Contain {src}. Block {dst} at the perimeter and add it to the IOC list. "
                    "Pull EDR process/network telemetry for the host to identify the implant, and check "
                    "whether other internal hosts talk to the same destination."
                ),
            )
            findings.append(self._attach(f, uniq))

        # A log source that omits the destination port (many proxy exports) produces
        # a duplicate channel for a pair already reported with a real port. Drop it.
        with_port = {(f.src_ip, f.dst_ip) for f in findings if f.metrics.get("port") is not None}
        return [f for f in findings
                if f.metrics.get("port") is not None
                or (f.src_ip, f.dst_ip) not in with_port]


@register
class SuspiciousPortDetector(Detector):
    name = "suspicious_port"
    rule_prefix = "NSM-C2"
    description = "Traffic on default offensive-tooling ports (4444, 50050, ...)."

    def run(self, events: Sequence[Event]) -> list[Finding]:
        cfg = self.cfg
        groups: dict[tuple[str, str, int], list[Event]] = defaultdict(list)
        for ev in events:
            if ev.dst_port in SUSPICIOUS_PORTS and ev.src_ip and ev.dst_ip:
                groups[(ev.src_ip, ev.dst_ip, ev.dst_port)].append(ev)

        findings: list[Finding] = []
        for (src, dst, port), evs in groups.items():
            outbound = in_networks(src, cfg.home_nets) and not in_networks(dst, cfg.home_nets)
            f = Finding(
                rule_id="NSM-C2-002",
                title=f"Traffic on offensive-tooling port {port}: {src} -> {dst}",
                severity="high" if outbound else "medium",
                confidence="medium",
                description=(
                    f"{len(evs)} events between {src} and {dst} on port {port} "
                    f"({service_name(port)}). This port has no legitimate business use in most "
                    "environments; it is the Metasploit/Cobalt Strike default listener."
                ),
                src_ip=src, dst_ip=dst, entity=f"{dst}:{port}",
                mitre=["T1571"],
                kill_chain="Command & Control",
                metrics={"events": len(evs), "port": port, "outbound": outbound},
                recommendation=f"Block {port}/tcp egress and investigate both endpoints.",
            )
            findings.append(self._attach(f, sorted(evs, key=lambda e: e.timestamp)))
        return findings
