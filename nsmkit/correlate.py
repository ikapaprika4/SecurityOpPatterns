"""
Correlation: turn a bag of findings into an incident narrative.

Two jobs:
  1. Chain findings that share a pivot (IP, user, VPN-assigned address) so the
     analyst sees "recon -> brute force -> lateral -> C2 -> exfil" rather than
     forty unrelated alerts.
  2. Follow the VPN pivot explicitly -- a cracked account's assigned_ip becomes
     the source IP of the next stage, which no single-log rule can see.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Sequence

from .enrich import in_networks
from .config import Config, DEFAULT_CONFIG
from .models import Action, Event, EventKind, Finding

KILL_CHAIN_ORDER = [
    "Reconnaissance", "Weaponization", "Delivery", "Exploitation",
    "Initial Access", "Installation", "Persistence", "Credential Access",
    "Discovery", "Lateral Movement", "Collection",
    "Command & Control", "Exfiltration", "Impact",
]


def _stage_rank(stage: str | None) -> int:
    try:
        return KILL_CHAIN_ORDER.index(stage) if stage else 99
    except ValueError:
        return 99


@dataclass
class Incident:
    """A set of findings linked by shared entities."""
    incident_id: str
    title: str = ""
    severity: str = "low"
    entities: set[str] = field(default_factory=set)
    findings: list[Finding] = field(default_factory=list)
    stages: list[str] = field(default_factory=list)

    @property
    def first_seen(self):
        ts = [f.first_seen for f in self.findings if f.first_seen]
        return min(ts) if ts else None

    @property
    def last_seen(self):
        ts = [f.last_seen for f in self.findings if f.last_seen]
        return max(ts) if ts else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "severity": self.severity,
            "entities": sorted(self.entities),
            "kill_chain_stages": self.stages,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }


def _entities(f: Finding) -> set[str]:
    out = set()
    for v in (f.src_ip, f.dst_ip, f.user, f.entity):
        if v:
            out.add(str(v))
    # Pull pivot values out of the metrics blob too.
    for key in ("assigned_ip", "destination", "domain", "responder", "ip", "mac"):
        v = f.metrics.get(key)
        if isinstance(v, str) and v:
            out.add(v)
    for key in ("targets", "hosts", "internal_hosts", "sources"):
        v = f.metrics.get(key)
        if isinstance(v, list):
            out.update(str(x) for x in v[:10] if x)
    return out


def correlate(findings: Sequence[Finding], config: Config | None = None) -> list[Incident]:
    """Union-find over shared entities.

    Shared infrastructure is not a join key: every host talks to the DNS
    resolver and the gateway, so linking findings through them would merge
    unrelated activity into one giant "incident". Addresses listed in the
    config as resolvers/gateways are ignored for linking (still reported)."""
    cfg = config or DEFAULT_CONFIG
    hubs = {str(x) for x in (*cfg.known_resolvers, *cfg.gateway_ips)}
    parent: dict[int, int] = {i: i for i in range(len(findings))}

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    ent_index: dict[str, list[int]] = defaultdict(list)
    for i, f in enumerate(findings):
        for e in _entities(f):
            if e not in hubs:
                ent_index[e].append(i)
    for idxs in ent_index.values():
        for j in idxs[1:]:
            union(idxs[0], j)

    groups: dict[int, list[int]] = defaultdict(list)
    for i in range(len(findings)):
        groups[find(i)].append(i)

    incidents: list[Incident] = []
    for n, idxs in enumerate(sorted(groups.values(), key=len, reverse=True), start=1):
        members = [findings[i] for i in idxs]
        # A finding without first_seen sorts last within its stage (comparing
        # a datetime with "" raised TypeError before).
        members.sort(key=lambda f: (_stage_rank(f.kill_chain), f.first_seen is None,
                                    f.first_seen or datetime.min))
        ents: set[str] = set()
        for f in members:
            ents |= _entities(f)
        stages = sorted({f.kill_chain for f in members if f.kill_chain}, key=_stage_rank)
        top = max(members, key=lambda f: f.severity_rank)
        inc = Incident(
            incident_id=f"INC-{n:03d}",
            title=(f"{stages[0]} -> {stages[-1]}: {top.title}" if len(stages) > 1 else top.title),
            severity=top.severity,
            entities=ents,
            findings=members,
            stages=stages,
        )
        incidents.append(inc)

    incidents.sort(key=lambda i: (-len(i.stages),
                                  -max(f.severity_rank for f in i.findings),
                                  -len(i.findings)))
    return incidents


# --------------------------------------------------------------------------
# VPN pivot: cracked account -> assigned IP -> internal activity
# --------------------------------------------------------------------------

def vpn_pivots(events: Sequence[Event], config: Config | None = None) -> list[dict[str, Any]]:
    """
    For each successful VPN auth, report what the assigned pool address then did.
    This is the join the perimeter investigation turns on and it cannot be seen
    in any single log file.
    """
    cfg = config or DEFAULT_CONFIG
    successes = [e for e in events
                 if e.kind == EventKind.AUTH and e.action is Action.SUCCESS and e.assigned_ip]
    if not successes:
        return []

    by_ip: dict[str, list[Event]] = defaultdict(list)
    for ev in events:
        if ev.src_ip:
            by_ip[ev.src_ip].append(ev)

    pivots = []
    for auth in successes:
        session = [e for e in by_ip.get(auth.assigned_ip, [])
                   if e.timestamp >= auth.timestamp
                   and (e.timestamp - auth.timestamp) <= timedelta(days=7)
                   and e.kind != EventKind.AUTH]
        if not session:
            continue
        session.sort(key=lambda e: e.timestamp)
        targets = sorted({e.dst_ip for e in session if e.dst_ip})
        ports = sorted({e.dst_port for e in session if e.dst_port})
        alerts = [e.signature for e in session if e.kind == EventKind.IDS_ALERT and e.signature]
        pivots.append({
            "user": auth.user,
            "external_ip": auth.src_ip,
            "assigned_ip": auth.assigned_ip,
            "login_time": auth.timestamp.isoformat(),
            "post_login_events": len(session),
            "internal_targets": targets[:30],
            "target_count": len(targets),
            "ports_touched": ports[:30],
            "ids_signatures": sorted(set(alerts))[:15],
            "first_activity": session[0].timestamp.isoformat(),
            "last_activity": session[-1].timestamp.isoformat(),
            "suspicious": bool(alerts) or len(targets) >= cfg.lateral_min_targets,
        })
    pivots.sort(key=lambda p: (not p["suspicious"], -p["target_count"]))
    return pivots


# --------------------------------------------------------------------------
# Top-talkers / triage statistics
# --------------------------------------------------------------------------

def summarise(events: Sequence[Event], config: Config | None = None) -> dict[str, Any]:
    """The stats an L1 analyst computes first -- the `sort | uniq -c` pass."""
    cfg = config or DEFAULT_CONFIG
    if not events:
        return {"event_count": 0}

    blocked_by_src: dict[str, int] = defaultdict(int)
    allowed_by_src: dict[str, int] = defaultdict(int)
    bytes_by_pair: dict[tuple[str, str], int] = defaultdict(int)
    alerts_by_sig: dict[str, int] = defaultdict(int)
    auth_fail_by_src: dict[str, int] = defaultdict(int)
    ports_by_dst: dict[str, set] = defaultdict(set)

    for ev in events:
        if ev.action in (Action.BLOCK, Action.DROP, Action.RESET) and ev.src_ip:
            blocked_by_src[ev.src_ip] += 1
        if ev.action is Action.ALLOW and ev.src_ip:
            allowed_by_src[ev.src_ip] += 1
        if ev.action is Action.FAILURE and ev.src_ip:
            auth_fail_by_src[ev.src_ip] += 1
        if ev.signature:
            alerts_by_sig[ev.signature] += 1
        if ev.src_ip and ev.dst_ip and ev.bytes_out:
            bytes_by_pair[(ev.src_ip, ev.dst_ip)] += ev.bytes_out
        if ev.dst_ip and ev.dst_port:
            ports_by_dst[ev.dst_ip].add(ev.dst_port)

    def top(d: dict, n: int = 10):
        return [{"key": (list(k) if isinstance(k, tuple) else k), "count": v}
                for k, v in sorted(d.items(), key=lambda kv: -kv[1])[:n]]

    ts = [e.timestamp for e in events if e.timestamp]
    return {
        "event_count": len(events),
        "time_range": {"start": min(ts).isoformat(), "end": max(ts).isoformat()} if ts else None,
        "by_source_type": {k: sum(1 for e in events if e.source_type == k)
                           for k in sorted({e.source_type for e in events})},
        "by_action": {k.value: sum(1 for e in events if e.action is k)
                      for k in {e.action for e in events}},
        "top_blocked_sources": top(blocked_by_src),
        "top_allowed_sources": top(allowed_by_src),
        "top_auth_failure_sources": top(auth_fail_by_src),
        "top_ids_signatures": top(alerts_by_sig),
        "top_upload_pairs": top(bytes_by_pair),
        "external_sources": sorted({e.src_ip for e in events
                                    if e.src_ip and not in_networks(e.src_ip, cfg.home_nets)})[:50],
        "internal_hosts_seen": sorted({e.dst_ip for e in events
                                       if e.dst_ip and in_networks(e.dst_ip, cfg.home_nets)})[:50],
    }
