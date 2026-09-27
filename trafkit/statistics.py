"""
Wireshark "Statistics" menu, reimplemented over PacketRecords: protocol
hierarchy, endpoints, and per-protocol (DNS/HTTP) summaries -- the
low-hanging-fruit overview a triage pass should start with, before anyone
opens a single packet.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from .models import PacketRecord


def protocol_hierarchy(packets: list[PacketRecord]) -> dict[str, int]:
    """Packet counts per top-level protocol, plus the application-layer
    protocols trafkit was able to identify inside TCP/UDP."""
    counts: Counter[str] = Counter()
    for p in packets:
        if p.proto is None:
            counts["ip (unrecognised transport)"] += 1
            continue
        counts[p.proto] += 1
        f = p.fields
        if f.get("http.request") or f.get("http.response"):
            counts["tcp.http"] += 1
        if f.get("ftp.request.command") or f.get("ftp.response.code"):
            counts["tcp.ftp"] += 1
        if f.get("tls.handshake.type") is not None:
            counts["tcp.tls"] += 1
        if "dns.qry.name" in f:
            counts["udp.dns"] += 1
        if f.get("dhcp.option.dhcp") is not None:
            counts["udp.dhcp"] += 1
        if f.get("nbns.name"):
            counts["udp.nbns"] += 1
        if f.get("kerberos"):
            counts["udp.kerberos"] += 1
    return dict(counts.most_common())


@dataclass
class EndpointStats:
    address: str
    packets: int = 0
    bytes: int = 0


def endpoints(packets: list[PacketRecord]) -> list[EndpointStats]:
    agg: dict[str, EndpointStats] = {}
    for p in packets:
        for addr in (p.src_ip, p.dst_ip):
            if not addr:
                continue
            e = agg.setdefault(addr, EndpointStats(address=addr))
            e.packets += 1
            e.bytes += p.length
    return sorted(agg.values(), key=lambda e: e.bytes, reverse=True)


@dataclass
class DNSStats:
    total_queries: int = 0
    total_responses: int = 0
    unique_query_names: int = 0
    top_queried: list[tuple] = field(default_factory=list)
    qtype_counts: dict = field(default_factory=dict)
    nxdomain: int = 0


def dns_stats(packets: list[PacketRecord]) -> DNSStats:
    stats = DNSStats()
    names = Counter()
    qtypes = Counter()
    for p in packets:
        f = p.fields
        if "dns.qry.name" not in f:
            continue
        if f.get("dns.flags.response"):
            stats.total_responses += 1
            if f.get("dns.rcode") == 3:
                stats.nxdomain += 1
        else:
            stats.total_queries += 1
            names[f["dns.qry.name"]] += 1
        qtypes[f.get("dns.qry.type.name", "?")] += 1
    stats.unique_query_names = len(names)
    stats.top_queried = names.most_common(10)
    stats.qtype_counts = dict(qtypes.most_common())
    return stats


@dataclass
class HTTPStats:
    total_requests: int = 0
    total_responses: int = 0
    methods: dict = field(default_factory=dict)
    status_codes: dict = field(default_factory=dict)
    top_hosts: list[tuple] = field(default_factory=list)
    user_agents: list[tuple] = field(default_factory=list)


def http_stats(packets: list[PacketRecord]) -> HTTPStats:
    stats = HTTPStats()
    methods, codes, hosts, uas = Counter(), Counter(), Counter(), Counter()
    for p in packets:
        f = p.fields
        if f.get("http.request"):
            stats.total_requests += 1
            if f.get("http.request.method"):
                methods[f["http.request.method"]] += 1
            if f.get("http.host"):
                hosts[f["http.host"]] += 1
            if f.get("http.user_agent"):
                uas[f["http.user_agent"]] += 1
        if f.get("http.response"):
            stats.total_responses += 1
            if f.get("http.response.code") is not None:
                codes[str(f["http.response.code"])] += 1
    stats.methods = dict(methods.most_common())
    stats.status_codes = dict(codes.most_common())
    stats.top_hosts = hosts.most_common(10)
    stats.user_agents = uas.most_common(10)
    return stats


def capture_summary(packets: list[PacketRecord]) -> dict:
    if not packets:
        return {"packet_count": 0}
    first, last = packets[0].ts, packets[-1].ts
    return {
        "packet_count": len(packets),
        "total_bytes": sum(p.length for p in packets),
        "duration_seconds": round(max(0.0, last - first), 3),
        "protocol_hierarchy": protocol_hierarchy(packets),
    }
