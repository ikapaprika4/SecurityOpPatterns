"""
Command line interface.

    trafkit overview <pcap>            quick triage: summary, protocol hierarchy, top hosts
    trafkit hosts <pcap>                host inventory (IP/MAC/OS guess/ports/traffic)
    trafkit filter <pcap> <expr>        apply a Wireshark-style display filter
    trafkit analyze <pcap>              full detector run + report
    trafkit dns <pcap>                  DNS statistics
    trafkit http <pcap>                 HTTP statistics
    trafkit creds <pcap>                extract cleartext credentials
    trafkit files <pcap>                extracted file metadata
    trafkit keywords <pcap> <words...>  keyword search across every text field
    trafkit acl <pcap>                  generate firewall ACL rules from findings
    trafkit rules                       list every detection rule
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import Config, __version__, analyze as run_analyze, read_warnings
from .aclgen import SUPPORTED_TARGETS, generate_acl
from .detectors import REGISTRY
from .detectors.cleartext import extract_credentials
from .detectors.hostid import identify_hosts_and_users
from .extract import extract_files, search_keywords
from .filters import FilterSyntaxError, apply_filter
from .hosts import build_hosts, resolved_addresses
from .models import SEVERITY_ORDER
from .pcapread import read_pcap
from .report import render_console, render_html, render_json, render_markdown
from .statistics import capture_summary, dns_stats, http_stats


def _read(path: str):
    """read_pcap, telling the analyst on stderr if the capture is damaged."""
    status: dict = {}
    packets = read_pcap(path, status=status)
    _warn(read_warnings(status, len(packets)))
    return packets


def _warn(warnings: list[str]) -> None:
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)


def cmd_overview(args) -> int:
    packets = _read(args.pcap)
    summary = capture_summary(packets)
    hosts = build_hosts(packets)
    resolved = resolved_addresses(packets)

    print(f"{args.pcap}")
    print(f"  {summary['packet_count']} packets, {summary['total_bytes']:,} bytes, "
          f"{summary['duration_seconds']}s")
    print(f"\nProtocol hierarchy:")
    for proto, count in summary["protocol_hierarchy"].items():
        pct = 100 * count / summary["packet_count"] if summary["packet_count"] else 0
        print(f"  {proto:<22} {count:>7} ({pct:5.1f}%)")

    print(f"\nHosts ({len(hosts)}):")
    top_hosts = sorted(hosts.values(), key=lambda h: h.bytes_sent + h.bytes_recv, reverse=True)
    for h in top_hosts[:15]:
        total = h.bytes_sent + h.bytes_recv
        names = ", ".join(sorted(h.hostnames)) or "-"
        os_g = h.os_guess or "?"
        print(f"  {h.ip:<16} {total:>10,}B  os={os_g:<40} names={names}")

    if resolved:
        print(f"\nResolved addresses ({len(resolved)}):")
        for ip, names in list(resolved.items())[:15]:
            print(f"  {ip:<16} {', '.join(sorted(names))}")
    return 0


def cmd_hosts(args) -> int:
    packets = _read(args.pcap)
    hosts = build_hosts(packets)
    for h in sorted(hosts.values(), key=lambda h: h.ip):
        print(f"\n{h.ip}")
        print(f"  MACs:       {', '.join(sorted(h.macs)) or '-'}")
        print(f"  Hostnames:  {', '.join(sorted(h.hostnames)) or '-'}")
        print(f"  OS guess:   {h.os_guess or '-'} (confidence: {h.os_confidence})")
        print(f"  Open ports: {', '.join(str(p) for p in sorted(h.open_ports)) or '-'}")
        print(f"  Sent:       {h.packets_sent} packets, {h.bytes_sent:,} bytes")
        print(f"  Received:   {h.packets_recv} packets, {h.bytes_recv:,} bytes")
    return 0


def cmd_filter(args) -> int:
    packets = _read(args.pcap)
    try:
        matched = apply_filter(args.expr, packets)
    except FilterSyntaxError as e:
        print(f"Filter error: {e}", file=sys.stderr)
        return 2
    print(f"{len(matched)}/{len(packets)} packets matched `{args.expr}`\n")
    for p in matched[:args.limit]:
        addr = f"{p.src_ip or p.src_mac or '?'} -> {p.dst_ip or p.dst_mac or '?'}"
        print(f"[{p.frame_number:>6}] t={p.ts:.6f} {addr:<38} {p.summary}")
    if len(matched) > args.limit:
        print(f"... and {len(matched) - args.limit} more (use --limit to see more)")
    return 0


def cmd_analyze(args) -> int:
    cfg = Config.from_json(Path(args.config).read_text()) if args.config else Config()
    result = run_analyze(args.pcap, cfg)
    _warn(result.warnings)

    floor = SEVERITY_ORDER.get(args.min_severity, 0)
    result.findings = [f for f in result.findings if f.severity_rank >= floor]

    if args.format == "json":
        out = render_json(result)
    elif args.format == "html":
        out = render_html(result)
    elif args.format == "markdown":
        out = render_markdown(result)
    else:
        out = render_console(result, colour=not args.no_color, verbose=args.verbose)

    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        print(f"Wrote {args.output} -- {len(result.findings)} finding(s), "
              f"worst severity {result.worst_severity}")
    else:
        print(out)
    return 1 if result.findings and result.worst_severity in ("high", "critical") else 0


def cmd_dns(args) -> int:
    packets = _read(args.pcap)
    stats = dns_stats(packets)
    print(f"Queries: {stats.total_queries}   Responses: {stats.total_responses}   "
          f"Unique names: {stats.unique_query_names}   NXDOMAIN: {stats.nxdomain}")
    print(f"\nQuery types:")
    for qtype, count in stats.qtype_counts.items():
        print(f"  {qtype:<8} {count}")
    print(f"\nTop queried names:")
    for name, count in stats.top_queried:
        print(f"  {count:>5}  {name}")
    return 0


def cmd_http(args) -> int:
    packets = _read(args.pcap)
    stats = http_stats(packets)
    print(f"Requests: {stats.total_requests}   Responses: {stats.total_responses}")
    print(f"\nMethods:      {stats.methods}")
    print(f"Status codes: {stats.status_codes}")
    print(f"\nTop hosts:")
    for host, count in stats.top_hosts:
        print(f"  {count:>5}  {host}")
    print(f"\nUser agents:")
    for ua, count in stats.user_agents:
        print(f"  {count:>5}  {ua}")
    return 0


def cmd_creds(args) -> int:
    packets = _read(args.pcap)
    creds = extract_credentials(packets)
    if not creds:
        print("No cleartext credentials found.")
        return 0
    for c in creds:
        print(f"[frame {c.frame}] {c.protocol}  {c.src} -> {c.dst}  "
              f"user={c.username!r} secret={c.secret!r}")
    return 0


def cmd_files(args) -> int:
    packets = _read(args.pcap)
    artifacts = extract_files(packets)
    if not artifacts:
        print("No file transfers identified.")
        return 0
    for a in artifacts:
        d = a.detail
        print(f"[frame {a.frame}] {d['filename']}  ({d['content_type']})  "
              f"{d['src']} -> {d['dst']}")
    return 0


def cmd_identify(args) -> int:
    packets = _read(args.pcap)
    ids = identify_hosts_and_users(packets)
    print("DHCP hostnames:")
    for ip, names in ids["dhcp_hostnames"].items():
        print(f"  {ip:<16} {', '.join(names)}")
    print("\nNBNS hostnames:")
    for ip, names in ids["nbns_hostnames"].items():
        print(f"  {ip:<16} {', '.join(names)}")
    print(f"\nKerberos users:  {', '.join(ids['kerberos_users']) or '-'}")
    print(f"Kerberos hosts:  {', '.join(ids['kerberos_hosts']) or '-'}")
    return 0


def cmd_keywords(args) -> int:
    packets = _read(args.pcap)
    hits = search_keywords(packets, args.words)
    if not hits:
        print("No keyword hits.")
        return 0
    for a in hits:
        d = a.detail
        print(f"[frame {a.frame}] {d['keyword']!r} in {d['field']}  "
              f"{d['src']} -> {d['dst']}: {d['context']}")
    return 0


def cmd_acl(args) -> int:
    result = run_analyze(args.pcap)
    out = generate_acl(result.findings, args.target, args.min_severity)
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        print(f"Wrote {args.output}")
    else:
        print(out)
    return 0


def cmd_rules(args) -> int:
    print(f"{'RULE':<16} {'SEVERITY-CAPABLE':<10} TITLE")
    print("-" * 90)
    for det_cls in REGISTRY:
        print(f"{det_cls.id:<16} {'':<10} {det_cls.title}")
    print(f"\n{len(REGISTRY)} detectors.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="trafkit", description="Packet-native traffic analysis toolkit")
    p.add_argument("--version", action="version", version=f"trafkit {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    o = sub.add_parser("overview", help="quick triage overview of a capture")
    o.add_argument("pcap")
    o.set_defaults(func=cmd_overview)

    h = sub.add_parser("hosts", help="host inventory")
    h.add_argument("pcap")
    h.set_defaults(func=cmd_hosts)

    flt = sub.add_parser("filter", help="apply a Wireshark-style display filter")
    flt.add_argument("pcap")
    flt.add_argument("expr")
    flt.add_argument("--limit", type=int, default=50)
    flt.set_defaults(func=cmd_filter)

    a = sub.add_parser("analyze", help="run every detector and report")
    a.add_argument("pcap")
    a.add_argument("-f", "--format", choices=["console", "json", "markdown", "html"], default="console")
    a.add_argument("-o", "--output")
    a.add_argument("-v", "--verbose", action="store_true")
    a.add_argument("--min-severity", default="info", choices=list(SEVERITY_ORDER))
    a.add_argument("--no-color", action="store_true")
    a.add_argument("--config", help="path to a JSON Config override")
    a.set_defaults(func=cmd_analyze)

    d = sub.add_parser("dns", help="DNS statistics")
    d.add_argument("pcap")
    d.set_defaults(func=cmd_dns)

    ht = sub.add_parser("http", help="HTTP statistics")
    ht.add_argument("pcap")
    ht.set_defaults(func=cmd_http)

    cr = sub.add_parser("creds", help="extract cleartext credentials")
    cr.add_argument("pcap")
    cr.set_defaults(func=cmd_creds)

    fi = sub.add_parser("files", help="extracted file metadata")
    fi.add_argument("pcap")
    fi.set_defaults(func=cmd_files)

    idf = sub.add_parser("identify", help="DHCP/NBNS/Kerberos host & user identification")
    idf.add_argument("pcap")
    idf.set_defaults(func=cmd_identify)

    kw = sub.add_parser("keywords", help="keyword search across text fields")
    kw.add_argument("pcap")
    kw.add_argument("words", nargs="+")
    kw.set_defaults(func=cmd_keywords)

    acl = sub.add_parser("acl", help="generate firewall ACL rules from findings")
    acl.add_argument("pcap")
    acl.add_argument("--target", choices=SUPPORTED_TARGETS, default="iptables")
    acl.add_argument("--min-severity", default="medium", choices=list(SEVERITY_ORDER))
    acl.add_argument("-o", "--output")
    acl.set_defaults(func=cmd_acl)

    r = sub.add_parser("rules", help="list detection rules")
    r.set_defaults(func=cmd_rules)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
