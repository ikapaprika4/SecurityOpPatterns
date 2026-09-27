"""
Command line interface.

    nsm analyze  <files...>        run every detector, correlate, report
    nsm parse    <file>            normalise a log to JSONL (inspect parsing)
    nsm stats    <files...>        the sort|uniq -c triage pass
    nsm pivot    <files...>        VPN account -> assigned IP -> internal activity
    nsm rules                      list detectors and their thresholds
    nsm snort    <findings.json>   emit Snort/Suricata rules from findings
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import Config, DEFAULT_CONFIG
from .correlate import correlate, summarise, vpn_pivots
from .detectors import REGISTRY
from .models import SEVERITY_ORDER
from .parsers import read_files, read_file
from .report import render_console, render_html, render_json, render_markdown
from .snortgen import findings_to_snort


def _load_config(path: str | None) -> Config:
    # Always a fresh instance: cmd_analyze sets min_severity on it, which
    # used to be written into the shared module-level DEFAULT_CONFIG.
    return Config.from_json(path) if path else Config()


def _expand(paths: list[str]) -> list[str]:
    out: list[str] = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            for ext in ("*.log", "*.csv", "*.json", "*.txt", "*.pcap", "*.pcapng"):
                out += [str(x) for x in sorted(path.rglob(ext))]
        else:
            out.append(str(path))
    return out


def cmd_analyze(args) -> int:
    cfg = _load_config(args.config)
    cfg.min_severity = args.min_severity
    files = _expand(args.files)
    if not files:
        print("No input files found.", file=sys.stderr)
        return 2

    events = read_files(files)
    if not events:
        print("No events parsed. Try --parser to force a grammar, or check the format.",
              file=sys.stderr)
        return 2

    only = set(args.only.split(",")) if args.only else None
    findings = []
    for cls in REGISTRY:
        det = cls(cfg)
        if only and det.name not in only:
            continue
        try:
            findings.extend(det.run(events))
        except Exception as exc:                      # a broken rule must not kill the run
            print(f"[warn] detector {det.name} failed: {exc}", file=sys.stderr)

    floor = SEVERITY_ORDER.get(cfg.min_severity, 0)
    findings = [f for f in findings if f.severity_rank >= floor]

    incidents = correlate(findings, cfg)
    summary = summarise(events, cfg)
    pivots = vpn_pivots(events, cfg)

    if args.format == "json":
        out = render_json(findings, incidents, summary, pivots)
    elif args.format == "markdown":
        out = render_markdown(findings, incidents, summary)
    elif args.format == "html":
        out = render_html(findings, incidents, summary, pivots)
    else:
        header = (f"Parsed {len(events):,} events from {len(files)} file(s)\n"
                  f"{summary['time_range']['start']} -> {summary['time_range']['end']}\n"
                  f"{'-' * 78}\n")
        out = header + render_console(findings, colour=not args.no_color, verbose=args.verbose)

    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        print(f"Wrote {args.output} ({len(findings)} findings, {len(incidents)} incidents)")
    else:
        print(out)

    critical_or_high = sum(1 for f in findings if f.severity in ("critical", "high"))
    return 1 if critical_or_high else 0


def cmd_parse(args) -> int:
    events = read_file(args.file, parser=args.parser)
    for ev in events:
        print(json.dumps(ev.to_dict(), default=str))
    print(f"# {len(events)} events", file=sys.stderr)
    return 0


def cmd_stats(args) -> int:
    cfg = _load_config(args.config)
    events = read_files(_expand(args.files))
    print(json.dumps(summarise(events, cfg), indent=2, default=str))
    return 0


def cmd_pivot(args) -> int:
    cfg = _load_config(args.config)
    events = read_files(_expand(args.files))
    print(json.dumps(vpn_pivots(events, cfg), indent=2, default=str))
    return 0


def cmd_rules(args) -> int:
    cfg = _load_config(args.config)
    print(f"{'DETECTOR':<26} {'PREFIX':<12} DESCRIPTION")
    print("-" * 100)
    for cls in REGISTRY:
        print(f"{cls.name:<26} {cls.rule_prefix:<12} {cls.description}")
    if args.show_thresholds:
        print("\nThresholds:")
        print(json.dumps(cfg.as_dict(), indent=2))
    return 0


def cmd_snort(args) -> int:
    data = json.loads(Path(args.findings).read_text(encoding="utf-8"))
    print(findings_to_snort(data.get("findings", data), start_sid=args.start_sid))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nsm", description="Network security monitoring log analysis toolkit")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="run all detectors and report")
    a.add_argument("files", nargs="+", help="log files, PCAPs, or directories")
    a.add_argument("-c", "--config", help="site config JSON")
    a.add_argument("-f", "--format", choices=["console", "json", "markdown", "html"],
                   default="console")
    a.add_argument("-o", "--output", help="write report to this path")
    a.add_argument("--only", help="comma-separated detector names to run")
    a.add_argument("--min-severity", default="info",
                   choices=["info", "low", "medium", "high", "critical"])
    a.add_argument("-v", "--verbose", action="store_true", help="include metrics and evidence")
    a.add_argument("--no-color", action="store_true")
    a.set_defaults(func=cmd_analyze)

    b = sub.add_parser("parse", help="normalise one log file to JSONL")
    b.add_argument("file")
    b.add_argument("--parser", choices=["firewall", "ids", "vpn", "json", "kv"])
    b.set_defaults(func=cmd_parse)

    c = sub.add_parser("stats", help="triage statistics (top talkers, blocks, alerts)")
    c.add_argument("files", nargs="+")
    c.add_argument("-c", "--config")
    c.set_defaults(func=cmd_stats)

    d = sub.add_parser("pivot", help="VPN account -> assigned IP -> internal activity")
    d.add_argument("files", nargs="+")
    d.add_argument("-c", "--config")
    d.set_defaults(func=cmd_pivot)

    e = sub.add_parser("rules", help="list detectors")
    e.add_argument("-c", "--config")
    e.add_argument("--show-thresholds", action="store_true")
    e.set_defaults(func=cmd_rules)

    f = sub.add_parser("snort", help="generate Snort/Suricata rules from a findings JSON")
    f.add_argument("findings")
    f.add_argument("--start-sid", type=int, default=1000001)
    f.set_defaults(func=cmd_snort)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
