"""Command-line interface: argparse subcommands, same shape as nsmkit/
trafkit/waapkit for consistency across the toolkit family."""

from __future__ import annotations

import argparse
import sys

from . import analyze_events
from .detectors import REGISTRY
from .parsers import EventParseError, event_stats, parse_event_file, parse_event_files
from .processtree import events_for_logon_id, find_logon_event
from .report import fmt_ts, render


def _load(args: argparse.Namespace):
    paths = args.path if isinstance(args.path, list) else [args.path]
    fmt = getattr(args, "format", None)
    if len(paths) == 1:
        return parse_event_file(paths[0], format_hint=fmt), paths[0]
    return parse_event_files(paths), ", ".join(paths)


def cmd_analyze(args: argparse.Namespace) -> int:
    events, label = _load(args)
    if not events:
        # Nothing was read. A report saying "0 events, no findings" would read
        # as a clean host, so this is an error (exit 2), not a result.
        raise EventParseError(f"no events found in {label}")
    result = analyze_events(events, path=label)
    print(render(result, args.format_out))
    if args.verbose:
        print(f"\n(parsed {len(result.events)} events)", file=sys.stderr)
    return 1 if result.worst_severity in ("high", "critical") else 0


def cmd_overview(args: argparse.Namespace) -> int:
    events, label = _load(args)
    if not events:
        print("No events parsed.")
        return 0
    s = event_stats(events)
    print(f"evtxkit overview: {label}")
    print(f"Events: {s['event_count']}")
    if s["first_ts"]:
        print(f"Time range: {fmt_ts(s['first_ts'])} -> {fmt_ts(s['last_ts'])}")
    if s["untimed_events"]:
        print(f"Events without timestamps: {s['untimed_events']}")
    if s["hosts"]:
        print("Hosts: " + ", ".join(f"{k}({v})" for k, v in list(s["hosts"].items())[:10]))
    print("By channel: " + ", ".join(f"{k}={v}" for k, v in sorted(s["by_channel"].items())))
    top_ids = list(s["by_event_id"].items())[:10]
    print("Top event IDs: " + ", ".join(f"{eid}({n})" for eid, n in top_ids))
    return 0


def cmd_sessions(args: argparse.Namespace) -> int:
    events, _label = _load(args)
    logon_event = find_logon_event(events, args.logon_id)
    if logon_event is not None:
        print(f"Logon {args.logon_id}: {logon_event.target_user} from {logon_event.source_ip or '(local)'} "
              f"(type {logon_event.logon_type}) at {fmt_ts(logon_event.ts)}")
    matches = events_for_logon_id(events, args.logon_id)
    print(f"{len(matches)} event(s) sharing Logon ID {args.logon_id}:")
    for e in matches:
        print(f"  [{e.event_id:5}] {e.channel:10} {fmt_ts(e.ts)}  {e.summary()}")
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    for det_cls in REGISTRY:
        print(f"{det_cls.id:30} {det_cls.tactic:22} {det_cls.title}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="evtxkit", description="Windows Security/Sysmon event log detection toolkit")
    sub = p.add_subparsers(dest="command", required=True)

    def add_common(sp, multi: bool = True):
        sp.add_argument("path", nargs="+" if multi else None,
                        help="Windows event source(s): .evtx, Event Viewer .xml, .json/.jsonl, "
                             "or ConsoleHost_history.txt. Several files from one host are "
                             "analysed together.")
        sp.add_argument("--format", choices=["jsonl", "evtx", "xml", "pshistory"], default=None,
                        help="force source format instead of auto-detecting")

    sp = sub.add_parser("analyze", help="run every detector and report findings")
    add_common(sp)
    sp.add_argument("-f", "--format-out", dest="format_out", choices=["console", "json", "markdown", "html"], default="console")
    sp.add_argument("-v", "--verbose", action="store_true")
    sp.set_defaults(func=cmd_analyze)

    sp = sub.add_parser("overview", help="quick event statistics, no detectors")
    add_common(sp)
    sp.set_defaults(func=cmd_overview)

    sp = sub.add_parser("sessions", help="show every event sharing a given Logon ID")
    add_common(sp, multi=False)
    sp.add_argument("logon_id", help="Logon ID (e.g. 0x3e7 or a decimal value, as it appears in the source)")
    sp.set_defaults(func=cmd_sessions)

    sp = sub.add_parser("rules", help="list every registered detector")
    sp.set_defaults(func=cmd_rules)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (EventParseError, OSError) as exc:
        print(f"evtxkit: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
