"""
Headless triage: the workbench's engine without the window.

    python -m socworkbench.batch EVIDENCE [EVIDENCE ...] [-o OUTDIR]

Recognises every file by its content (emails, Windows event logs, network
logs, packet captures; folders and .zip archives are expanded), runs the
matching toolkit and prints one line per case. With -o it also writes each
case's exports (HTML report, JSON, indicators, blocklist and the kit's own
formats), a combined blocklist and a machine-readable summary.json.

The exit code lets a pipeline act on the result:

    0  everything was analysed and nothing reached --fail-on (default: high)
    1  at least one case reached --fail-on
    2  incomplete: some evidence could not be analysed, or none was recognised
       (and nothing reached --fail-on) -- unreadable evidence never passes as clean
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from socworkbench import __version__  # noqa: E402
from socworkbench.engine import analyze_batch  # noqa: E402
from socworkbench.export import EXPORTS, blocklist, render  # noqa: E402

LEVEL_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "clean": 0, "info": 0}
FAIL_ON = ("critical", "high", "medium", "low", "never")
EXIT_OK, EXIT_FINDINGS, EXIT_INCOMPLETE = 0, 1, 2


def _slug(text: str, limit: int = 48) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("._")[:limit] or "case"


def case_row(case: dict) -> dict:
    """The part of a case a summary needs (no findings, no raw evidence)."""
    verdict = case.get("verdict", {})
    return {
        "kit": case["kit"], "kind": case.get("kit_label", ""), "title": case["title"],
        "sources": [s["name"] for s in case.get("sources", [])], "status": case.get("status", "ok"),
        "verdict": verdict.get("label", ""), "level": verdict.get("level", "info"),
        "score": verdict.get("score"), "summary": verdict.get("summary", ""),
        "counts": case.get("counts", {}), "findings": len(case.get("findings", [])),
        "indicators": len(case.get("iocs", [])),
        "blockable_indicators": sum(1 for i in case.get("iocs", []) if i.get("block")),
        "notes": list(case.get("notes", [])),
    }


def exit_code(cases: list[dict], fail_on: str) -> int:
    ok = [c for c in cases if c.get("status") != "error"]
    if fail_on != "never":
        threshold = LEVEL_RANK[fail_on]
        if any(LEVEL_RANK.get(c.get("verdict", {}).get("level", "info"), 0) >= threshold for c in ok):
            return EXIT_FINDINGS
    if not ok or len(ok) != len(cases):
        return EXIT_INCOMPLETE
    return EXIT_OK


def write_reports(out_dir: str, result: dict, formats: set[str] | None, code: int) -> dict:
    """Write every case's exports under out_dir; returns the summary dict."""
    os.makedirs(out_dir, exist_ok=True)
    rows = []
    for n, case in enumerate(result["cases"], start=1):
        row = case_row(case)
        first = case["sources"][0]["name"] if case.get("sources") else case["title"]
        folder = f"{n:03d}_{case['kit']}_{_slug(re.split(r'[\\/]', first)[-1])}"
        os.makedirs(os.path.join(out_dir, folder), exist_ok=True)
        written = []
        for fmt in case.get("exports", []):
            if formats is not None and fmt not in formats:
                continue
            body, _ctype = render(case, fmt)
            name = EXPORTS[fmt][2]
            with open(os.path.join(out_dir, folder, name), "wb") as fh:
                fh.write(body)
            written.append(name)
        row["folder"], row["files"] = folder, written
        rows.append(row)

    merged = {"title": f"all {len(rows)} cases", "kit_label": "Combined",
              "iocs": [i for c in result["cases"] if c.get("status") != "error" for i in c.get("iocs", [])]}
    with open(os.path.join(out_dir, "combined-blocklist.txt"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(blocklist(merged))

    summary = build_summary(result, rows, code)
    with open(os.path.join(out_dir, "summary.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(summary, fh, indent=2, ensure_ascii=False)
    return summary


def build_summary(result: dict, rows: list[dict], code: int) -> dict:
    levels = {name: 0 for name in ("critical", "high", "medium", "low", "clean", "info")}
    errors = 0
    for r in rows:
        if r["status"] == "error":
            errors += 1
        else:
            levels[r["level"] if r["level"] in levels else "info"] += 1
    worst = max((r for r in rows if r["status"] != "error"),
                key=lambda r: LEVEL_RANK.get(r["level"], 0), default=None)
    return {
        "tool": f"SOC Workbench {__version__}",
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "exit_code": code,
        "worst_level": worst["level"] if worst else None,
        "cases_by_level": levels, "errors": errors,
        "cases": rows, "skipped": result["skipped"], "notes": result["notes"],
    }


def print_table(summary: dict, out_dir: str | None, stream) -> None:
    rows = summary["cases"]
    print(f"SOC triage: {len(rows)} case(s), {len(summary['skipped'])} file(s) skipped", file=stream)
    order = sorted(rows, key=lambda r: (r["status"] == "error", -LEVEL_RANK.get(r["level"], 0)))
    for r in order:
        label = "ERROR" if r["status"] == "error" else r["verdict"]
        detail = "; ".join(r["notes"])[:90] if r["status"] == "error" else r["summary"]
        src = r["sources"][0] if len(r["sources"]) == 1 else f"{len(r['sources'])} files"
        print(f"  {label:<10} {r['kind']:<15} {src[:44]:<44} {detail}", file=stream)
    for s in summary["skipped"]:
        print(f"  skipped    {s['name'][:60]}: {s['reason']}", file=stream)
    for note in summary["notes"]:
        print(f"  note: {note}", file=stream)
    lv = summary["cases_by_level"]
    print(f"worst: {(summary['worst_level'] or 'none').upper()}   "
          f"critical {lv['critical']}, high {lv['high']}, medium {lv['medium']}, low {lv['low']}, "
          f"clean {lv['clean'] + lv['info']}, could not analyse {summary['errors']}", file=stream)
    if out_dir:
        print(f"reports: {os.path.abspath(out_dir)}", file=stream)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="socworkbench.batch", formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Headless SOC triage: analyse any mix of evidence and write a report per case.",
        epilog="exit code: 0 = analysed, nothing at --fail-on; 1 = a case reached --fail-on; "
               "2 = some evidence could not be analysed, or none was recognised")
    ap.add_argument("evidence", nargs="+", help="files, folders or .zip archives")
    ap.add_argument("-o", "--out", metavar="DIR", help="write each case's exports and summary.json here")
    ap.add_argument("--formats", default="all",
                    help="comma-separated exports to write: " + ", ".join(EXPORTS) + " (default: all)")
    ap.add_argument("--fail-on", choices=FAIL_ON, default="high",
                    help="lowest verdict level that makes the exit code 1 (default: high)")
    ap.add_argument("--json", action="store_true", help="print summary.json to stdout instead of the table")
    ap.add_argument("-q", "--quiet", action="store_true", help="print nothing; rely on the exit code and -o")
    ap.add_argument("--version", action="version", version=f"SOC Workbench {__version__}")
    args = ap.parse_args(argv)

    formats = None
    if args.formats != "all":
        formats = {f.strip() for f in args.formats.split(",") if f.strip()}
        unknown = formats - set(EXPORTS)
        if unknown:
            ap.error(f"unknown export format(s): {', '.join(sorted(unknown))}")
    missing = [p for p in args.evidence if not os.path.exists(p)]
    if missing:
        ap.error("no such file or folder: " + ", ".join(missing))

    try:                                     # evidence text is not ASCII; never die on a console codepage
        sys.stdout.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass

    with tempfile.TemporaryDirectory(prefix="socwb-batch-") as workdir:
        progress = (lambda _m: None) if (args.quiet or args.json) else \
            (lambda m: print(f"  .. {m}", file=sys.stderr, flush=True))
        result = analyze_batch([os.path.abspath(p) for p in args.evidence], workdir=workdir, progress=progress)
        code = exit_code(result["cases"], args.fail_on)
        if args.out:
            summary = write_reports(args.out, result, formats, code)
        else:
            summary = build_summary(result, [case_row(c) for c in result["cases"]], code)

    if args.json:
        json.dump(summary, sys.stdout, indent=2, ensure_ascii=False)
        print()
    elif not args.quiet:
        print_table(summary, args.out, sys.stdout)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
