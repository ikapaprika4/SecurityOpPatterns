"""
Command line interface.

    phish analyze <files|dirs>      full triage: artifacts, findings, verdict, IOCs
    phish headers <file>            header artifacts + delivery path + auth results
    phish urls <file>               every URL, defanged, with the red flags
    phish attachments <file>        hashes, flags, embedded links; --extract to save
    phish iocs <files>              IOC export (csv | json | misp | stix | blocklist)
    phish defang / refang <value>   convert an indicator for safe or live use
    phish enrich <file>             reputation lookups (needs API keys)
    phish rules                     list every detection rule
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import analyze_file, analyze_paths, __version__
from .iocs import collect_iocs, defang, refang, to_blocklist, to_csv, to_misp, to_stix_lite
from .models import SEVERITY_ORDER
from .parser import parse_email_file
from .report import render_console, render_html, render_json, render_markdown


def _expand(paths: list[str]) -> list[str]:
    out: list[str] = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            for ext in ("*.eml", "*.msg", "*.txt", "*.mbox"):
                out += [str(x) for x in sorted(path.rglob(ext))]
        else:
            out.append(str(path))
    return out


def cmd_analyze(args) -> int:
    files = _expand(args.files)
    if not files:
        print("No email files found.", file=sys.stderr)
        return 2
    results = analyze_paths(files)

    floor = SEVERITY_ORDER.get(args.min_severity, 0)
    for r in results:
        r.findings = [f for f in r.findings if f.severity_rank >= floor or f.score < 0]

    if args.format == "json":
        out = render_json(results)
    elif args.format == "html":
        out = render_html(results)
    elif args.format == "markdown":
        out = "\n\n---\n\n".join(render_markdown(r) for r in results)
    else:
        out = "\n".join(render_console(r, colour=not args.no_color, verbose=args.verbose)
                        for r in results)

    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        worst = max((r.score for r in results), default=0)
        print(f"Wrote {args.output} — {len(results)} message(s), highest score {worst}")
    else:
        print(out)

    return 1 if any(r.verdict.value in ("phishing", "malicious") for r in results) else 0


def cmd_headers(args) -> int:
    e = parse_email_file(args.file)
    print(f"From:         {e.from_addr}")
    print(f"  address:    {e.from_addr.address if e.from_addr else '—'}")
    print(f"  display:    {e.from_addr.display_name if e.from_addr else '—'}")
    print(f"  local part: {e.from_addr.local_part if e.from_addr else '—'}")
    print(f"  domain:     {e.from_addr.domain if e.from_addr else '—'}")
    print(f"Reply-To:     {e.reply_to.address if e.reply_to else '—'}")
    print(f"Return-Path:  {e.return_path.address if e.return_path else '—'}")
    print(f"To:           {', '.join(a.address for a in e.to) or '— (BCC delivery)'}")
    print(f"Cc:           {', '.join(a.address for a in e.cc) or '—'}")
    print(f"Subject:      {e.subject}")
    print(f"Date:         {e.date}")
    print(f"Message-ID:   {e.message_id}")
    print(f"Originating:  {e.originating_ip or '—'}")

    print(f"\nDelivery path ({len(e.received_chain)} hops, oldest first):")
    for hop in reversed(e.received_chain):
        delay = f"  (+{hop.delay_seconds:.0f}s)" if hop.delay_seconds else ""
        print(f"  [{hop.index}] from {hop.from_host or '?'} "
              f"[{hop.from_ip or '?'}] by {hop.by_host or '?'}"
              f"{f' with {hop.with_protocol}' if hop.with_protocol else ''}{delay}")
        if args.verbose:
            print(f"        {hop.raw[:200]}")

    a = e.auth
    print(f"\nAuthentication:")
    print(f"  SPF   {a.spf.value}  -> {a.spf_action}"
          + (f"  (domain {a.spf_domain})" if a.spf_domain else ""))
    print(f"  DKIM  {a.dkim.value}" + (f"  (d={a.dkim_domain})" if a.dkim_domain else ""))
    print(f"  DMARC {a.dmarc.value}" + (f"  (p={a.dmarc_policy})" if a.dmarc_policy else ""))
    for note in a.notes:
        print(f"  ! {note}")
    if args.all:
        print("\nAll headers:")
        for k, v in e.all_headers:
            print(f"  {k}: {' '.join(str(v).split())[:200]}")
    return 0


def cmd_urls(args) -> int:
    r = analyze_file(args.file)
    if not r.email.urls:
        print("No URLs found.")
        return 0
    for u in r.email.urls:
        print(f"\n{u.defanged}")
        print(f"  source:  {u.source}")
        if u.display_text:
            print(f"  text:    {u.display_text[:120]}")
        print(f"  domain:  {u.domain}")
        for step in u.redirect_chain:
            print(f"  wrapped: {defang(step)[:140]}")
        for n in u.notes:
            print(f"  ! {n}")
    return 0


def cmd_attachments(args) -> int:
    e = parse_email_file(args.file)
    if not e.attachments:
        print("No attachments.")
        return 0
    for a in e.attachments:
        print(f"\n{a.filename}")
        print(f"  content-type: {a.content_type}")
        print(f"  encoding:     {a.transfer_encoding}")
        print(f"  size:         {a.size} bytes")
        print(f"  md5:          {a.md5}")
        print(f"  sha1:         {a.sha1}")
        print(f"  sha256:       {a.sha256}")
        flags = [n for n, v in (("dangerous", a.is_dangerous),
                                ("double-extension", a.has_double_extension),
                                ("macro-capable", a.macro_capable)) if v]
        print(f"  flags:        {', '.join(flags) or '—'}")
        for n in a.notes:
            print(f"  ! {n}")
        for u in a.embedded_urls:
            print(f"  link: {defang(u)}")
        if args.extract:
            os.makedirs(args.extract, exist_ok=True)
            # Neutralise the extension so an extracted sample cannot be run by accident.
            safe = os.path.basename(a.filename).replace("/", "_") + ".bin"
            dest = os.path.join(args.extract, f"{a.sha256[:12]}_{safe}")
            with open(dest, "wb") as fh:
                fh.write(a.data)
            os.chmod(dest, 0o600)
            print(f"  saved -> {dest}  (renamed .bin so it cannot execute)")
    return 0


def cmd_iocs(args) -> int:
    results = analyze_paths(_expand(args.files))
    # Only export indicators from messages that were actually judged bad.
    # Merging a benign message's artifacts into a blocklist is how a SOC ends
    # up blocking github.com. --all overrides for corpus-wide extraction.
    if not args.all:
        kept = [r for r in results if r.verdict.value != "benign"]
        skipped = len(results) - len(kept)
        if skipped:
            print(f"# skipped {skipped} message(s) with a benign verdict "
                  f"(use --all to include them)", file=sys.stderr)
        results = kept
    merged: dict[str, list[str]] = {}
    for r in results:
        for kind, values in collect_iocs(r).items():
            merged.setdefault(kind, [])
            for v in values:
                if v not in merged[kind]:
                    merged[kind].append(v)
    for k in merged:
        merged[k].sort()

    fmt = args.format
    if fmt == "json":
        out = json.dumps(merged, indent=2)
    elif fmt == "csv":
        out = to_csv(merged)
    elif fmt == "misp":
        out = to_misp(merged)
    elif fmt == "stix":
        out = to_stix_lite(merged)
    elif fmt == "blocklist":
        out = to_blocklist(merged)
    else:
        lines = []
        for kind, values in merged.items():
            lines.append(f"\n[{kind}]")
            lines += [f"  {v}" for v in values]
        out = "\n".join(lines)

    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        print(f"Wrote {args.output}")
    else:
        print(out)
    return 0


def cmd_defang(args) -> int:
    for v in args.values:
        print(defang(v))
    return 0


def cmd_refang(args) -> int:
    for v in args.values:
        print(refang(v))
    return 0


def cmd_enrich(args) -> int:
    from .enrich import enrich_result
    r = analyze_file(args.file)
    data = enrich_result(r, submit_urls=args.submit_urls)
    print(json.dumps({"verdict": r.verdict.value, "score": r.score,
                      "enrichment": data}, indent=2, default=str))
    return 0


def cmd_rules(args) -> int:
    from . import detectors as D
    from .models import ParsedEmail
    print(f"{'RULE':<14} {'CATEGORY':<12} DESCRIPTION")
    print("-" * 100)
    import inspect
    import re
    seen: set[str] = set()
    for fn in D.ALL_CHECKS:
        src = inspect.getsource(fn)
        for m in re.finditer(r'"(PH-[A-Z]+-\d+)",\s*\n?\s*(?:f?")([^"]{4,90})', src):
            rid, title = m.group(1), m.group(2)
            if rid in seen:
                continue
            seen.add(rid)
            cat = rid.split("-")[1].lower()
            print(f"{rid:<14} {cat:<12} {title}")
    print(f"\n{len(seen)} rules. Verdict thresholds: "
          + ", ".join(f"{v.value}>={s}" for s, v in D.VERDICT_THRESHOLDS))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="phish",
                                description="Email / phishing analysis toolkit")
    p.add_argument("--version", action="version", version=f"phishkit {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="full triage of one or more emails")
    a.add_argument("files", nargs="+")
    a.add_argument("-f", "--format", choices=["console", "json", "markdown", "html"],
                   default="console")
    a.add_argument("-o", "--output")
    a.add_argument("-v", "--verbose", action="store_true")
    a.add_argument("--min-severity", default="info",
                   choices=["info", "low", "medium", "high", "critical"])
    a.add_argument("--no-color", action="store_true")
    a.set_defaults(func=cmd_analyze)

    h = sub.add_parser("headers", help="header artifacts, delivery path, auth results")
    h.add_argument("file")
    h.add_argument("-v", "--verbose", action="store_true")
    h.add_argument("--all", action="store_true", help="dump every header")
    h.set_defaults(func=cmd_headers)

    u = sub.add_parser("urls", help="extract and analyse every URL")
    u.add_argument("file")
    u.set_defaults(func=cmd_urls)

    at = sub.add_parser("attachments", help="hashes, flags and embedded links")
    at.add_argument("file")
    at.add_argument("--extract", metavar="DIR",
                    help="save attachments to DIR (renamed .bin, mode 0600)")
    at.set_defaults(func=cmd_attachments)

    i = sub.add_parser("iocs", help="export indicators")
    i.add_argument("files", nargs="+")
    i.add_argument("-f", "--format",
                   choices=["text", "json", "csv", "misp", "stix", "blocklist"],
                   default="text")
    i.add_argument("-o", "--output")
    i.add_argument("--all", action="store_true",
                   help="include indicators from messages judged benign")
    i.set_defaults(func=cmd_iocs)

    d = sub.add_parser("defang", help="make indicators unclickable")
    d.add_argument("values", nargs="+")
    d.set_defaults(func=cmd_defang)

    rf = sub.add_parser("refang", help="restore defanged indicators")
    rf.add_argument("values", nargs="+")
    rf.set_defaults(func=cmd_refang)

    en = sub.add_parser("enrich", help="reputation lookups (requires API keys)")
    en.add_argument("file")
    en.add_argument("--submit-urls", action="store_true",
                    help="actively scan URLs on urlscan.io (may alert the operator)")
    en.set_defaults(func=cmd_enrich)

    r = sub.add_parser("rules", help="list detection rules")
    r.set_defaults(func=cmd_rules)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
