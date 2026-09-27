"""Rendering: console, JSON, Markdown, and a self-contained HTML case file."""

from __future__ import annotations

import html as html_mod
import json
from typing import Any, Optional, Sequence

from .models import AnalysisResult, Finding

SEV_COLOR = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[1;33m",
             "low": "\033[0;36m", "info": "\033[0;37m"}
VERDICT_COLOR = {"malicious": "\033[1;97;41m", "phishing": "\033[1;31m",
                 "suspicious": "\033[1;33m", "spam": "\033[0;36m", "benign": "\033[0;32m"}
RESET = "\033[0m"

SEV_HEX = {"critical": "#b3261e", "high": "#d93025", "medium": "#e8a33d",
           "low": "#3a8ac4", "info": "#8a8f98"}
VERDICT_HEX = {"malicious": "#8b1a14", "phishing": "#b3261e", "suspicious": "#e8a33d",
               "spam": "#3a8ac4", "benign": "#2e7d4f"}


# --------------------------------------------------------------------------
# Console
# --------------------------------------------------------------------------

def render_console(result: AnalysisResult, colour: bool = True, verbose: bool = False) -> str:
    e = result.email
    L: list[str] = []

    def c(text: str, code: str) -> str:
        return f"{code}{text}{RESET}" if colour else text

    v = result.verdict.value
    L.append("=" * 78)
    L.append(f" VERDICT: {c(f' {v.upper()} ', VERDICT_COLOR.get(v, ''))}   "
             f"score={result.score}   "
             f"types={', '.join(t.value for t in result.phish_types) or '-'}")
    L.append("=" * 78)

    L.append("\n-- HEADER ARTIFACTS " + "-" * 58)
    rows = [
        ("From", str(e.from_addr) if e.from_addr else "(none)"),
        ("Reply-To", e.reply_to.address if e.reply_to else "(none)"),
        ("Return-Path", e.return_path.address if e.return_path else "(none)"),
        ("To", ", ".join(a.address for a in e.to) or "(none — BCC delivery)"),
        ("Cc", ", ".join(a.address for a in e.cc) or "-"),
        ("Subject", e.subject or "(none)"),
        ("Date", e.date.isoformat() if e.date else "(none)"),
        ("Message-ID", e.message_id or "(none)"),
        ("Originating IP", e.originating_ip or "(unknown)"),
        ("Hops", str(len(e.received_chain))),
    ]
    for k, val in rows:
        L.append(f"  {k:<16} {val}")

    a = e.auth
    L.append("\n-- AUTHENTICATION " + "-" * 60)
    L.append(f"  SPF   {a.spf.value:<10} -> action: {a.spf_action}"
             + (f"   (domain: {a.spf_domain})" if a.spf_domain else ""))
    L.append(f"  DKIM  {a.dkim.value:<10}"
             + (f"   (d={a.dkim_domain})" if a.dkim_domain else ""))
    L.append(f"  DMARC {a.dmarc.value:<10}"
             + (f"   (policy: p={a.dmarc_policy})" if a.dmarc_policy else ""))

    if e.urls:
        L.append(f"\n-- URLS ({len(e.urls)}) " + "-" * 62)
        for u in e.urls[:25]:
            tags = []
            if u.is_shortener:
                tags.append("SHORTENER")
            if u.is_tracking_pixel:
                tags.append("PIXEL")
            if u.is_ip_literal:
                tags.append("IP-LITERAL")
            if u.lookalike_of:
                tags.append(f"LOOKALIKE:{u.lookalike_of}")
            tag = f"  [{' '.join(tags)}]" if tags else ""
            L.append(f"  {u.defanged[:110]}{tag}")
            if verbose and u.display_text:
                L.append(f"      text: {u.display_text[:90]}")
            if verbose:
                for n in u.notes:
                    L.append(f"      - {n}")

    if e.attachments:
        L.append(f"\n-- ATTACHMENTS ({len(e.attachments)}) " + "-" * 53)
        for att in e.attachments:
            flags = []
            if att.is_dangerous:
                flags.append("DANGEROUS")
            if att.has_double_extension:
                flags.append("DOUBLE-EXT")
            if att.macro_capable:
                flags.append("MACRO-CAPABLE")
            L.append(f"  {att.filename}  ({att.content_type}, {att.size} bytes)"
                     + (f"  [{' '.join(flags)}]" if flags else ""))
            L.append(f"      sha256: {att.sha256}")
            if verbose:
                L.append(f"      md5:    {att.md5}")
                for u in att.embedded_urls[:5]:
                    from .iocs import defang
                    L.append(f"      link:   {defang(u)[:100]}")

    L.append(f"\n-- FINDINGS ({len(result.findings)}) " + "-" * 58)
    ordered = sorted(result.findings, key=lambda f: (-f.severity_rank, -f.score))
    for f in ordered:
        tag = f"[{f.severity.upper():^8}]"
        L.append(f"{c(tag, SEV_COLOR.get(f.severity, ''))} {f.rule_id}  {f.title}  "
                 f"(+{f.score})")
        L.append(f"           {f.description}")
        if verbose:
            if f.mitre:
                L.append(f"           ATT&CK: {', '.join(f.mitre)}")
            for ev in f.evidence[:4]:
                L.append(f"             | {ev[:150]}")
            if f.recommendation:
                L.append(f"           action: {f.recommendation}")
        L.append("")

    if result.iocs:
        L.append("-- IOCs (defanged) " + "-" * 59)
        for kind, values in result.iocs.items():
            L.append(f"  {kind}:")
            for val in values[:12]:
                L.append(f"    {val}")
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------
# JSON / Markdown
# --------------------------------------------------------------------------

def render_json(results: Sequence[AnalysisResult],
                enrichment: Optional[dict] = None) -> str:
    payload: dict[str, Any] = {
        "analysed": len(results),
        "results": [r.to_dict() for r in results],
    }
    if enrichment:
        payload["enrichment"] = enrichment
    return json.dumps(payload, indent=2, default=str)


def render_markdown(result: AnalysisResult) -> str:
    e = result.email
    a = e.auth
    L = [f"# Phishing analysis — {e.subject or '(no subject)'}", "",
         f"**Verdict:** `{result.verdict.value}` · **Score:** {result.score} · "
         f"**Type:** {', '.join(t.value for t in result.phish_types) or '—'}", "",
         "## Header artifacts", "",
         "| Field | Value |", "|---|---|",
         f"| From | `{e.from_addr}` |" if e.from_addr else "| From | — |",
         f"| Reply-To | `{e.reply_to.address if e.reply_to else '—'}` |",
         f"| Return-Path | `{e.return_path.address if e.return_path else '—'}` |",
         f"| To | `{', '.join(x.address for x in e.to) or '— (BCC)'}` |",
         f"| Subject | {e.subject} |",
         f"| Date | {e.date.isoformat() if e.date else '—'} |",
         f"| Originating IP | `{e.originating_ip or '—'}` |",
         f"| Message-ID | `{e.message_id or '—'}` |", "",
         "## Authentication", "",
         "| Mechanism | Result | Notes |", "|---|---|---|",
         f"| SPF | `{a.spf.value}` | prescribed action: {a.spf_action}"
         + (f"; domain {a.spf_domain}" if a.spf_domain else "") + " |",
         f"| DKIM | `{a.dkim.value}` | " + (f"d={a.dkim_domain}" if a.dkim_domain else "—") + " |",
         f"| DMARC | `{a.dmarc.value}` | "
         + (f"policy p={a.dmarc_policy}" if a.dmarc_policy else "—") + " |", ""]

    if e.urls:
        L += ["## URLs", "", "| URL (defanged) | Source | Flags |", "|---|---|---|"]
        for u in e.urls[:30]:
            flags = []
            if u.is_shortener:
                flags.append("shortener")
            if u.is_tracking_pixel:
                flags.append("tracking pixel")
            if u.is_ip_literal:
                flags.append("IP literal")
            if u.lookalike_of:
                flags.append(f"lookalike of {u.lookalike_of}")
            L.append(f"| `{u.defanged}` | {u.source} | {', '.join(flags) or '—'} |")
        L.append("")

    if e.attachments:
        L += ["## Attachments", "", "| Filename | Type | Size | SHA256 | Flags |",
              "|---|---|---|---|---|"]
        for att in e.attachments:
            flags = []
            if att.is_dangerous:
                flags.append("dangerous")
            if att.has_double_extension:
                flags.append("double extension")
            if att.macro_capable:
                flags.append("macro-capable")
            L.append(f"| `{att.filename}` | {att.content_type} | {att.size} | "
                     f"`{att.sha256[:32]}…` | {', '.join(flags) or '—'} |")
        L.append("")

    L += ["## Findings", ""]
    for f in sorted(result.findings, key=lambda f: (-f.severity_rank, -f.score)):
        L += [f"### {f.rule_id} — {f.title}",
              f"*Severity:* **{f.severity}** · *Confidence:* {f.confidence} · "
              f"*Score:* +{f.score} · *ATT&CK:* {', '.join(f.mitre) or '—'}", "",
              f.description, ""]
        if f.evidence:
            L += ["```"] + [ev[:200] for ev in f.evidence[:5]] + ["```", ""]
        if f.recommendation:
            L += [f"**Action:** {f.recommendation}", ""]

    if result.iocs:
        L += ["## Indicators of compromise", "",
              "All values defanged. Refang before feeding them to a tool.", ""]
        for kind, values in result.iocs.items():
            L += [f"**{kind}**", "", "```"] + values[:25] + ["```", ""]
    return "\n".join(L)


# --------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------

_HEAD = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Phishing Analysis</title>
<style>
:root{--bg:#fbfbfa;--fg:#1d1c1a;--muted:#6b6862;--card:#fff;--line:#e5e2dc;--code:#f2f0ec;}
@media(prefers-color-scheme:dark){:root{--bg:#191817;--fg:#e9e7e3;--muted:#9a958c;
--card:#232120;--line:#332f2d;--code:#1f1d1c;}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);padding:2rem 1.25rem;
font:14px/1.55 ui-sans-serif,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1000px;margin:0 auto}
h1{font-size:1.5rem;margin:0 0 .35rem}
h2{font-size:1.05rem;margin:2rem 0 .7rem;border-bottom:1px solid var(--line);padding-bottom:.4rem}
.verdict{display:inline-block;padding:.35rem .9rem;border-radius:6px;color:#fff;
font-weight:700;letter-spacing:.06em;text-transform:uppercase;font-size:.85rem}
.sub{color:var(--muted);margin:.6rem 0 1.4rem}
table{border-collapse:collapse;width:100%;font-size:.85rem;margin:.4rem 0}
td,th{border-bottom:1px solid var(--line);padding:.4rem .55rem;text-align:left;
vertical-align:top;word-break:break-word}
th{color:var(--muted);font-weight:600;white-space:nowrap}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
code{background:var(--code);padding:.1rem .3rem;border-radius:3px;font-size:.82em}
pre{background:var(--code);padding:.6rem .75rem;border-radius:6px;overflow-x:auto;
font-size:.76rem;margin:.5rem 0;white-space:pre-wrap;word-break:break-all}
.f{background:var(--card);border:1px solid var(--line);border-left-width:4px;
border-radius:8px;padding:.85rem 1.05rem;margin-bottom:.65rem}
.f h3{margin:0 0 .3rem;font-size:.95rem}
.meta{color:var(--muted);font-size:.76rem;margin-bottom:.45rem;display:flex;gap:.85rem;flex-wrap:wrap}
.badge{display:inline-block;padding:.1rem .45rem;border-radius:4px;color:#fff;
font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em}
.rec{font-size:.84rem;border-left:2px solid var(--line);padding-left:.7rem;color:var(--muted);margin-top:.5rem}
.tiles{display:flex;gap:.6rem;flex-wrap:wrap;margin:1rem 0 1.4rem}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:.6rem .9rem;min-width:96px}
.tile .n{font-size:1.4rem;font-weight:650;line-height:1.1}
.tile .l{color:var(--muted);font-size:.7rem;text-transform:uppercase;letter-spacing:.05em}
.scroll{overflow-x:auto}
.flag{color:#b3261e;font-weight:600}
</style></head><body><div class="wrap">
"""


def render_html(results: Sequence[AnalysisResult]) -> str:
    esc = html_mod.escape
    P = [_HEAD]
    multi = len(results) > 1
    if multi:
        P.append("<h1>Phishing Analysis Report</h1>")
        P.append(f'<div class="sub">{len(results)} message(s) analysed</div>')
        P.append('<div class="scroll"><table><tr><th>File</th><th>Verdict</th><th>Score</th>'
                 '<th>From</th><th>Subject</th></tr>')
        for r in results:
            vh = VERDICT_HEX.get(r.verdict.value, "#888")
            frm = r.email.from_addr.address if r.email.from_addr else "—"
            P.append(f'<tr><td><code>{esc(r.email.source_path.split("/")[-1])}</code></td>'
                     f'<td><span class="badge" style="background:{vh}">'
                     f'{esc(r.verdict.value)}</span></td><td>{r.score}</td>'
                     f'<td><code>{esc(frm)}</code></td><td>{esc(r.email.subject[:70])}</td></tr>')
        P.append("</table></div>")

    for r in results:
        e, a = r.email, r.email.auth
        vh = VERDICT_HEX.get(r.verdict.value, "#888")
        P.append(f'<h2>{esc(e.subject or "(no subject)")}</h2>')
        P.append(f'<div><span class="verdict" style="background:{vh}">{esc(r.verdict.value)}'
                 f'</span> <span class="sub">score {r.score} · '
                 f'{esc(", ".join(t.value for t in r.phish_types) or "—")}</span></div>')

        counts: dict[str, int] = {}
        for f in r.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        P.append('<div class="tiles">')
        for sev in ("critical", "high", "medium", "low", "info"):
            P.append(f'<div class="tile"><div class="n" style="color:{SEV_HEX[sev]}">'
                     f'{counts.get(sev, 0)}</div><div class="l">{sev}</div></div>')
        P.append(f'<div class="tile"><div class="n">{len(e.urls)}</div><div class="l">urls</div></div>')
        P.append(f'<div class="tile"><div class="n">{len(e.attachments)}</div>'
                 f'<div class="l">attachments</div></div>')
        P.append("</div>")

        P.append("<h2>Header artifacts</h2><div class='scroll'><table>")
        for k, val in (("From", str(e.from_addr) if e.from_addr else "—"),
                       ("Reply-To", e.reply_to.address if e.reply_to else "—"),
                       ("Return-Path", e.return_path.address if e.return_path else "—"),
                       ("To", ", ".join(x.address for x in e.to) or "— (BCC delivery)"),
                       ("Cc", ", ".join(x.address for x in e.cc) or "—"),
                       ("Date", e.date.isoformat() if e.date else "—"),
                       ("Originating IP", e.originating_ip or "—"),
                       ("Message-ID", e.message_id or "—"),
                       ("Delivery hops", str(len(e.received_chain)))):
            P.append(f"<tr><th>{esc(k)}</th><td><code>{esc(str(val))}</code></td></tr>")
        P.append("</table></div>")

        P.append("<h2>Authentication</h2><div class='scroll'><table>"
                 "<tr><th>Mechanism</th><th>Result</th><th>Detail</th></tr>")
        bad = {"fail", "softfail", "permerror", "temperror"}
        for name, res, detail in (
                ("SPF", a.spf.value, f"prescribed action: {a.spf_action}"
                 + (f" · domain {a.spf_domain}" if a.spf_domain else "")),
                ("DKIM", a.dkim.value, f"d={a.dkim_domain}" if a.dkim_domain else "—"),
                ("DMARC", a.dmarc.value,
                 f"policy p={a.dmarc_policy}" if a.dmarc_policy else "—")):
            cls = ' class="flag"' if res in bad else ""
            P.append(f"<tr><th>{name}</th><td{cls}><code>{esc(res)}</code></td>"
                     f"<td>{esc(detail)}</td></tr>")
        P.append("</table></div>")

        if e.urls:
            P.append("<h2>URLs</h2><div class='scroll'><table>"
                     "<tr><th>URL (defanged)</th><th>Source</th><th>Flags</th></tr>")
            for u in e.urls[:40]:
                flags = []
                if u.is_shortener:
                    flags.append("shortener")
                if u.is_tracking_pixel:
                    flags.append("tracking pixel")
                if u.is_ip_literal:
                    flags.append("IP literal")
                if u.lookalike_of:
                    flags.append(f"lookalike of {u.lookalike_of}")
                fl = f'<span class="flag">{esc(", ".join(flags))}</span>' if flags else "—"
                P.append(f"<tr><td><code>{esc(u.defanged)}</code></td>"
                         f"<td>{esc(u.source)}</td><td>{fl}</td></tr>")
            P.append("</table></div>")

        if e.attachments:
            P.append("<h2>Attachments</h2><div class='scroll'><table>"
                     "<tr><th>Filename</th><th>Type</th><th>Size</th><th>SHA256</th>"
                     "<th>Flags</th></tr>")
            for att in e.attachments:
                flags = []
                if att.is_dangerous:
                    flags.append("dangerous")
                if att.has_double_extension:
                    flags.append("double extension")
                if att.macro_capable:
                    flags.append("macro-capable")
                fl = f'<span class="flag">{esc(", ".join(flags))}</span>' if flags else "—"
                P.append(f"<tr><td><code>{esc(att.filename)}</code></td>"
                         f"<td>{esc(att.content_type)}</td><td>{att.size}</td>"
                         f"<td><code>{esc(att.sha256[:24])}…</code></td><td>{fl}</td></tr>")
            P.append("</table></div>")

        P.append("<h2>Findings</h2>")
        for f in sorted(r.findings, key=lambda f: (-f.severity_rank, -f.score)):
            colour = SEV_HEX.get(f.severity, "#888")
            P.append(f'<div class="f" style="border-left-color:{colour}">')
            P.append(f'<h3>{esc(f.rule_id)} — {esc(f.title)}</h3>')
            P.append(f'<div class="meta"><span class="badge" style="background:{colour}">'
                     f'{esc(f.severity)}</span><span>confidence: {esc(f.confidence)}</span>'
                     f'<span>score +{f.score}</span>'
                     f'<span>ATT&amp;CK: {esc(", ".join(f.mitre) or "—")}</span></div>')
            P.append(f"<div>{esc(f.description)}</div>")
            if f.evidence:
                P.append(f"<pre>{esc(chr(10).join(f.evidence[:5]))}</pre>")
            if f.recommendation:
                P.append(f'<div class="rec">{esc(f.recommendation)}</div>')
            P.append("</div>")

        if r.iocs:
            P.append("<h2>Indicators of compromise</h2>"
                     "<p class='sub'>Defanged. Refang before submitting to a tool.</p>")
            for kind, values in r.iocs.items():
                P.append(f"<strong>{esc(kind)}</strong>"
                         f"<pre>{esc(chr(10).join(values[:25]))}</pre>")

    P.append("</div></body></html>")
    return "\n".join(P)
