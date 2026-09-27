"""Output rendering: console table, JSON, Markdown, and a self-contained HTML report."""

from __future__ import annotations

import html
import json
from typing import Any, Sequence

from .correlate import Incident
from .models import Finding

SEV_COLOR = {
    "critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[1;33m",
    "low": "\033[0;36m", "info": "\033[0;37m",
}
RESET = "\033[0m"

SEV_HEX = {
    "critical": "#b3261e", "high": "#d93025", "medium": "#e8a33d",
    "low": "#3a8ac4", "info": "#8a8f98",
}


# --------------------------------------------------------------------------
# Console
# --------------------------------------------------------------------------

def render_console(findings: Sequence[Finding], colour: bool = True, verbose: bool = False) -> str:
    if not findings:
        return "No findings.\n"
    ordered = sorted(findings, key=lambda f: (-f.severity_rank, f.rule_id))
    out: list[str] = []
    for f in ordered:
        tag = f"[{f.severity.upper():^8}]"
        if colour:
            tag = f"{SEV_COLOR.get(f.severity, '')}{tag}{RESET}"
        out.append(f"{tag} {f.rule_id}  {f.title}")
        out.append(f"           confidence={f.confidence}  "
                   f"mitre={','.join(f.mitre) or '-'}  stage={f.kill_chain or '-'}")
        when = ""
        if f.first_seen:
            when = f.first_seen.strftime('%Y-%m-%d %H:%M:%S')
            if f.last_seen and f.last_seen != f.first_seen:
                when += f" -> {f.last_seen.strftime('%Y-%m-%d %H:%M:%S')}"
        if when:
            out.append(f"           window: {when}")
        out.append(f"           {f.description}")
        if verbose:
            if f.metrics:
                out.append(f"           metrics: {json.dumps(f.metrics, default=str)[:600]}")
            for ln in f.evidence[:5]:
                out.append(f"             | {ln[:200]}")
            if f.recommendation:
                out.append(f"           action: {f.recommendation}")
        out.append("")
    counts: dict[str, int] = {}
    for f in ordered:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    out.append("  ".join(f"{k}={v}" for k, v in
                         sorted(counts.items(), key=lambda kv: -Finding(
                             rule_id="", title="", severity=kv[0], confidence="",
                             description="").severity_rank)))
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------
# JSON / Markdown
# --------------------------------------------------------------------------

def render_json(findings: Sequence[Finding],
                incidents: Sequence[Incident] | None = None,
                summary: dict[str, Any] | None = None,
                pivots: list[dict] | None = None) -> str:
    return json.dumps({
        "summary": summary or {},
        "vpn_pivots": pivots or [],
        "incidents": [i.to_dict() for i in (incidents or [])],
        "findings": [f.to_dict() for f in
                     sorted(findings, key=lambda f: (-f.severity_rank, f.rule_id))],
    }, indent=2, default=str)


def render_markdown(findings: Sequence[Finding],
                    incidents: Sequence[Incident] | None = None,
                    summary: dict[str, Any] | None = None) -> str:
    lines = ["# Network Security Monitoring Report", ""]
    if summary:
        tr = summary.get("time_range") or {}
        lines += [
            f"**Events analysed:** {summary.get('event_count', 0):,}  ",
            f"**Window:** {tr.get('start', '?')} to {tr.get('end', '?')}  ",
            f"**Findings:** {len(findings)}", "",
        ]
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    if counts:
        lines += ["| Severity | Count |", "|---|---|"]
        for sev in ("critical", "high", "medium", "low", "info"):
            if sev in counts:
                lines.append(f"| {sev} | {counts[sev]} |")
        lines.append("")

    if incidents:
        lines += ["## Incidents", ""]
        for inc in incidents:
            if len(inc.findings) < 2:
                continue
            lines += [f"### {inc.incident_id} — {inc.title}",
                      f"*Severity:* {inc.severity} · *Stages:* {' → '.join(inc.stages)} · "
                      f"*Findings:* {len(inc.findings)}",
                      f"*Entities:* `{'`, `'.join(sorted(inc.entities)[:12])}`", ""]
            for f in inc.findings:
                lines.append(f"- **{f.rule_id}** {f.title} ({f.severity})")
            lines.append("")

    lines += ["## All findings", ""]
    for f in sorted(findings, key=lambda f: (-f.severity_rank, f.rule_id)):
        lines += [f"### {f.rule_id} — {f.title}",
                  f"*Severity:* {f.severity} · *Confidence:* {f.confidence} · "
                  f"*ATT&CK:* {', '.join(f.mitre) or '—'} · *Stage:* {f.kill_chain or '—'}", "",
                  f.description, ""]
        if f.metrics:
            lines += ["```json", json.dumps(f.metrics, indent=2, default=str)[:1500], "```", ""]
        if f.evidence:
            lines += ["**Evidence**", "```"] + f.evidence[:5] + ["```", ""]
        if f.recommendation:
            lines += [f"**Recommended action:** {f.recommendation}", ""]
    return "\n".join(lines)


# --------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------

_HTML_HEAD = """<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NSM Report</title>
<style>
:root{--bg:#fbfbfa;--fg:#1d1c1a;--muted:#6b6862;--card:#fff;--line:#e5e2dc;}
@media (prefers-color-scheme:dark){:root{--bg:#191817;--fg:#e9e7e3;--muted:#9a958c;--card:#232120;--line:#332f2d;}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.55 ui-sans-serif,-apple-system,Segoe UI,Roboto,sans-serif;padding:2rem 1.25rem;}
.wrap{max-width:1080px;margin:0 auto}
h1{font-size:1.6rem;margin:0 0 .25rem} h2{font-size:1.1rem;margin:2rem 0 .75rem;
 border-bottom:1px solid var(--line);padding-bottom:.4rem}
.sub{color:var(--muted);margin-bottom:1.5rem}
.tiles{display:flex;gap:.6rem;flex-wrap:wrap;margin-bottom:1.5rem}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:.7rem 1rem;min-width:110px}
.tile .n{font-size:1.5rem;font-weight:650;line-height:1.1}
.tile .l{color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.05em}
.f{background:var(--card);border:1px solid var(--line);border-left-width:4px;border-radius:8px;
 padding:.9rem 1.1rem;margin-bottom:.7rem}
.f h3{margin:0 0 .35rem;font-size:.98rem}
.meta{color:var(--muted);font-size:.78rem;margin-bottom:.5rem;display:flex;gap:.9rem;flex-wrap:wrap}
.badge{display:inline-block;padding:.1rem .45rem;border-radius:4px;color:#fff;font-size:.7rem;
 font-weight:650;text-transform:uppercase;letter-spacing:.04em}
pre{background:rgba(127,127,127,.09);padding:.6rem .75rem;border-radius:6px;overflow-x:auto;
 font-size:.76rem;margin:.5rem 0}
.rec{font-size:.85rem;border-left:2px solid var(--line);padding-left:.7rem;color:var(--muted)}
table{border-collapse:collapse;width:100%;font-size:.82rem} td,th{border-bottom:1px solid var(--line);
 padding:.35rem .5rem;text-align:left} th{color:var(--muted);font-weight:600}
.scroll{overflow-x:auto}
</style></head><body><div class="wrap">
"""


def render_html(findings: Sequence[Finding],
                incidents: Sequence[Incident] | None = None,
                summary: dict[str, Any] | None = None,
                pivots: list[dict] | None = None) -> str:
    e = html.escape
    parts = [_HTML_HEAD, "<h1>Network Security Monitoring Report</h1>"]

    tr = (summary or {}).get("time_range") or {}
    parts.append(f'<div class="sub">{(summary or {}).get("event_count", 0):,} events · '
                 f'{e(str(tr.get("start", "?")))} → {e(str(tr.get("end", "?")))}</div>')

    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    parts.append('<div class="tiles">')
    for sev in ("critical", "high", "medium", "low", "info"):
        parts.append(f'<div class="tile"><div class="n" style="color:{SEV_HEX[sev]}">'
                     f'{counts.get(sev, 0)}</div><div class="l">{sev}</div></div>')
    parts.append('</div>')

    if incidents:
        multi = [i for i in incidents if len(i.findings) > 1]
        if multi:
            parts.append("<h2>Correlated incidents</h2>")
            for inc in multi[:10]:
                parts.append(
                    f'<div class="f" style="border-left-color:{SEV_HEX.get(inc.severity, "#888")}">'
                    f'<h3>{e(inc.incident_id)} — {e(inc.title)}</h3>'
                    f'<div class="meta"><span class="badge" style="background:{SEV_HEX.get(inc.severity, "#888")}">'
                    f'{e(inc.severity)}</span><span>{e(" → ".join(inc.stages))}</span>'
                    f'<span>{len(inc.findings)} findings</span></div>'
                    f'<pre>{e(", ".join(sorted(inc.entities)[:20]))}</pre>'
                    "<ul>" + "".join(f"<li>{e(f.rule_id)} — {e(f.title)}</li>"
                                     for f in inc.findings) + "</ul></div>")

    if pivots:
        parts.append("<h2>VPN session pivots</h2><div class='scroll'><table>"
                     "<tr><th>User</th><th>External IP</th><th>Assigned IP</th><th>Login</th>"
                     "<th>Targets</th><th>Suspicious</th></tr>")
        for p in pivots[:25]:
            parts.append(
                f"<tr><td>{e(str(p['user']))}</td><td>{e(str(p['external_ip']))}</td>"
                f"<td>{e(str(p['assigned_ip']))}</td><td>{e(str(p['login_time']))}</td>"
                f"<td>{p['target_count']}</td><td>{'yes' if p['suspicious'] else 'no'}</td></tr>")
        parts.append("</table></div>")

    parts.append("<h2>Findings</h2>")
    for f in sorted(findings, key=lambda f: (-f.severity_rank, f.rule_id)):
        colour = SEV_HEX.get(f.severity, "#888")
        parts.append(f'<div class="f" style="border-left-color:{colour}">')
        parts.append(f'<h3>{e(f.rule_id)} — {e(f.title)}</h3>')
        window = ""
        if f.first_seen:
            window = f.first_seen.strftime("%Y-%m-%d %H:%M")
            if f.last_seen and f.last_seen != f.first_seen:
                window += " → " + f.last_seen.strftime("%Y-%m-%d %H:%M")
        parts.append(
            f'<div class="meta"><span class="badge" style="background:{colour}">{e(f.severity)}</span>'
            f'<span>confidence: {e(f.confidence)}</span>'
            f'<span>ATT&amp;CK: {e(", ".join(f.mitre) or "—")}</span>'
            f'<span>{e(f.kill_chain or "—")}</span>'
            + (f'<span>{e(window)}</span>' if window else "") + '</div>')
        parts.append(f"<div>{e(f.description)}</div>")
        if f.metrics:
            parts.append(f"<pre>{e(json.dumps(f.metrics, indent=2, default=str)[:1800])}</pre>")
        if f.evidence:
            parts.append(f"<pre>{e(chr(10).join(f.evidence[:5]))}</pre>")
        if f.recommendation:
            parts.append(f'<div class="rec">{e(f.recommendation)}</div>')
        parts.append("</div>")

    parts.append("</div></body></html>")
    return "\n".join(parts)
