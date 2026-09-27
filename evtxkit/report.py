"""Report rendering: console (with a kill-chain-ordered timeline), JSON,
Markdown, HTML -- same four formats as nsmkit/trafkit/waapkit.

All times are shown in UTC (Windows records SystemTime in UTC; rendering in
the analyst's local zone made reports from two machines disagree), and
events from a source without timestamps -- PowerShell history -- are shown
as "(no timestamp)" instead of as 1970-01-01.
"""

from __future__ import annotations

import html as _html
import json
from datetime import datetime, timezone

from .models import AnalysisResult

TACTIC_ORDER = [
    "Initial Access", "Execution", "Persistence", "Defense Evasion", "Discovery",
    "Credential Access", "Collection", "Command and Control", "Unknown", "Internal",
]


def _tactic_rank(tactic: str) -> int:
    try:
        return TACTIC_ORDER.index(tactic)
    except ValueError:
        return len(TACTIC_ORDER)


def _sorted_findings(result: AnalysisResult):
    return sorted(result.findings, key=lambda f: (-f.severity_rank, _tactic_rank(f.tactic)))


def _ts_index(result: AnalysisResult) -> dict[int, float]:
    return {e.index: e.ts for e in result.events}


def _earliest_ts(result: AnalysisResult, finding, index: dict[int, float] | None = None) -> float:
    index = index if index is not None else _ts_index(result)
    tss = [index[i] for i in finding.events if index.get(i, 0) > 0]
    return min(tss) if tss else float("inf")


def _timeline(result: AnalysisResult):
    index = _ts_index(result)
    return sorted(result.findings, key=lambda f: _earliest_ts(result, f, index))


def fmt_ts(ts: float) -> str:
    if not ts or ts == float("inf"):
        return "(no timestamp)"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def render_console(result: AnalysisResult) -> str:
    lines = []
    lines.append(f"evtxkit analysis: {result.path}")
    lines.append("=" * 60)
    lines.append(f"Events: {len(result.events)}  |  Findings: {len(result.findings)}  |  Worst severity: {result.worst_severity}")
    lines.append("")

    if not result.findings:
        lines.append("No findings.")
        return "\n".join(lines)

    index = _ts_index(result)
    lines.append("Attack timeline (earliest evidence first):")
    for f in _timeline(result):
        when = fmt_ts(_earliest_ts(result, f, index))
        lines.append(f"  {when:<24} [{f.tactic:20}] [{f.severity.upper():8}] {f.rule_id:28} {f.title}")
    lines.append("")

    lines.append(f"Findings ({len(result.findings)}), most severe first:")
    for f in _sorted_findings(result):
        lines.append(
            f"  [{f.severity.upper():8}] {f.rule_id:28} {f.title} "
            f"(tactic={f.tactic}, confidence={f.confidence}, events={len(f.events)})"
        )
        lines.append(f"      {f.description}")
        if f.mitre:
            lines.append(f"      ATT&CK: {', '.join(f.mitre)}")
        if f.recommendation:
            lines.append(f"      -> {f.recommendation}")
    lines.append("")
    tactic_counts = {}
    for f in result.findings:
        tactic_counts[f.tactic] = tactic_counts.get(f.tactic, 0) + 1
    lines.append("By tactic: " + ", ".join(f"{k}={v}" for k, v in sorted(tactic_counts.items(), key=lambda kv: _tactic_rank(kv[0]))))
    return "\n".join(lines)


def render_json(result: AnalysisResult) -> str:
    index = _ts_index(result)
    payload = {
        "path": result.path,
        "event_count": len(result.events),
        "worst_severity": result.worst_severity,
        "timeline": [f.rule_id for f in _timeline(result)],
        "findings": [dict(f.to_dict(), first_seen=fmt_ts(_earliest_ts(result, f, index)))
                     for f in _sorted_findings(result)],
    }
    return json.dumps(payload, indent=2, default=str)


def render_markdown(result: AnalysisResult) -> str:
    lines = [f"# evtxkit analysis: `{result.path}`", ""]
    lines.append(f"**Events:** {len(result.events)}  **Findings:** {len(result.findings)}  **Worst severity:** {result.worst_severity}")
    lines.append("")
    if not result.findings:
        lines.append("No findings.")
        return "\n".join(lines)

    index = _ts_index(result)
    lines.append("## Attack timeline")
    lines.append("")
    lines.append("| Time (UTC) | Tactic | Severity | Rule | Title |")
    lines.append("|---|---|---|---|---|")
    for f in _timeline(result):
        lines.append(f"| {fmt_ts(_earliest_ts(result, f, index))} | {f.tactic} | {f.severity} | `{f.rule_id}` | {f.title} |")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    for f in _sorted_findings(result):
        lines.append(f"### `{f.rule_id}` — {f.title}")
        lines.append("")
        lines.append(f"*Tactic: {f.tactic} · Severity: {f.severity} · Confidence: {f.confidence}"
                     + (f" · ATT&CK: {', '.join(f.mitre)}" if f.mitre else "") + "*")
        lines.append("")
        lines.append(f.description)
        if f.recommendation:
            lines.append("")
            lines.append(f"**Recommendation:** {f.recommendation}")
        lines.append("")
    return "\n".join(lines)


_SEV_HEX = {"critical": "#b3261e", "high": "#d93025", "medium": "#b7791f",
            "low": "#3a7ca5", "info": "#6b7280"}


def render_html(result: AnalysisResult) -> str:
    esc = _html.escape
    index = _ts_index(result)
    by_idx = result.event_by_index()
    cards = []
    for f in _sorted_findings(result):
        colour = _SEV_HEX.get(f.severity, "#6b7280")
        ev_rows = "".join(
            f"<li><code>{esc(fmt_ts(by_idx[i].ts))}</code> [{by_idx[i].event_id}] "
            f"{esc(by_idx[i].summary()[:220])}</li>"
            for i in f.events[:8] if i in by_idx)
        cards.append(
            f'<div class="f" style="border-left-color:{colour}">'
            f'<h3>{esc(f.title)} <code>{esc(f.rule_id)}</code></h3>'
            f'<div class="meta"><span class="b" style="background:{colour}">{esc(f.severity)}</span>'
            f'<span>{esc(f.tactic)}</span><span>confidence {esc(f.confidence)}</span>'
            f'<span>{esc(fmt_ts(_earliest_ts(result, f, index)))}</span>'
            + (f'<span>ATT&amp;CK {esc(", ".join(f.mitre))}</span>' if f.mitre else "")
            + f'</div><p>{esc(f.description)}</p>'
            + (f"<ul>{ev_rows}</ul>" if ev_rows else "")
            + (f'<p class="rec">{esc(f.recommendation)}</p>' if f.recommendation else "")
            + "</div>")
    body = "".join(cards) or "<p>No findings.</p>"
    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>evtxkit analysis</title>
<style>
:root{{--bg:#fbfbfa;--fg:#1d1c1a;--muted:#6b6862;--card:#fff;--line:#e5e2dc}}
@media(prefers-color-scheme:dark){{:root{{--bg:#191817;--fg:#e9e7e3;--muted:#9a958c;--card:#232120;--line:#332f2d}}}}
body{{margin:0;background:var(--bg);color:var(--fg);font:14px/1.55 system-ui,sans-serif;padding:2rem 1rem}}
.wrap{{max-width:980px;margin:0 auto}} h1{{font-size:1.4rem}} code{{font-size:.85em}}
.f{{background:var(--card);border:1px solid var(--line);border-left-width:4px;border-radius:8px;padding:.8rem 1rem;margin:.6rem 0}}
.f h3{{margin:0 0 .3rem;font-size:1rem}} .meta{{display:flex;gap:.8rem;flex-wrap:wrap;color:var(--muted);font-size:.8rem}}
.b{{color:#fff;border-radius:4px;padding:0 .4rem;font-weight:700;text-transform:uppercase;font-size:.7rem}}
.rec{{color:var(--muted);border-left:2px solid var(--line);padding-left:.6rem}} ul{{font-size:.82rem;color:var(--muted)}}
</style>
</head>
<body><div class="wrap">
<h1>evtxkit analysis: {esc(result.path)}</h1>
<p>Events: {len(result.events)} &middot; Findings: {len(result.findings)} &middot; Worst severity: {esc(result.worst_severity)} &middot; times in UTC</p>
{body}
</div></body>
</html>"""


_RENDERERS = {
    "console": render_console,
    "json": render_json,
    "markdown": render_markdown,
    "html": render_html,
}


def render(result: AnalysisResult, fmt: str = "console") -> str:
    if fmt not in _RENDERERS:
        raise ValueError(f"unknown report format: {fmt!r} (choices: {sorted(_RENDERERS)})")
    return _RENDERERS[fmt](result)
