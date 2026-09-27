"""Rendering: console (with colour), JSON, Markdown, HTML -- same four
formats as nsmkit/phishkit for consistency across the toolkit family."""

from __future__ import annotations

import html
import json

from .models import AnalysisResult
from .statistics import capture_summary

_SEV_COLOR = {"critical": "\033[1;41m", "high": "\033[1;31m", "medium": "\033[1;33m",
              "low": "\033[0;36m", "info": "\033[0;37m"}
_RESET = "\033[0m"


def render_console(result: AnalysisResult, colour: bool = True, verbose: bool = False) -> str:
    lines = [f"== trafkit report: {result.path} =="]
    summary = capture_summary(result.packets)
    lines.append(f"{summary.get('packet_count', 0)} packets, "
                 f"{summary.get('total_bytes', 0):,} bytes, "
                 f"{summary.get('duration_seconds', 0)}s")
    lines.append(f"Hosts: {len(result.hosts)}   Findings: {len(result.findings)}   "
                 f"Worst severity: {result.worst_severity}")
    lines.append("")

    if not result.findings:
        lines.append("No findings.")
    for f in result.findings:
        c = _SEV_COLOR.get(f.severity, "") if colour else ""
        r = _RESET if colour else ""
        lines.append(f"[{c}{f.severity.upper()}{r}] {f.rule_id} -- {f.title}")
        lines.append(f"  {f.description}")
        if f.mitre:
            lines.append(f"  ATT&CK: {f.mitre}")
        if verbose and f.evidence:
            lines.append(f"  evidence: {json.dumps(f.evidence, default=str)[:400]}")
        if verbose and f.frames:
            lines.append(f"  frames: {f.frames[:15]}")
        if f.recommendation:
            lines.append(f"  -> {f.recommendation}")
        lines.append("")
    return "\n".join(lines)


def render_json(result: AnalysisResult) -> str:
    return json.dumps({
        "path": result.path,
        "summary": capture_summary(result.packets),
        "host_count": len(result.hosts),
        "worst_severity": result.worst_severity,
        "findings": [f.to_dict() for f in result.findings],
    }, indent=2, default=str)


def render_markdown(result: AnalysisResult) -> str:
    summary = capture_summary(result.packets)
    lines = [f"# trafkit report: `{result.path}`", "",
             f"- Packets: {summary.get('packet_count', 0)}",
             f"- Bytes: {summary.get('total_bytes', 0):,}",
             f"- Duration: {summary.get('duration_seconds', 0)}s",
             f"- Hosts: {len(result.hosts)}",
             f"- Findings: {len(result.findings)} (worst: {result.worst_severity})",
             ""]
    if not result.findings:
        lines.append("No findings.")
    for f in result.findings:
        lines.append(f"## [{f.severity.upper()}] {f.rule_id} -- {f.title}")
        lines.append("")
        lines.append(f.description)
        lines.append("")
        if f.mitre:
            lines.append(f"**ATT&CK:** {f.mitre}")
        if f.recommendation:
            lines.append(f"**Recommendation:** {f.recommendation}")
        lines.append("")
    return "\n".join(lines)


def render_html(result: AnalysisResult) -> str:
    summary = capture_summary(result.packets)
    rows = []
    for f in result.findings:
        rows.append(f"""
        <tr class="sev-{f.severity}">
          <td>{html.escape(f.severity.upper())}</td>
          <td>{html.escape(f.rule_id)}</td>
          <td>{html.escape(f.title)}</td>
          <td>{html.escape(f.description)}</td>
          <td>{html.escape(f.recommendation or '')}</td>
        </tr>""")
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>trafkit report: {html.escape(result.path)}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }}
table {{ border-collapse: collapse; width: 100%; }}
td, th {{ border: 1px solid #ccc; padding: 6px 10px; text-align: left; vertical-align: top; }}
tr.sev-critical {{ background: #ffdada; }}
tr.sev-high {{ background: #ffe8d6; }}
tr.sev-medium {{ background: #fff8d6; }}
tr.sev-low {{ background: #e8f6ff; }}
tr.sev-info {{ background: #f4f4f4; }}
</style></head><body>
<h1>trafkit report: {html.escape(result.path)}</h1>
<p>{summary.get('packet_count', 0)} packets, {summary.get('total_bytes', 0):,} bytes,
   {summary.get('duration_seconds', 0)}s duration, {len(result.hosts)} hosts,
   worst severity <strong>{html.escape(result.worst_severity)}</strong>.</p>
<table>
<tr><th>Severity</th><th>Rule</th><th>Title</th><th>Description</th><th>Recommendation</th></tr>
{''.join(rows) if rows else '<tr><td colspan="5">No findings.</td></tr>'}
</table>
</body></html>"""
