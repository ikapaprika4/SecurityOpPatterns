"""
Case exports: a self-contained HTML report (the same visual language as the
app, printable, no external resources), the case as JSON, indicators as CSV
or a blocklist, plus each kit's own machine formats (MISP/STIX for email,
firewall ACLs for captures, Snort/Suricata rules for network logs).

Every string that came out of the evidence is attacker-controlled and is
HTML-escaped; URLs appear defanged and are never rendered as links.
"""

from __future__ import annotations

import csv
import html
import io
import json
import re
from datetime import datetime, timezone

EXPORTS = {
    "html": ("Report (HTML)", "text/html; charset=utf-8", "report.html"),
    "json": ("Case (JSON)", "application/json", "case.json"),
    "iocs_csv": ("Indicators (CSV)", "text/csv; charset=utf-8", "iocs.csv"),
    "blocklist": ("Blocklist (TXT)", "text/plain; charset=utf-8", "blocklist.txt"),
    "misp": ("MISP event (JSON)", "application/json", "misp.json"),
    "stix": ("STIX 2.1 bundle", "application/json", "stix.json"),
    "acl_iptables": ("ACL: iptables", "text/plain; charset=utf-8", "acl-iptables.sh"),
    "acl_cisco_ios": ("ACL: Cisco IOS", "text/plain; charset=utf-8", "acl-cisco.txt"),
    "acl_pf": ("ACL: pf", "text/plain; charset=utf-8", "acl-pf.conf"),
    "acl_netsh": ("ACL: Windows netsh", "text/plain; charset=utf-8", "acl-netsh.bat"),
    "snort": ("Snort/Suricata rules", "text/plain; charset=utf-8", "local.rules"),
}


def filename(case: dict, fmt: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", case.get("title") or "case").strip("_")[:60] or "case"
    return f"{stem}-{EXPORTS[fmt][2]}"


def render(case: dict, fmt: str) -> tuple[bytes, str]:
    """(body, content-type) for an export format listed in case['exports']."""
    if fmt not in EXPORTS or fmt not in case.get("exports", []):
        raise KeyError(fmt)
    ctype = EXPORTS[fmt][1]
    extra = case.get("_export", {})
    if fmt == "html":
        return report_html(case).encode("utf-8"), ctype
    if fmt == "json":
        public = {k: v for k, v in case.items() if not k.startswith("_")}
        return json.dumps(public, indent=2, ensure_ascii=False).encode("utf-8"), ctype
    if fmt == "iocs_csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["type", "value_defanged", "value", "block", "context"])
        for i in case.get("iocs", []):
            w.writerow([i["type"], i["value"], i["raw"], "yes" if i["block"] else "no", i["context"]])
        return buf.getvalue().encode("utf-8"), ctype
    if fmt == "blocklist":
        return blocklist(case).encode("utf-8"), ctype
    if fmt in ("misp", "stix"):
        from phishkit.iocs import to_misp, to_stix_lite
        iocs = extra.get("phish_iocs", {})
        body = to_misp(iocs, info=f"Phishing: {case.get('title', '')}") if fmt == "misp" \
            else to_stix_lite(iocs)
        return body.encode("utf-8"), ctype
    if fmt.startswith("acl_"):
        from trafkit.aclgen import generate_acl
        return generate_acl(extra.get("traf_findings", []), fmt[4:], "medium").encode("utf-8"), ctype
    if fmt == "snort":
        from nsmkit.snortgen import findings_to_snort
        return findings_to_snort(extra.get("nsm_findings", [])).encode("utf-8"), ctype
    raise KeyError(fmt)


def blocklist(case: dict) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [f"# SOC Workbench blocklist -- {case.get('title', '')}",
             f"# {case.get('kit_label', '')} case, generated {now}. Review before deploying.",
             "# Only indicators judged block-worthy are listed; legitimate / shared",
             "# infrastructure seen in the evidence is deliberately left out."]
    groups: dict[str, list[str]] = {}
    for i in case.get("iocs", []):
        if i["block"]:
            groups.setdefault(i["type"], []).append(i["raw"])
    if not groups:
        lines.append("# (no block-worthy indicators)")
    for typ in ("ip", "domain", "url", "email", "sha256", "sha1", "md5"):
        if typ in groups:
            lines += ["", f"# {typ}"] + sorted(set(groups.pop(typ)))
    for typ, vals in groups.items():
        lines += ["", f"# {typ}"] + sorted(set(vals))
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# HTML report
# --------------------------------------------------------------------------

_CSS = """
:root{--paper:#f4f2ec;--raised:#fcfbf8;--ink:#20242b;--soft:#5b6169;--faint:#8a8f96;--rule:#dcd7ca;
--code:#eeebe3;--crit:#b3261e;--high:#c2410c;--med:#a16207;--low:#2f6f9f;--info:#6b7280;--clean:#2e7d4f;
--accent:#3c5a80}
@media (prefers-color-scheme:dark){:root{--paper:#15181d;--raised:#1d222a;--ink:#e9e6dd;--soft:#9ba1aa;
--faint:#6e7580;--rule:#2b313b;--code:#11151a;--crit:#f2837b;--high:#fb923c;--med:#facc15;--low:#7cb7e0;
--info:#9ca3af;--clean:#6fcf97}}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);
font:14px/1.55 "IBM Plex Sans","Segoe UI Variable","Segoe UI",system-ui,sans-serif}
.wrap{max-width:1040px;margin:0 auto;padding:36px 22px 80px}
h1,h2,h3{font-family:Fraunces,"Iowan Old Style","Palatino Linotype",Georgia,serif;margin:0}
h1{font-size:28px;line-height:1.15;margin:6px 0 4px}h2{font-size:18px;margin:28px 0 10px;
padding-bottom:6px;border-bottom:1px solid var(--rule)}h3{font-size:15px}
.kicker{font:600 11px/1 "IBM Plex Mono","Cascadia Mono",Consolas,monospace;letter-spacing:.12em;
text-transform:uppercase;color:var(--faint)}
.sub{color:var(--soft)}.mono,code,pre{font-family:"IBM Plex Mono","Cascadia Mono",Consolas,monospace}
.pill{display:inline-block;padding:4px 12px;border-radius:999px;color:#fff;font:700 12px/1.4 system-ui;
letter-spacing:.06em}.lv-critical{background:var(--crit)}.lv-high{background:var(--high)}
.lv-medium{background:var(--med)}.lv-low{background:var(--low)}.lv-info{background:var(--info)}
.lv-clean{background:var(--clean)}
.tiles{display:flex;gap:10px;flex-wrap:wrap;margin:18px 0}.tile{background:var(--raised);
border:1px solid var(--rule);border-radius:10px;padding:10px 14px;min-width:96px}
.tile b{display:block;font-size:22px;line-height:1.1}.tile span{font-size:11px;color:var(--soft);
text-transform:uppercase;letter-spacing:.06em}
.f{background:var(--raised);border:1px solid var(--rule);border-left:4px solid var(--info);
border-radius:10px;padding:12px 16px;margin:10px 0;break-inside:avoid}
.f.critical{border-left-color:var(--crit)}.f.high{border-left-color:var(--high)}
.f.medium{border-left-color:var(--med)}.f.low{border-left-color:var(--low)}
.meta{display:flex;gap:12px;flex-wrap:wrap;color:var(--soft);font-size:12px;margin:4px 0 8px}
.meta .sev{font-weight:700;text-transform:uppercase}.critical .sev{color:var(--crit)}
.high .sev{color:var(--high)}.medium .sev{color:var(--med)}.low .sev{color:var(--low)}
pre{background:var(--code);border-radius:8px;padding:10px 12px;white-space:pre-wrap;word-break:break-word;
font-size:12px;margin:8px 0}.rec{border-left:2px solid var(--rule);padding-left:10px;color:var(--soft)}
table{border-collapse:collapse;width:100%;font-size:13px;margin:6px 0 4px}th,td{text-align:left;
vertical-align:top;padding:6px 8px;border-bottom:1px solid var(--rule);word-break:break-word}
th{color:var(--soft);font-weight:600}.kv th{width:190px;white-space:nowrap}
.bad{color:var(--crit);font-weight:600}.good{color:var(--clean);font-weight:600}.muted{color:var(--faint)}
.note{color:var(--soft);font-size:12px}.tl{border-left:2px solid var(--rule);margin:8px 0 0 6px;
padding-left:16px}.tl div{margin:0 0 10px}.tl time{font:12px "Cascadia Mono",Consolas,monospace;color:var(--soft)}
footer{margin-top:40px;color:var(--faint);font-size:12px}
@media print{body{background:#fff}.f,.tile{border-color:#ccc}}
"""


def _e(v) -> str:
    return html.escape("" if v is None else str(v))


def _cell(c) -> str:
    if isinstance(c, dict):
        text = c.get("t", "")
        cls = []
        if c.get("mono"):
            cls.append("mono")
        if c.get("tone") in ("bad", "good", "muted"):
            cls.append(c["tone"])
        return f'<td class="{" ".join(cls)}">{_e(text)}</td>'
    return f"<td>{_e(c)}</td>"


def _section(s: dict) -> str:
    title = f"<h3>{_e(s.get('title'))}</h3>"
    note = f'<p class="note">{_e(s["note"])}</p>' if s.get("note") else ""
    kind = s.get("kind")
    if kind == "kv":
        rows = "".join(f"<tr><th>{_e(k)}</th><td class='mono'>{_e(v)}</td></tr>" for k, v in s["items"])
        return f"{title}<table class='kv'>{rows}</table>{note}"
    if kind == "table":
        head = "".join(f"<th>{_e(c)}</th>" for c in s["columns"])
        rows = "".join("<tr>" + "".join(_cell(c) for c in r) + "</tr>" for r in s["rows"])
        return f"{title}<table><tr>{head}</tr>{rows}</table>{note}"
    if kind == "timeline":
        items = "".join(f"<div><time>{_e(i['when'])}</time><br><b>{_e(i['label'])}</b> "
                        f"<span class='muted'>· {_e(i['severity'])} · {_e(i.get('detail', ''))}</span></div>"
                        for i in s["items"])
        return f"{title}<div class='tl'>{items}</div>{note}"
    if kind == "text":
        return f"{title}<pre{' class=mono' if s.get('mono') else ''}>{_e(s['text'])}</pre>{note}"
    return ""


def report_html(case: dict) -> str:
    v = case.get("verdict", {})
    counts = case.get("counts", {})
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
           f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
           f"<title>{_e(case.get('title'))} — SOC Workbench report</title><style>{_CSS}</style></head>"
           f"<body><div class='wrap'>"]
    out.append(f"<div class='kicker'>SOC Workbench · {_e(case.get('kit_label'))} case</div>")
    out.append(f"<h1>{_e(case.get('title'))}</h1>")
    out.append(f"<div class='sub'>{_e(case.get('subtitle'))}</div>")
    score = f" · score {v['score']}" if v.get("score") is not None else ""
    out.append(f"<p><span class='pill lv-{_e(v.get('level', 'info'))}'>{_e(v.get('label', ''))}</span> "
               f"<span class='sub'>{_e(v.get('summary', ''))}{_e(score)}</span></p>")
    out.append("<div class='tiles'>" + "".join(
        f"<div class='tile'><b>{counts.get(s, 0)}</b><span>{s}</span></div>"
        for s in ("critical", "high", "medium", "low", "info"))
        + f"<div class='tile'><b>{len(case.get('iocs', []))}</b><span>indicators</span></div></div>")
    src = "".join(f"<tr><td class='mono'>{_e(s['name'])}</td><td>{_e(s['size_h'])}</td>"
                  f"<td>{_e(s['detected_as'])}</td></tr>" for s in case.get("sources", []))
    out.append(f"<h2>Evidence</h2><table><tr><th>File</th><th>Size</th><th>Recognised as</th></tr>{src}</table>")
    if case.get("notes"):
        out.append("<p class='note'>" + "<br>".join(_e(n) for n in case["notes"]) + "</p>")

    out.append(f"<h2>Findings ({len(case.get('findings', []))})</h2>")
    if not case.get("findings"):
        out.append("<p class='sub'>No detector fired on this evidence.</p>")
    for f in case.get("findings", []):
        mitre = ", ".join(f.get("mitre") or [])
        out.append(
            f"<div class='f {_e(f['severity'])}'><h3>{_e(f['title'])}</h3>"
            f"<div class='meta'><span class='sev'>{_e(f['severity'])}</span>"
            f"<span class='mono'>{_e(f['rule_id'])}</span><span>confidence {_e(f['confidence'])}</span>"
            + (f"<span>{_e(f['category'])}</span>" if f.get("category") else "")
            + (f"<span>{_e(f['when'])}</span>" if f.get("when") else "")
            + (f"<span>ATT&amp;CK {_e(mitre)}</span>" if mitre else "")
            + f"</div><div>{_e(f['description'])}</div>"
            + (f"<pre>{_e(chr(10).join(f['evidence'][:12]))}</pre>" if f.get("evidence") else "")
            + (f"<p class='rec'>{_e(f['recommendation'])}</p>" if f.get("recommendation") else "")
            + "</div>")

    if case.get("sections"):
        out.append("<h2>Details</h2>")
        out += [_section(s) for s in case["sections"]]

    iocs = case.get("iocs", [])
    if iocs:
        out.append(f"<h2>Indicators ({len(iocs)})</h2><p class='note'>Defanged. "
                   "“Block” marks indicators fit for a blocklist; the rest is context "
                   "(internal hosts, accounts, legitimate or shared infrastructure).</p>")
        rows = "".join(f"<tr><td>{_e(i['type'])}</td><td class='mono'>{_e(i['value'])}</td>"
                       f"<td class='{'bad' if i['block'] else 'muted'}'>{'block' if i['block'] else 'context'}</td>"
                       f"<td class='muted'>{_e(i['context'])}</td></tr>" for i in iocs)
        out.append(f"<table><tr><th>Type</th><th>Value</th><th></th><th>Context</th></tr>{rows}</table>")
    out.append(f"<footer>Generated by SOC Workbench on {now}. Times are UTC. Case {_e(case.get('id'))}."
               f"</footer></div></body></html>")
    return "".join(out)
