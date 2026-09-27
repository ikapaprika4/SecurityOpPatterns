"""
The analysis engine behind the workbench: expand what was dropped, route
every file to its kit, run it, and normalise each result into a *case* -- one
JSON-safe shape the UI and the HTML report render the same way, whichever
kit produced it:

    verdict   label + level (critical/high/medium/low/clean/info) + score
    findings  rule, severity, confidence, description, evidence, action, ATT&CK
    iocs      typed indicators, each marked block-worthy or context-only
    sections  kit-specific detail as kv / table / timeline / text blocks

Grouping follows what each kit is for: every email is its own case; Windows
logs are merged per host (Security + Sysmon from one machine correlate
through Logon IDs and PIDs, two machines must not); network logs are merged
into one case (cross-device correlation is nsmkit's whole point); every
capture is its own case, analysed by trafkit (packets) *and* nsmkit's
flow-level detectors (beaconing, exfiltration, DNS spoofing, SSL stripping)
from a single parse.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
import traceback
import uuid
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Optional

from soccore import netaddr

from .detect import EVTX, KIT_LABELS, NSM, PHISH, TRAF, Sniff, sniff

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEV_RANK = {s: 4 - i for i, s in enumerate(SEVERITIES)}
MAX_PACKETS = 3_000_000
ZIP_PASSWORDS = (None, b"infected", b"malware", b"virus")   # the sample-sharing conventions
Progress = Callable[[str], None]


@dataclass
class Batch:
    files: list[str] = field(default_factory=list)
    names: dict[str, str] = field(default_factory=dict)     # path -> display name
    skipped: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


# ==========================================================================
# Utilities
# ==========================================================================

def _utc(ts: Optional[float]) -> Optional[str]:
    if not ts or ts <= 0:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _dt(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def jsonable(obj: Any) -> Any:
    """Anything -> JSON-safe (bytes become hex, sets lists, dates ISO)."""
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, (bytes, bytearray)):
        return bytes(obj[:256]).hex()
    if isinstance(obj, dict):
        return {str(k): jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [jsonable(v) for v in obj]
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "value") and isinstance(getattr(obj, "value"), (str, int)):
        return obj.value
    return str(obj)


def _defang(v: str) -> str:
    from phishkit.iocs import defang
    return defang(v)


def _fmt(v: Any) -> str:
    """Evidence value -> one readable line (strings unquoted)."""
    if isinstance(v, str):
        return v[:400]
    if isinstance(v, (list, tuple, set)) and all(isinstance(x, (str, int, float)) for x in v):
        return ", ".join(str(x) for x in list(v)[:30])
    return json.dumps(jsonable(v))[:400]


def _counts(findings: list[dict]) -> dict[str, int]:
    c = Counter(f["severity"] for f in findings)
    return {s: c.get(s, 0) for s in SEVERITIES}


def _severity_verdict(findings: list[dict], clean_label: str = "No findings") -> dict:
    ranked = [f for f in findings if f["severity"] != "info"] or findings
    if not ranked:
        return {"label": "CLEAN", "level": "clean", "score": None, "summary": clean_label}
    worst = max(ranked, key=lambda f: SEV_RANK.get(f["severity"], 0))["severity"]
    n = len([f for f in findings if f["severity"] == worst])
    return {"label": worst.upper(), "level": worst if worst != "info" else "info", "score": None,
            "summary": f"{n} {worst} finding{'s' if n != 1 else ''} of {len(findings)}"}


def _new_case(kit: str, title: str, sources: list[dict]) -> dict:
    return {"id": uuid.uuid4().hex[:12], "kit": kit, "kit_label": KIT_LABELS.get(kit, "Unsupported"),
            "title": title, "subtitle": "", "sources": sources, "status": "ok",
            "verdict": {}, "counts": {}, "findings": [], "iocs": [], "sections": [],
            "notes": [], "exports": ["html", "json", "iocs_csv", "blocklist"],
            "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "elapsed_ms": 0, "native": None}


def _source(path: str, name: str, s: Optional[Sniff]) -> dict:
    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0
    return {"name": name, "size": size, "size_h": _human_bytes(size),
            "format": s.fmt if s else "", "detected_as": s.reason if s else ""}


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for block in iter(lambda: fh.read(1 << 20), b""):
                h.update(block)
    except OSError:
        return ""
    return h.hexdigest()


def _add_ioc(iocs: list[dict], seen: set, typ: str, value: str, context: str,
             block: bool, defang: bool = True) -> None:
    if not value:
        return
    key = (typ, value.lower())
    if key in seen:
        return
    seen.add(key)
    iocs.append({"type": typ, "value": _defang(value) if defang else value, "raw": value,
                 "context": context, "block": block})


_URL_IN_TEXT = re.compile(r"\bhttps?://[^\s'\"<>|)]+", re.I)


# ==========================================================================
# Expansion: folders, zips
# ==========================================================================

def expand(paths: Iterable[str], names: Optional[dict[str, str]] = None,
           workdir: Optional[str] = None, progress: Progress = lambda m: None) -> Batch:
    batch = Batch()
    names = names or {}
    for p in paths:
        display = names.get(p, os.path.basename(p))
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for f in sorted(files):
                    full = os.path.join(root, f)
                    batch.files.append(full)
                    batch.names[full] = os.path.relpath(full, os.path.dirname(p))
            continue
        if zipfile.is_zipfile(p) and not sniff(p).kit and workdir:
            _expand_zip(p, display, workdir, batch, progress)
            continue
        batch.files.append(p)
        batch.names[p] = display
    return batch


def _expand_zip(path: str, display: str, workdir: str, batch: Batch, progress: Progress) -> None:
    dest = os.path.join(workdir, "unzipped", uuid.uuid4().hex[:8])
    os.makedirs(dest, exist_ok=True)
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        batch.skipped.append({"name": display, "reason": f"damaged zip: {exc}"})
        return
    used_password = None
    with zf:
        members = [m for m in zf.infolist() if not m.is_dir()][:2000]
        progress(f"Unpacking {display} ({len(members)} files)")
        for m in members:
            base = os.path.basename(m.filename.replace("\\", "/"))
            if not base or m.file_size > 4 * 1024 ** 3:
                continue
            data = None
            for pwd in ZIP_PASSWORDS:
                try:
                    data = zf.read(m, pwd=pwd)
                    used_password = used_password or (pwd.decode() if pwd else None)
                    break
                except RuntimeError:            # encrypted, wrong password
                    continue
                except (zipfile.BadZipFile, NotImplementedError, OSError) as exc:
                    batch.skipped.append({"name": f"{display}/{m.filename}",
                                          "reason": f"could not extract: {exc}"})
                    break
            if data is None:
                if m.flag_bits & 0x1:
                    batch.skipped.append({"name": f"{display}/{m.filename}",
                                          "reason": "encrypted with an unknown password"})
                continue
            # Only evidence gets written out. Anything else in the archive
            # (binaries, documents) stays inside it -- never on disk.
            safe = re.sub(r"[^A-Za-z0-9._ -]", "_", base)[:120] or "member"
            target = os.path.join(dest, f"{len(batch.files):04d}_{safe}")
            with open(target, "wb") as fh:
                fh.write(data)
            s = sniff(target)
            if s.kit is None:
                os.remove(target)
                batch.skipped.append({"name": f"{display}/{m.filename}", "reason": s.reason})
                continue
            batch.files.append(target)
            batch.names[target] = f"{display}/{m.filename}"
    if used_password:
        batch.notes.append(f"{display}: opened with the conventional password '{used_password}'")


# ==========================================================================
# Orchestration
# ==========================================================================

def analyze_batch(paths: list[str], names: Optional[dict[str, str]] = None,
                  workdir: Optional[str] = None, progress: Progress = lambda m: None) -> dict:
    """Analyse everything dropped together. Returns {"cases": [...],
    "skipped": [...], "notes": [...]}."""
    batch = expand(paths, names, workdir, progress)
    routed: dict[str, list[tuple[str, Sniff]]] = defaultdict(list)
    for f in batch.files:
        s = sniff(f)
        if s.kit is None:
            batch.skipped.append({"name": batch.names.get(f, os.path.basename(f)), "reason": s.reason})
            continue
        routed[s.kit].append((f, s))

    cases: list[dict] = []
    for f, s in routed.get(PHISH, []):
        cases.extend(_guard(PHISH, [(f, s)], batch, progress, _phish_cases))
    if routed.get(EVTX):
        cases.extend(_guard(EVTX, routed[EVTX], batch, progress, _evtx_cases))
    if routed.get(NSM):
        cases.extend(_guard(NSM, routed[NSM], batch, progress, _nsm_cases))
    for f, s in routed.get(TRAF, []):
        cases.extend(_guard(TRAF, [(f, s)], batch, progress, _traf_cases))

    for c in cases:
        c["counts"] = _counts(c["findings"])
    return {"cases": cases, "skipped": batch.skipped, "notes": batch.notes}


def _guard(kit: str, items, batch: Batch, progress: Progress, fn) -> list[dict]:
    """Run one kit adapter; a failure becomes an error case the analyst can
    see, never a lost batch."""
    t0 = time.perf_counter()
    try:
        out = fn(items, batch, progress)
    except Exception as exc:  # noqa: BLE001
        names = [batch.names.get(f, os.path.basename(f)) for f, _ in items]
        case = _new_case(kit, ", ".join(names)[:120] or "analysis", [
            _source(f, batch.names.get(f, os.path.basename(f)), s) for f, s in items])
        case["status"] = "error"
        case["verdict"] = {"label": "ERROR", "level": "info", "score": None,
                           "summary": "Could not be analysed"}
        case["notes"] = [f"{type(exc).__name__}: {exc}"]
        case["exports"] = ["json"]
        case["_trace"] = traceback.format_exc()          # log only; never sent to the page
        out = [case]
    elapsed = int((time.perf_counter() - t0) * 1000)
    for c in out:
        c["elapsed_ms"] = c.get("elapsed_ms") or elapsed
    return out


# ==========================================================================
# phishkit
# ==========================================================================

_PHISH_LEVEL = {"malicious": "critical", "phishing": "high", "suspicious": "medium",
                "spam": "low", "benign": "clean"}
_PHISH_IOC_TYPES = {
    "sender_addresses": ("email", "sender address"), "reply_to": ("email", "reply-to address"),
    "sender_domains": ("domain", "sender domain"), "url_domains": ("domain", "link domain"),
    "originating_ips": ("ip", "originating IP"), "urls": ("url", "link"),
    "attachment_sha256": ("sha256", "attachment"), "attachment_md5": ("md5", "attachment"),
    "attachment_sha1": ("sha1", "attachment"), "attachment_names": ("filename", "attachment"),
    "message_ids": ("message-id", "message"), "subjects": ("subject", "message"),
    "context_domains": ("domain", "legitimate/shared domain -- do not block"),
    "context_urls": ("url", "link to a legitimate site -- do not block"),
    "context_ips": ("ip", "mail provider's server -- do not block"),
}


def _phish_cases(items, batch: Batch, progress: Progress) -> list[dict]:
    from phishkit import analyze_paths
    from phishkit.iocs import refang
    path, s = items[0]
    display = batch.names.get(path, os.path.basename(path))
    progress(f"Analysing email {display}")
    results = analyze_paths([path])
    cases = []
    for r in results:
        t0 = time.perf_counter()
        e = r.email
        sub = e.source_path.rsplit("#", 1)[1] if "#" in e.source_path else ""
        name = f"{display} #{sub}" if sub else display
        case = _new_case(PHISH, e.subject or "(no subject)", [_source(path, name, s)])
        frm = e.from_addr.address if e.from_addr else "?"
        case["subtitle"] = f"from {frm}"
        v = r.verdict.value
        case["verdict"] = {
            "label": v.upper(), "level": _PHISH_LEVEL.get(v, "info"), "score": r.score,
            "summary": f"score {r.score}" + (f" · {', '.join(t.value for t in r.phish_types)}"
                                             if r.phish_types else "")}
        for f in sorted(r.findings, key=lambda f: (-f.severity_rank, -f.score)):
            case["findings"].append({
                "rule_id": f.rule_id, "title": f.title, "severity": f.severity,
                "confidence": f.confidence, "category": f.category,
                "description": f.description, "evidence": list(f.evidence),
                "recommendation": f.recommendation, "mitre": list(f.mitre),
                "when": _dt(e.date), "engine": "phishkit", "score": f.score})
        benign = v == "benign"
        seen: set = set()
        for kind, values in r.iocs.items():
            typ, ctx = _PHISH_IOC_TYPES.get(kind, ("text", kind))
            blockable = not kind.startswith("context_") and not benign and kind not in (
                "subjects", "message_ids", "attachment_names")
            network = typ in ("email", "domain", "ip", "url")
            for val in values:
                _add_ioc(case["iocs"], seen, typ, refang(val) if network else val, ctx,
                         blockable, defang=network)
        if benign and case["iocs"]:
            case["notes"].append("Benign verdict: indicators are listed for reference and "
                                 "excluded from the blocklist export.")
        case["sections"] = _phish_sections(r)
        case["notes"].extend(e.parse_errors)
        case["exports"] += ["misp", "stix"]
        case["native"] = jsonable(r.to_dict())
        case["elapsed_ms"] = int((time.perf_counter() - t0) * 1000)
        case["_export"] = {"phish_iocs": r.iocs}
        cases.append(case)
    return cases


def _phish_sections(r) -> list[dict]:
    e, a = r.email, r.email.auth
    tone = lambda res: "bad" if res in ("fail", "softfail", "permerror", "temperror") else (  # noqa: E731
        "good" if res == "pass" else "muted")
    sections = [
        {"kind": "kv", "title": "Message", "items": [
            ["From", str(e.from_addr) if e.from_addr else "(none)"],
            ["Reply-To", e.reply_to.address if e.reply_to else "—"],
            ["Return-Path", e.return_path.address if e.return_path else "—"],
            ["To", ", ".join(x.address for x in e.to) or "— (BCC delivery)"],
            ["Cc", ", ".join(x.address for x in e.cc) or "—"],
            ["Subject", e.subject or "(none)"],
            ["Date", _dt(e.date) or "—"],
            ["Message-ID", e.message_id or "—"],
            ["Originating IP", e.originating_ip or "—"],
            ["SHA-256 of file", e.file_sha256 or "—"],
        ]},
        {"kind": "table", "title": "Authentication", "columns": ["Check", "Result", "Detail"], "rows": [
            ["SPF", {"t": a.spf.value, "tone": tone(a.spf.value)},
             f"action: {a.spf_action}" + (f" · {a.spf_domain}" if a.spf_domain else "")],
            ["DKIM", {"t": a.dkim.value, "tone": tone(a.dkim.value)}, f"d={a.dkim_domain}" if a.dkim_domain else "—"],
            ["DMARC", {"t": a.dmarc.value, "tone": tone(a.dmarc.value)},
             f"p={a.dmarc_policy}" if a.dmarc_policy else "—"],
        ], "note": "Results asserted by the receiving mail server. A pass proves the domain is "
                   "real, not that it is trustworthy."},
    ]
    if e.received_chain:
        rows = []
        for hop in reversed(e.received_chain):
            rows.append([str(len(e.received_chain) - hop.index), hop.from_host or "?",
                         {"t": hop.from_ip or "?", "mono": True}, hop.by_host or "?",
                         hop.with_protocol or "", _dt(hop.timestamp) or "",
                         f"+{hop.delay_seconds:.0f}s" if hop.delay_seconds else ""])
        sections.append({"kind": "table", "title": "Delivery path (oldest first)",
                         "columns": ["#", "From host", "IP", "By", "Proto", "Time", "Delay"],
                         "rows": rows})
    if e.urls:
        rows = []
        for u in e.urls[:60]:
            flags = [n for n, on in (("shortener", u.is_shortener), ("tracking pixel", u.is_tracking_pixel),
                                     ("IP literal", u.is_ip_literal)) if on]
            if u.lookalike_of:
                flags.append(f"imitates {u.lookalike_of}")
            rows.append([{"t": u.defanged, "mono": True}, u.source, u.display_text[:80],
                         {"t": ", ".join(flags) or "—", "tone": "bad" if flags else "muted"}])
        sections.append({"kind": "table", "title": f"Links ({len(e.urls)})",
                         "columns": ["URL (defanged)", "Where", "Link text", "Flags"], "rows": rows})
    if e.attachments:
        rows = []
        for att in e.attachments:
            flags = [n for n, on in (("executable", att.is_dangerous),
                                     ("double extension", att.has_double_extension),
                                     ("macro-capable", att.macro_capable)) if on]
            rows.append([{"t": att.filename, "mono": True}, att.content_type, _human_bytes(att.size),
                         {"t": att.sha256, "mono": True},
                         {"t": ", ".join(flags) or "—", "tone": "bad" if flags else "muted"}])
        sections.append({"kind": "table", "title": "Attachments",
                         "columns": ["File", "Type", "Size", "SHA-256", "Flags"], "rows": rows,
                         "note": "Attachments are hashed in memory and never written to disk."})
    body = (e.body_text or "").strip()
    if not body and e.body_html:
        body = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", e.body_html)).strip()
    if body:
        sections.append({"kind": "text", "title": "Body (plain text, first 3000 characters)",
                         "text": body[:3000], "mono": False})
    hdrs = "\n".join(f"{k}: {' '.join(str(v).split())}" for k, v in e.all_headers)
    if hdrs:
        sections.append({"kind": "text", "title": "All headers", "text": hdrs[:20000], "mono": True,
                         "collapsed": True})
    return sections


# ==========================================================================
# evtxkit
# ==========================================================================

def _evtx_cases(items, batch: Batch, progress: Progress) -> list[dict]:
    from evtxkit import analyze_events
    from evtxkit.parsers import EventParseError, parse_event_file

    per_file: list[tuple[str, Sniff, list]] = []
    errors: list[str] = []
    for path, s in items:
        display = batch.names.get(path, os.path.basename(path))
        progress(f"Reading Windows events from {display}")
        try:
            evs = parse_event_file(path)
        except (EventParseError, OSError) as exc:
            errors.append(f"{display}: {exc}")
            continue
        if not evs:                      # zero events must not read as a clean host
            errors.append(f"{display}: no events found in the file")
            continue
        for e in evs:
            e.source = display
        per_file.append((path, s, evs))

    # Group by host: Logon IDs and PIDs are only meaningful within one machine.
    by_host: dict[str, list] = defaultdict(list)
    host_files: dict[str, set] = defaultdict(set)
    untimed: list = []
    untimed_files: set = set()
    for path, s, evs in per_file:
        for e in evs:
            if e.computer:
                by_host[e.computer].append(e)
                host_files[e.computer].add(path)
            else:
                untimed.append(e)
                untimed_files.add(path)
    groups: list[tuple[str, list, set]] = []
    if len(by_host) <= 1:
        host = next(iter(by_host), "")
        groups.append((host, by_host.get(host, []) + untimed, host_files.get(host, set()) | untimed_files))
    else:
        for host, evs in by_host.items():
            groups.append((host, evs, host_files[host]))
        if untimed:
            groups.append(("", untimed, untimed_files))

    sniffs = {p: s for p, s, _ in per_file}
    cases = []
    for host, evs, files in groups:
        t0 = time.perf_counter()
        evs.sort(key=lambda e: (e.ts <= 0, e.ts))
        for i, e in enumerate(evs):
            e.index = i
        names = sorted(batch.names.get(p, os.path.basename(p)) for p in files)
        label = names[0] if len(names) == 1 else f"{len(names)} logs"
        progress(f"Running evtxkit detectors over {len(evs):,} events"
                 + (f" from {host}" if host else ""))
        result = analyze_events(evs, path=label)
        if host:
            title = f"{host} · {names[0]}" if len(names) == 1 else host
        elif all(e.channel == "PowerShellHistory" for e in evs):
            title = f"PowerShell history · {names[0]}" if len(names) == 1 else "PowerShell history"
        else:
            title = names[0] if len(names) == 1 else "Windows events"
        case = _new_case(EVTX, title, [_source(p, batch.names.get(p, os.path.basename(p)),
                                               sniffs.get(p)) for p in sorted(files)])
        case["subtitle"] = f"{len(evs):,} events · {label}"
        _fill_evtx_case(case, result)
        case["notes"].extend(errors)
        case["elapsed_ms"] = int((time.perf_counter() - t0) * 1000)
        cases.append(case)
    if not per_file and errors:
        raise RuntimeError("; ".join(errors))
    return cases


def _fill_evtx_case(case: dict, result) -> None:
    from evtxkit.report import TACTIC_ORDER
    by_idx = result.event_by_index()
    seen: set = set()
    for f in sorted(result.findings, key=lambda f: (-f.severity_rank,
                                                    TACTIC_ORDER.index(f.tactic)
                                                    if f.tactic in TACTIC_ORDER else 99)):
        refs = [by_idx[i] for i in f.events if i in by_idx]
        timed = [e.ts for e in refs if e.ts > 0]
        evidence = [f"{k}: {v}" for k, v in f.evidence.items()
                    if v not in (None, "", [], {}) and k not in ("text", "decoded")]
        if f.evidence.get("decoded"):
            evidence.append(f"decoded: {f.evidence['decoded'][:600]}")
        evidence += [f"[{e.event_id}] {_utc(e.ts) or '(no time)'}  {e.summary()[:200]}"
                     + (f"  (record {e.get('EventRecordID')})" if e.get("EventRecordID") else "")
                     for e in refs[:8]]
        case["findings"].append({
            "rule_id": f.rule_id, "title": f.title, "severity": f.severity,
            "confidence": f.confidence, "category": f.tactic, "description": f.description,
            "evidence": evidence, "recommendation": f.recommendation, "mitre": list(f.mitre),
            "when": _utc(min(timed)) if timed else None, "engine": "evtxkit"})
        _evtx_iocs(case["iocs"], seen, f, refs)
    case["verdict"] = _severity_verdict(case["findings"])
    st = result.stats
    case["sections"] = [
        {"kind": "kv", "title": "Overview", "items": [
            ["Events", f"{st['event_count']:,}"],
            ["Hosts", ", ".join(f"{h} ({n:,})" for h, n in list(st["hosts"].items())[:6]) or "—"],
            ["First event", _utc(st["first_ts"]) or "—"],
            ["Last event", _utc(st["last_ts"]) or "—"],
            ["Channels", ", ".join(f"{c} ({n:,})" for c, n in st["by_channel"].items()) or "—"],
            ["Without timestamps", f"{st['untimed_events']:,}" if st["untimed_events"] else "0"],
        ]},
    ]
    timeline = sorted(case["findings"], key=lambda f: f["when"] or "~")
    if timeline:
        case["sections"].append({"kind": "timeline", "title": "Attack timeline (UTC)", "items": [
            {"when": f["when"] or "no timestamp", "label": f["title"], "severity": f["severity"],
             "detail": f"{f['category']} · {f['rule_id']}"} for f in timeline]})
    case["sections"].append({"kind": "table", "title": "Event IDs", "columns": ["Event ID", "Count"],
                             "rows": [[str(k), f"{v:,}"] for k, v in list(st["by_event_id"].items())[:25]]})
    case["native"] = jsonable({"path": result.path, "event_count": len(result.events),
                               "worst_severity": result.worst_severity, "stats": st,
                               "findings": [f.to_dict() for f in result.findings]})


def _evtx_iocs(iocs: list[dict], seen: set, f, refs) -> None:
    ev = f.evidence
    for key in ("src", "creator_source_ip", "destination"):
        v = ev.get(key)
        if isinstance(v, str) and netaddr.parse(v):
            ip = str(netaddr.parse(v))
            _add_ioc(iocs, seen, "ip", ip, f"{f.rule_id} {key}", netaddr.is_public(ip))
        elif isinstance(v, str) and "." in v and " " not in v and key == "destination":
            _add_ioc(iocs, seen, "domain", v, f"{f.rule_id} destination", True)
    for key in ("new_user", "target_user", "member", "cleared_by", "created_by"):
        v = ev.get(key)
        if isinstance(v, str) and v and v != "(not recorded)" and ":\\" not in v:
            _add_ioc(iocs, seen, "account", v, f"{f.rule_id} {key}", False, defang=False)
    for key in ("image", "binary_path", "target", "lnk_path", "launched", "created_by"):
        v = ev.get(key)
        if isinstance(v, str) and ("\\" in v or "/" in v):
            _add_ioc(iocs, seen, "file", v, f"{f.rule_id} {key}", False, defang=False)
    text = " ".join(str(ev.get(k, "")) for k in ("command_line", "decoded", "text"))
    for url in _URL_IN_TEXT.findall(text):
        _add_ioc(iocs, seen, "url", url.rstrip("'\");,"), f"{f.rule_id} command line", True)
    for e in refs:
        hashes = e.get("Hashes")
        for part in hashes.split(",") if hashes else []:
            algo, _, val = part.partition("=")
            if algo.upper() in ("SHA256", "MD5", "SHA1") and val:
                _add_ioc(iocs, seen, algo.lower(), val.lower(), f"{f.rule_id} {e.image}", True,
                         defang=False)


# ==========================================================================
# nsmkit
# ==========================================================================

_NSM_ATTACKER_SRC = ("NSM-SCAN", "NSM-CRED", "NSM-WEB", "NSM-PERIM")
_NSM_ATTACKER_DST = ("NSM-C2", "NSM-EXFIL")


def _nsm_cases(items, batch: Batch, progress: Progress) -> list[dict]:
    import nsmkit
    from nsmkit.config import Config
    from nsmkit.parsers import read_file

    events, notes, used = [], [], []
    for path, s in items:
        display = batch.names.get(path, os.path.basename(path))
        progress(f"Parsing {display}")
        try:
            evs = read_file(path)
        except Exception as exc:  # noqa: BLE001
            notes.append(f"{display}: could not be parsed ({type(exc).__name__}: {exc})")
            continue
        if not evs:
            notes.append(f"{display}: no events recognised")
            continue
        events.extend(evs)
        used.append((path, s))
    if not events:
        raise RuntimeError("no events could be parsed from these files. " + " ".join(notes))
    events.sort(key=lambda e: e.timestamp)
    progress(f"Running nsmkit detectors over {len(events):,} events")
    t0 = time.perf_counter()
    out = nsmkit.analyze(config=Config(), events=events)
    names = [batch.names.get(p, os.path.basename(p)) for p, _ in used]
    title = names[0] if len(names) == 1 else f"Network logs ({len(names)} files)"
    case = _new_case(NSM, title, [_source(p, batch.names.get(p, os.path.basename(p)), s)
                                  for p, s in used])
    summary = out["summary"]
    tr = summary.get("time_range") or {}
    span = lambda t: str(t or "?").replace("T", " ")  # noqa: E731
    case["subtitle"] = f"{summary['event_count']:,} events · {span(tr.get('start'))} → {span(tr.get('end'))}"
    _fill_nsm_findings(case, out["findings"], engine="nsmkit")
    case["verdict"] = _severity_verdict(case["findings"])
    case["notes"].extend(notes)
    case["sections"] = _nsm_sections(out)
    case["exports"] += ["snort"]
    case["native"] = jsonable({"summary": summary, "vpn_pivots": out["vpn_pivots"],
                               "incidents": [i.to_dict() for i in out["incidents"]],
                               "findings": [f.to_dict() for f in out["findings"]]})
    case["_export"] = {"nsm_findings": [f.to_dict() for f in out["findings"]]}
    case["elapsed_ms"] = int((time.perf_counter() - t0) * 1000)
    return [case]


def _fill_nsm_findings(case: dict, findings, engine: str) -> None:
    seen = {(i["type"], i["raw"].lower()) for i in case["iocs"]}
    for f in sorted(findings, key=lambda f: (-f.severity_rank, f.rule_id)):
        evidence = [f"{k}: {_fmt(v)}" for k, v in f.metrics.items()
                    if v not in (None, "", [], {})]
        evidence += [ln[:300] for ln in f.evidence[:6]]
        case["findings"].append({
            "rule_id": f.rule_id, "title": f.title, "severity": f.severity,
            "confidence": f.confidence, "category": f.kill_chain or "",
            "description": f.description, "evidence": evidence,
            "recommendation": f.recommendation, "mitre": list(f.mitre),
            "when": _dt(f.first_seen), "engine": engine})
        for role, ip, attacker in (("source", f.src_ip, f.rule_id.startswith(_NSM_ATTACKER_SRC)),
                                   ("destination", f.dst_ip, f.rule_id.startswith(_NSM_ATTACKER_DST))):
            if ip and netaddr.parse(ip):
                public = netaddr.is_public(ip)
                _add_ioc(case["iocs"], seen, "ip", ip, f"{f.rule_id} {role}", attacker and public)
        dom = f.metrics.get("domain") if isinstance(f.metrics, dict) else None
        if dom:
            _add_ioc(case["iocs"], seen, "domain", dom, f"{f.rule_id}", True)
        if f.rule_id == "NSM-EXFIL-003" and f.entity and not netaddr.parse(f.entity):
            _add_ioc(case["iocs"], seen, "domain", f.entity, f"{f.rule_id} upload destination", True)
        if f.user:
            _add_ioc(case["iocs"], seen, "account", f.user, f.rule_id, False, defang=False)
        mac = f.metrics.get("mac") if isinstance(f.metrics, dict) else None
        for m in [mac] + list(f.metrics.get("suspect_macs", []) if isinstance(f.metrics, dict) else []):
            if m:
                _add_ioc(case["iocs"], seen, "mac", m, f.rule_id, False, defang=False)


def _nsm_sections(out: dict) -> list[dict]:
    s = out["summary"]
    tr = s.get("time_range") or {}
    sections = [{"kind": "kv", "title": "Overview", "items": [
        ["Events", f"{s.get('event_count', 0):,}"],
        ["Window", f"{tr.get('start', '?')} → {tr.get('end', '?')}"],
        ["Sources", ", ".join(f"{k} ({v:,})" for k, v in s.get("by_source_type", {}).items())],
        ["Actions", ", ".join(f"{k} ({v:,})" for k, v in sorted(s.get("by_action", {}).items()))],
        ["External sources", f"{len(s.get('external_sources', [])):,}"],
    ]}]
    multi = [i for i in out["incidents"] if len(i.findings) > 1]
    if multi:
        sections.append({"kind": "table", "title": "Correlated incidents",
                         "columns": ["Incident", "Severity", "Kill chain", "Findings", "Entities"],
                         "rows": [[inc.incident_id, {"t": inc.severity, "sev": inc.severity},
                                   " → ".join(inc.stages), str(len(inc.findings)),
                                   {"t": ", ".join(sorted(inc.entities)[:8]), "mono": True}]
                                  for inc in multi[:15]],
                         "note": "Findings linked by a shared IP, account, domain or VPN address."})
    if out["vpn_pivots"]:
        sections.append({"kind": "table", "title": "VPN session pivots",
                         "columns": ["User", "From", "Assigned IP", "Login", "Internal targets", "Suspicious"],
                         "rows": [[p["user"], {"t": p["external_ip"], "mono": True},
                                   {"t": p["assigned_ip"], "mono": True}, p["login_time"],
                                   str(p["target_count"]),
                                   {"t": "yes" if p["suspicious"] else "no",
                                    "tone": "bad" if p["suspicious"] else "muted"}]
                                  for p in out["vpn_pivots"][:20]]})
    for key, title in (("top_blocked_sources", "Top blocked sources"),
                       ("top_auth_failure_sources", "Top authentication failures"),
                       ("top_ids_signatures", "Top IDS signatures"),
                       ("top_upload_pairs", "Largest upload pairs (bytes)")):
        rows = s.get(key) or []
        if rows:
            sections.append({"kind": "table", "title": title, "columns": ["Key", "Count"],
                             "rows": [[{"t": " → ".join(r["key"]) if isinstance(r["key"], list)
                                        else str(r["key"]), "mono": True}, f"{r['count']:,}"]
                                      for r in rows[:10]]})
    return sections


# ==========================================================================
# trafkit (+ nsmkit flow detectors on the same packets)
# ==========================================================================

# nsmkit detectors that add what trafkit does not have. Resolver/egress
# policy rules need a site profile, so they stay out of the drop-anything path.
_NSM_ON_PCAP = ("suspicious_port", "http_exfil", "volume_exfil", "ftp_exfil", "dns_spoof",
                "ssl_strip", "lateral_movement")


def _traf_cases(items, batch: Batch, progress: Progress) -> list[dict]:
    from trafkit.config import Config as TrafConfig
    from trafkit.detectors import AnalysisContext, run_detectors
    from trafkit.hosts import build_conversations, build_hosts
    from trafkit.pcapread import read_pcap

    path, s = items[0]
    display = batch.names.get(path, os.path.basename(path))
    progress(f"Reading packets from {display}")
    t0 = time.perf_counter()
    status: dict = {}
    packets = read_pcap(path, max_packets=MAX_PACKETS, status=status)
    damage = status.get("problem")
    if not packets:          # never let an unreadable capture read as "clean"
        raise RuntimeError(f"no packets could be read -- {damage}" if damage
                           else "the capture contains no packets")
    progress(f"Analysing {len(packets):,} packets")
    hosts = build_hosts(packets)
    convos = build_conversations(packets)
    findings = run_detectors(packets, AnalysisContext(hosts=hosts, conversations=convos), TrafConfig())

    case = _new_case(TRAF, display, [_source(path, display, s)])
    frame_ts = {p.frame_number: p.ts for p in packets}
    seen: set = set()
    for f in findings:
        evidence = [f"{k}: {_fmt(v)}" for k, v in f.evidence.items()
                    if v not in (None, "", [], {})]
        if f.frames:
            evidence.append("frames: " + ", ".join(str(n) for n in f.frames[:25]))
        tss = [frame_ts[n] for n in f.frames if n in frame_ts and frame_ts[n] > 0]
        case["findings"].append({
            "rule_id": f.rule_id, "title": f.title, "severity": f.severity,
            "confidence": f.confidence, "category": "", "description": f.description,
            "evidence": evidence, "recommendation": f.recommendation,
            "mitre": [f.mitre.split()[0]] if f.mitre else [], "mitre_label": f.mitre or "",
            "when": _utc(min(tss)) if tss else None, "engine": "trafkit"})
        _traf_iocs(case["iocs"], seen, f)

    progress("Running flow-level detectors (beaconing, exfiltration, spoofing)")
    try:
        nsm_findings = _nsm_on_capture(packets)
    except Exception as exc:  # noqa: BLE001
        nsm_findings = []
        case["notes"].append(f"flow-level detectors failed: {type(exc).__name__}: {exc}")
    _fill_nsm_findings(case, nsm_findings, engine="nsmkit")
    case["findings"].sort(key=lambda f: -SEV_RANK.get(f["severity"], 0))
    case["verdict"] = _severity_verdict(case["findings"])
    case["sections"] = _traf_sections(packets, hosts, convos)
    if damage:
        case["notes"].insert(0, f"The capture is damaged: {damage}. The analysis covers only the "
                                f"{len(packets):,} frame(s) read up to that point.")
        if case["verdict"]["level"] == "clean":
            case["verdict"]["summary"] = "No findings in the readable part of a damaged capture"
    if status.get("limited"):
        case["notes"].append(f"Only the first {MAX_PACKETS:,} packets were analysed.")
    summary = case["sections"][0]["items"]
    case["subtitle"] = f"{summary[0][1]} packets · {summary[2][1]}"
    case["exports"] += ["acl_iptables", "acl_cisco_ios", "acl_pf", "acl_netsh"]
    case["native"] = jsonable({"path": display, "findings": [f.to_dict() for f in findings],
                               "flow_findings": [f.to_dict() for f in nsm_findings]})
    case["_export"] = {"traf_findings": findings}
    case["elapsed_ms"] = int((time.perf_counter() - t0) * 1000)
    return [case]


def _nsm_on_capture(packets) -> list:
    import nsmkit
    from nsmkit.config import Config
    from nsmkit.pcap import events_from_packets
    events = events_from_packets(packets)
    cfg = Config()
    # Per-packet POST sizes, not per-request log lines: the 600-byte lab
    # threshold would flag every login form on a real capture.
    cfg.http_post_large_bytes = 64 * 1024
    # No site profile here, so learn the resolvers: whoever answers the bulk
    # of the capture's DNS. A rogue responder answers only what it targets.
    answers = Counter(e.src_ip for e in events if e.dns_is_response and e.src_ip)
    total = sum(answers.values())
    learned = {ip for ip, n in answers.items() if total and n >= 3 and n / total >= 0.3}
    cfg.known_resolvers = sorted(set(cfg.known_resolvers) | learned)
    found = nsmkit.run_detectors(events, cfg, only=_NSM_ON_PCAP)
    # Beaconing wants one event per connection attempt, not per packet.
    starts = [p for p in packets if p.fields.get("tcp.flags.syn") == 1 and p.fields.get("tcp.flags.ack") == 0]
    found += nsmkit.run_detectors(events_from_packets(starts), cfg, only=("beaconing",))
    return found


_TRAF_ATTACKER = ("src", "prober", "client")


def _traf_iocs(iocs: list[dict], seen: set, f) -> None:
    ev = f.evidence
    for key in _TRAF_ATTACKER:
        v = ev.get(key)
        if isinstance(v, str) and netaddr.parse(v):
            _add_ioc(iocs, seen, "ip", v, f"{f.rule_id} {key}",
                     netaddr.is_public(v) and f.severity in ("medium", "high", "critical"))
    if f.rule_id.startswith(("TUNNEL", "TLS")):
        v = ev.get("dst")
        if isinstance(v, str) and netaddr.is_public(v):
            _add_ioc(iocs, seen, "ip", v, f"{f.rule_id} destination", True)
    if ev.get("sni"):
        _add_ioc(iocs, seen, "domain", ev["sni"], f"{f.rule_id} TLS SNI", True)
    for q in ev.get("sample_queries", [])[:1]:
        from nsmkit.enrich import registered_domain
        dom = registered_domain(q)
        if dom:
            _add_ioc(iocs, seen, "domain", dom, f"{f.rule_id} tunnel domain", True)
    for key in ("attacker_mac", "mac"):
        if ev.get(key):
            _add_ioc(iocs, seen, "mac", ev[key], f.rule_id, False, defang=False)


def _mask(secret: Optional[str]) -> str:
    if not secret:
        return ""
    return secret[0] + "•" * min(8, max(3, len(secret) - 2)) + (secret[-1] if len(secret) > 2 else "")


def _traf_sections(packets, hosts, convos) -> list[dict]:
    from trafkit.detectors.cleartext import extract_credentials
    from trafkit.detectors.hostid import identify_hosts_and_users
    from trafkit.detectors.tls import tls_handshakes
    from trafkit.extract import extract_files
    from trafkit.hosts import resolved_addresses
    from trafkit.statistics import capture_summary, dns_stats, http_stats

    s = capture_summary(packets)
    first = packets[0].ts if packets else 0
    last = packets[-1].ts if packets else 0
    sections = [{"kind": "kv", "title": "Capture", "items": [
        ["Packets", f"{s.get('packet_count', 0):,}"],
        ["Bytes", _human_bytes(s.get("total_bytes", 0))],
        ["Duration", f"{s.get('duration_seconds', 0):,}s"],
        ["First packet", _utc(first) or "—"],
        ["Last packet", _utc(last) or "—"],
        ["Hosts", f"{len(hosts):,}"],
    ]}]
    hier = s.get("protocol_hierarchy") or {}
    if hier:
        n = s.get("packet_count", 1) or 1
        sections.append({"kind": "table", "title": "Protocol hierarchy", "columns": ["Protocol", "Packets", "%"],
                         "rows": [[k, f"{v:,}", f"{100 * v / n:.1f}"] for k, v in hier.items()]})
    top = sorted(hosts.values(), key=lambda h: h.bytes_sent + h.bytes_recv, reverse=True)[:25]
    if top:
        sections.append({"kind": "table", "title": "Hosts (by traffic)",
                         "columns": ["IP", "MAC", "Names", "OS guess", "Open ports", "Sent", "Received"],
                         "rows": [[{"t": h.ip, "mono": True}, {"t": ", ".join(sorted(h.macs))[:40], "mono": True},
                                   ", ".join(sorted(h.hostnames))[:60], h.os_guess or "—",
                                   ", ".join(str(p) for p in sorted(h.open_ports)[:12]) or "—",
                                   _human_bytes(h.bytes_sent), _human_bytes(h.bytes_recv)] for h in top]})
    if convos:
        sections.append({"kind": "table", "title": "Top conversations",
                         "columns": ["Proto", "A", "B", "Packets", "Bytes", "Duration"],
                         "rows": [[c.proto, {"t": f"{c.a_addr}:{c.a_port}", "mono": True},
                                   {"t": f"{c.b_addr}:{c.b_port}", "mono": True}, f"{c.packets:,}",
                                   _human_bytes(c.bytes),
                                   f"{(c.end or 0) - (c.start or 0):.1f}s"] for c in convos[:15]]})
    ids = identify_hosts_and_users(packets)
    items = [[f"DHCP {ip}", ", ".join(n)] for ip, n in ids["dhcp_hostnames"].items()]
    items += [[f"NBNS {ip}", ", ".join(n)] for ip, n in ids["nbns_hostnames"].items()]
    if ids["kerberos_users"]:
        items.append(["Kerberos users", ", ".join(ids["kerberos_users"])])
    if ids["kerberos_hosts"]:
        items.append(["Kerberos hosts", ", ".join(ids["kerberos_hosts"])])
    if items:
        sections.append({"kind": "kv", "title": "Host & user identification", "items": items})
    creds = extract_credentials(packets)
    if creds:
        sections.append({"kind": "table", "title": f"Cleartext credentials ({len(creds)})",
                         "columns": ["Frame", "Protocol", "From → To", "User", "Secret"],
                         "rows": [[str(c.frame), c.protocol, {"t": f"{c.src} → {c.dst}", "mono": True},
                                   c.username or "", {"t": _mask(c.secret), "secret": c.secret or "",
                                                      "mono": True}] for c in creds[:100]],
                         "note": "Secrets are masked; click one to reveal it."})
    files = extract_files(packets)
    if files:
        sections.append({"kind": "table", "title": "Files transferred (HTTP)",
                         "columns": ["Frame", "File", "Type", "Server → client"],
                         "rows": [[str(a.frame), {"t": a.detail["filename"], "mono": True},
                                   a.detail["content_type"], f"{a.detail['src']} → {a.detail['dst']}"]
                                  for a in files[:50]]})
    ds = dns_stats(packets)
    if ds.total_queries:
        sections.append({"kind": "table", "title": f"DNS ({ds.total_queries:,} queries, {ds.nxdomain:,} NXDOMAIN)",
                         "columns": ["Name", "Queries"],
                         "rows": [[{"t": n, "mono": True}, str(c)] for n, c in ds.top_queried]})
    resolved = resolved_addresses(packets)
    if resolved:
        sections.append({"kind": "table", "title": "Resolved addresses", "columns": ["Address", "Names"],
                         "rows": [[{"t": ip, "mono": True}, ", ".join(sorted(n))]
                                  for ip, n in list(resolved.items())[:40]]})
    hs = http_stats(packets)
    if hs.total_requests:
        rows = [[{"t": h, "mono": True}, str(c)] for h, c in hs.top_hosts]
        sections.append({"kind": "table", "title": f"HTTP ({hs.total_requests:,} requests)",
                         "columns": ["Host", "Requests"], "rows": rows})
        if hs.user_agents:
            sections.append({"kind": "table", "title": "HTTP user agents", "columns": ["User agent", "Requests"],
                             "rows": [[{"t": ua, "mono": True}, str(c)] for ua, c in hs.user_agents]})
    tls = [h for h in tls_handshakes(packets) if h["type"] == "ClientHello"]
    if tls:
        sni = Counter((h["sni"] or "(none)", h["port"]) for h in tls)
        sections.append({"kind": "table", "title": "TLS client hellos", "columns": ["SNI", "Port", "Count"],
                         "rows": [[{"t": n, "mono": True}, str(p), str(c)] for (n, p), c in sni.most_common(30)]})
    return sections


# ==========================================================================
# Samples
# ==========================================================================

def sample_paths(kit: str = "all") -> list[str]:
    root = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")
    kits = [PHISH, EVTX, NSM, TRAF] if kit == "all" else [kit]
    out = []
    for k in kits:
        d = os.path.join(root, k)
        if os.path.isdir(d):
            out += [os.path.join(d, f) for f in sorted(os.listdir(d))]
    return out
