"""
Log parsers.

Each parser is a callable ``(line: str) -> Event | None``. A parser returns
None when the line does not match its grammar; the auto-detector uses that to
score candidate parsers against a sample of the file.

Adding a source
---------------
1. Write a ``parse_<name>(line)`` function returning an Event or None.
2. Register it in ``PARSERS`` with a source_type key.
That is the whole extension surface -- detectors never touch raw text.
"""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timezone
from typing import Callable, Iterable, Iterator, Optional

from .models import Action, Event, EventKind, normalise_action

# --------------------------------------------------------------------------
# Timestamp handling
# --------------------------------------------------------------------------

_TS_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y/%m/%d %H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
    "%b %d, %Y @ %H:%M:%S.%f",   # Kibana CSV export
    "%b %d %H:%M:%S",            # syslog (year-less)
    "%m/%d-%H:%M:%S.%f",         # Snort native fast alert
    "%m/%d/%Y %H:%M:%S",
)


def parse_timestamp(value: str, default_year: int | None = None) -> Optional[datetime]:
    """Best-effort timestamp parsing across the formats NSM sources emit."""
    if value is None:
        return None
    v = str(value).strip().strip('"')
    if not v:
        return None

    # Epoch seconds / milliseconds
    if re.fullmatch(r"\d{9,13}(\.\d+)?", v):
        num = float(v)
        if num > 1e11:            # milliseconds
            num /= 1000.0
        return datetime.fromtimestamp(num, tz=timezone.utc).replace(tzinfo=None)

    # ISO with explicit offset
    try:
        iso = v.replace("Z", "+00:00")
        dt = datetime.fromisoformat(iso)
        return dt.replace(tzinfo=None) if dt.tzinfo else dt
    except ValueError:
        pass

    for fmt in _TS_FORMATS:
        try:
            dt = datetime.strptime(v, fmt)
        except ValueError:
            continue
        if dt.year == 1900:       # year-less format
            dt = dt.replace(year=default_year or datetime.now().year)
        return dt
    return None


def _to_int(value) -> Optional[int]:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _split_hostport(token: str) -> tuple[Optional[str], Optional[int]]:
    """'10.0.0.5:445' -> ('10.0.0.5', 445); IPv6 aware; bare IP tolerated."""
    t = token.strip().rstrip(",;")
    if not t:
        return None, None
    if t.startswith("["):                       # [::1]:443
        host, _, port = t.rpartition("]:")
        return host.lstrip("["), _to_int(port)
    if t.count(":") == 1:
        host, _, port = t.rpartition(":")
        return host, _to_int(port)
    return t, None                              # bare IPv4 or IPv6


# --------------------------------------------------------------------------
# 1. Perimeter firewall  (THM / generic appliance text format)
#    2025-08-25 00:47:46 ALLOW TCP 203.0.113.100:62718 -> 10.0.0.50:443
# --------------------------------------------------------------------------

_FW_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+"
    r"(?P<action>ALLOW|BLOCK|DENY|DROP|REJECT|ACCEPT|PERMIT|PASS)\s+"
    r"(?P<proto>TCP|UDP|ICMP|GRE|ESP|IP)\s+"
    r"(?P<src>\S+?)\s*->\s*(?P<dst>\S+)"
    r"(?:\s+bytes=(?P<bytes>\d+))?",
    re.IGNORECASE,
)


def parse_firewall(line: str) -> Optional[Event]:
    m = _FW_RE.match(line.strip())
    if not m:
        return None
    src_ip, src_port = _split_hostport(m.group("src"))
    dst_ip, dst_port = _split_hostport(m.group("dst"))
    return Event(
        timestamp=parse_timestamp(m.group("ts")),
        kind=EventKind.NETWORK_FLOW,
        action=normalise_action(m.group("action")),
        source_type="firewall",
        raw=line.rstrip("\n"),
        src_ip=src_ip, src_port=src_port,
        dst_ip=dst_ip, dst_port=dst_port,
        protocol=m.group("proto").lower(),
        bytes_out=_to_int(m.group("bytes")) or 0,
    )


# --------------------------------------------------------------------------
# 2. Snort / Suricata fast alert
#    2025-08-25 00:12:53 [**] [1:2003272:1] ET POLICY Suspicious HTTP [**]
#      [Classification: Suspicious Activity] [Priority: 3] {TCP} 1.2.3.4:20127 -> 10.0.0.20:22
#    07/24-10:46:52.401504 [**] [1:1000001:1] "Ping" [**] [Priority: 0] {ICMP} 127.0.0.1 -> 127.0.0.1
# --------------------------------------------------------------------------

_IDS_RE = re.compile(
    r"^(?P<ts>\S+(?:[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)?)\s+"
    r"\[\*\*\]\s*\[(?P<sid>[\d:]+)\]\s*(?P<msg>.*?)\s*\[\*\*\]"
    r"(?:\s*\[Classification:\s*(?P<cls>[^\]]*)\])?"
    r"(?:\s*\[Priority:\s*(?P<pri>\d+)\])?"
    r"(?:\s*\{(?P<proto>\w+)\})?"
    r"\s*(?P<src>\S+?)\s*->\s*(?P<dst>\S+)\s*$"
)


def parse_ids_alert(line: str) -> Optional[Event]:
    m = _IDS_RE.match(line.strip())
    if not m:
        return None
    src_ip, src_port = _split_hostport(m.group("src"))
    dst_ip, dst_port = _split_hostport(m.group("dst"))
    proto = m.group("proto")
    return Event(
        timestamp=parse_timestamp(m.group("ts")),
        kind=EventKind.IDS_ALERT,
        action=Action.ALERT,
        source_type="ids",
        raw=line.rstrip("\n"),
        src_ip=src_ip, src_port=src_port,
        dst_ip=dst_ip, dst_port=dst_port,
        protocol=proto.lower() if proto else None,
        signature=(m.group("msg") or "").strip().strip('"'),
        sid=m.group("sid"),
        classification=(m.group("cls") or "").strip() or None,
        priority=_to_int(m.group("pri")),
    )


# --------------------------------------------------------------------------
# 3. VPN authentication
#    2025-08-25 08:25:10 203.0.113.100 svc_backup SUCCESS assigned_ip=10.8.0.131
#    2025-09-03 02:19:00 203.0.113.10 svc_backup FAIL
# --------------------------------------------------------------------------

_VPN_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+"
    r"(?P<ip>[0-9a-fA-F\.:]+)\s+"
    r"(?P<user>\S+)\s+"
    r"(?P<result>SUCCESS|FAIL|FAILED|FAILURE|SUCCESS_AUTH|FAILED_AUTH|DENIED)"
    r"(?:\s+assigned_ip=(?P<assigned>[0-9a-fA-F\.:]+))?",
    re.IGNORECASE,
)

# Alternative appliance style seen in the perimeter room:
#   2025-09-22 10:12:11 FAILED_AUTH TCP 1.2.3.4:31245 -> 10.0.0.1:443 (user 'admin')
_VPN_ALT_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\s+"
    r"(?P<result>SUCCESS_AUTH|FAILED_AUTH)\s+(?P<proto>\w+)\s+"
    r"(?P<src>\S+?)\s*->\s*(?P<dst>\S+?)\s+\(user\s+'(?P<user>[^']*)'\)",
    re.IGNORECASE,
)


def parse_vpn_auth(line: str) -> Optional[Event]:
    s = line.strip()
    m = _VPN_RE.match(s)
    if m:
        return Event(
            timestamp=parse_timestamp(m.group("ts")),
            kind=EventKind.AUTH,
            action=normalise_action(m.group("result")),
            source_type="vpn",
            raw=s,
            src_ip=m.group("ip"),
            user=m.group("user"),
            assigned_ip=m.group("assigned"),
            extra={"service": "vpn"},
        )
    m = _VPN_ALT_RE.match(s)
    if m:
        src_ip, src_port = _split_hostport(m.group("src"))
        dst_ip, dst_port = _split_hostport(m.group("dst"))
        return Event(
            timestamp=parse_timestamp(m.group("ts")),
            kind=EventKind.AUTH,
            action=normalise_action(m.group("result")),
            source_type="vpn",
            raw=s,
            src_ip=src_ip, src_port=src_port,
            dst_ip=dst_ip, dst_port=dst_port,
            protocol=m.group("proto").lower(),
            user=m.group("user"),
            extra={"service": "vpn"},
        )
    return None


# --------------------------------------------------------------------------
# 4. WAF / key=value logs
#    timestamp=2025-09-22T09:14:46Z src_ip=1.2.3.4 action=BLOCK
#      request="GET /search.php?q=<script>" rule_id=941100 attack_type="XSS"
# --------------------------------------------------------------------------

_KV_RE = re.compile(r'(\w[\w\.\-]*)=("([^"]*)"|\'([^\']*)\'|\S+)')


def parse_kv(line: str) -> Optional[Event]:
    s = line.strip()
    if "=" not in s:
        return None
    pairs: dict[str, str] = {}
    for m in _KV_RE.finditer(s):
        key = m.group(1).lower()
        val = m.group(3) if m.group(3) is not None else (
            m.group(4) if m.group(4) is not None else m.group(2))
        pairs[key] = val
    if len(pairs) < 2:
        return None

    ts = None
    for k in ("timestamp", "time", "ts", "@timestamp", "date"):
        if k in pairs:
            ts = parse_timestamp(pairs[k])
            if ts:
                break
    if ts is None:
        return None

    src_ip = pairs.get("src_ip") or pairs.get("source_ip") or pairs.get("client_ip") or pairs.get("srcip")
    dst_ip = pairs.get("dst_ip") or pairs.get("dest_ip") or pairs.get("destination_ip") or pairs.get("dstip")

    request = pairs.get("request") or pairs.get("uri") or ""
    method, uri = None, request or None
    if request:
        parts = request.split(None, 1)
        if len(parts) == 2 and parts[0].isupper():
            method, uri = parts[0], parts[1]
    method = pairs.get("method", method)

    kind = EventKind.HTTP if (method or uri or "attack_type" in pairs) else EventKind.OTHER
    return Event(
        timestamp=ts,
        kind=kind,
        action=normalise_action(pairs.get("action")),
        source_type="waf" if "attack_type" in pairs or "rule_id" in pairs else "kv",
        raw=s,
        src_ip=src_ip,
        src_port=_to_int(pairs.get("src_port")),
        dst_ip=dst_ip,
        dst_port=_to_int(pairs.get("dst_port") or pairs.get("dest_port")),
        protocol=(pairs.get("proto") or pairs.get("protocol") or "").lower() or None,
        bytes_out=_to_int(pairs.get("bytes_sent") or pairs.get("bytes_out") or pairs.get("bytes")) or 0,
        bytes_in=_to_int(pairs.get("bytes_received") or pairs.get("bytes_in")) or 0,
        user=pairs.get("user") or pairs.get("username"),
        signature=pairs.get("attack_type") or pairs.get("msg"),
        sid=pairs.get("rule_id") or pairs.get("sid"),
        http_method=method,
        http_uri=uri,
        http_host=pairs.get("domain") or pairs.get("host") or pairs.get("hostname"),
        http_status=_to_int(pairs.get("status") or pairs.get("status_code")),
        user_agent=pairs.get("user_agent") or pairs.get("useragent"),
        dns_query=pairs.get("query") or pairs.get("dns_query"),
        dns_qtype=pairs.get("qtype") or pairs.get("query_type"),
        extra={k: v for k, v in pairs.items() if k not in {"timestamp", "src_ip", "dst_ip", "action"}},
    )


# --------------------------------------------------------------------------
# 5. JSON lines (Zeek JSON, Suricata EVE, generic SIEM export)
# --------------------------------------------------------------------------

_JSON_FIELD_MAP = {
    "src_ip": ("src_ip", "source.ip", "id.orig_h", "id_orig_h", "srcip", "client_ip"),
    "src_port": ("src_port", "source.port", "id.orig_p", "id_orig_p"),
    "dst_ip": ("dst_ip", "dest_ip", "destination.ip", "id.resp_h", "id_resp_h", "dstip"),
    "dst_port": ("dst_port", "dest_port", "destination.port", "id.resp_p", "id_resp_p"),
    "protocol": ("proto", "protocol", "network.protocol", "network.transport"),
    "bytes_out": ("orig_ip_bytes", "orig_bytes", "bytes_sent", "source.bytes", "bytes_toserver"),
    "bytes_in": ("resp_ip_bytes", "resp_bytes", "bytes_received", "destination.bytes", "bytes_toclient"),
    "packets": ("orig_pkts", "packets"),
    "duration": ("duration",),
    "user": ("user", "username", "user.name"),
    "dns_query": ("query", "dns.rrname", "dns_query"),
    "dns_qtype": ("qtype_name", "dns.rrtype", "qtype"),
    "dns_rcode": ("rcode_name", "dns.rcode", "rcode"),
    "http_method": ("method", "http.method", "http_method"),
    "http_uri": ("uri", "http.url", "url"),
    "http_host": ("host", "http.hostname", "domain", "server_name"),
    "http_status": ("status_code", "http.status", "status"),
    "user_agent": ("user_agent", "http.http_user_agent"),
    "signature": ("alert.signature", "signature", "msg"),
    "sid": ("alert.signature_id", "sid", "rule_id"),
    "priority": ("alert.severity", "priority"),
    "classification": ("alert.category", "classification"),
}


def _dig(obj: dict, dotted: str):
    cur = obj
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _first(obj: dict, keys: tuple[str, ...]):
    for k in keys:
        v = obj.get(k) if k in obj else _dig(obj, k)
        if v not in (None, "", "-"):
            return v
    return None


def event_from_dict(obj: dict, raw: str = "", source_type: str = "json") -> Optional[Event]:
    """Build an Event from an already-decoded record (JSON line, CSV row, ...)."""
    ts = None
    for key in ("@timestamp", "timestamp", "ts", "time", "_time", "event_time", "date"):
        if key in obj and obj[key] not in (None, ""):
            ts = parse_timestamp(obj[key])
            if ts:
                break
    if ts is None:
        return None

    vals = {field: _first(obj, keys) for field, keys in _JSON_FIELD_MAP.items()}

    kind = EventKind.OTHER
    if vals["signature"]:
        kind = EventKind.IDS_ALERT
    elif vals["dns_query"]:
        kind = EventKind.DNS
    elif vals["http_method"] or vals["http_uri"]:
        kind = EventKind.HTTP
    elif vals["user"] and _first(obj, ("action", "result", "status")):
        kind = EventKind.AUTH
    elif vals["src_ip"] and vals["dst_ip"]:
        kind = EventKind.NETWORK_FLOW

    action_raw = _first(obj, ("action", "rule.action", "result", "status", "conn_state", "event_type"))
    return Event(
        timestamp=ts,
        kind=kind,
        action=normalise_action(action_raw if isinstance(action_raw, str) else None),
        source_type=source_type,
        raw=raw or json.dumps(obj)[:2000],
        src_ip=vals["src_ip"], src_port=_to_int(vals["src_port"]),
        dst_ip=vals["dst_ip"], dst_port=_to_int(vals["dst_port"]),
        protocol=str(vals["protocol"]).lower() if vals["protocol"] else None,
        bytes_out=_to_int(vals["bytes_out"]) or 0,
        bytes_in=_to_int(vals["bytes_in"]) or 0,
        packets=_to_int(vals["packets"]) or 0,
        duration=float(vals["duration"]) if vals["duration"] not in (None, "") else 0.0,
        user=vals["user"],
        signature=vals["signature"], sid=str(vals["sid"]) if vals["sid"] else None,
        classification=vals["classification"], priority=_to_int(vals["priority"]),
        dns_query=vals["dns_query"], dns_qtype=vals["dns_qtype"], dns_rcode=vals["dns_rcode"],
        http_method=vals["http_method"], http_uri=vals["http_uri"],
        http_host=vals["http_host"], http_status=_to_int(vals["http_status"]),
        user_agent=vals["user_agent"],
        extra={"conn_state": obj.get("conn_state")} if obj.get("conn_state") else {},
    )


def parse_json_line(line: str) -> Optional[Event]:
    s = line.strip()
    if not s.startswith("{"):
        return None
    try:
        obj = json.loads(s)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None
    # Flatten Suricata EVE nested alert/dns/http objects one level.
    flat = dict(obj)
    for nested in ("alert", "dns", "http", "flow", "tls"):
        if isinstance(obj.get(nested), dict):
            for k, v in obj[nested].items():
                flat.setdefault(f"{nested}.{k}", v)
                flat.setdefault(k, v)
    return event_from_dict(flat, raw=s, source_type="json")


# --------------------------------------------------------------------------
# Parser registry + auto-detection
# --------------------------------------------------------------------------

PARSERS: dict[str, Callable[[str], Optional[Event]]] = {
    "firewall": parse_firewall,
    "ids": parse_ids_alert,
    "vpn": parse_vpn_auth,
    "json": parse_json_line,
    "kv": parse_kv,
}

# Order matters: most specific grammar first, greediest (kv) last.
_DETECT_ORDER = ["ids", "firewall", "vpn", "json", "kv"]


def detect_parser(sample_lines: Iterable[str]) -> tuple[str, Callable[[str], Optional[Event]]]:
    """Score each parser over a sample and return the best fit."""
    sample = [ln for ln in sample_lines if ln.strip()][:200]
    best_name, best_score = "kv", 0.0
    for name in _DETECT_ORDER:
        fn = PARSERS[name]
        hits = sum(1 for ln in sample if fn(ln) is not None)
        score = hits / len(sample) if sample else 0.0
        if score > best_score + 1e-9:
            best_name, best_score = name, score
        if best_score >= 0.9:
            break
    return best_name, PARSERS[best_name]


# --------------------------------------------------------------------------
# CSV
# --------------------------------------------------------------------------

def parse_csv(path: str, source_type: str = "csv") -> Iterator[Event]:
    """
    Parse a CSV/TSV export (Kibana, Splunk, Zeek). Rows whose `message` column
    holds a JSON blob (the Kibana Zeek export) are merged into the row dict so
    the connection detail is not lost.
    """
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        head = fh.read(8192)
        fh.seek(0)
        try:
            dialect = csv.Sniffer().sniff(head, delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
        for row in csv.DictReader(fh, dialect=dialect):
            clean = {(k or "").strip().lstrip("﻿"): (v.strip() if isinstance(v, str) else v)
                     for k, v in row.items() if k}
            msg = clean.get("message") or clean.get("_raw") or ""
            if isinstance(msg, str) and msg.strip().startswith("{"):
                try:
                    for k, v in json.loads(msg).items():
                        clean.setdefault(k, v)
                except json.JSONDecodeError:
                    pass
            ev = event_from_dict(clean, raw=json.dumps(clean)[:2000], source_type=source_type)
            if ev:
                yield ev


# --------------------------------------------------------------------------
# Top-level file reader
# --------------------------------------------------------------------------

def read_file(path: str, parser: str | None = None) -> list[Event]:
    """
    Read one log file into Events. `parser` forces a grammar; otherwise the
    format is auto-detected from the first 200 non-blank lines.
    """
    if path.lower().endswith((".csv", ".tsv")):
        return list(parse_csv(path))
    if path.lower().endswith((".pcap", ".pcapng")):
        from .pcap import read_pcap
        return read_pcap(path)

    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()

    if parser:
        fn = PARSERS[parser]
        name = parser
    else:
        name, fn = detect_parser(lines)

    events: list[Event] = []
    for ln in lines:
        if not ln.strip():
            continue
        ev = fn(ln)
        if ev is None:
            # Fall back across the registry so mixed files still parse.
            for alt_name in _DETECT_ORDER:
                if alt_name == name:
                    continue
                ev = PARSERS[alt_name](ln)
                if ev is not None:
                    break
        if ev is not None and ev.timestamp is not None:
            events.append(ev)
    events.sort(key=lambda e: e.timestamp)
    return events


def read_files(paths: Iterable[str]) -> list[Event]:
    """Read many files and return one time-ordered event stream."""
    all_events: list[Event] = []
    for p in paths:
        all_events.extend(read_file(p))
    all_events.sort(key=lambda e: e.timestamp)
    return all_events
