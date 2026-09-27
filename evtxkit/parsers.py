"""Event ingestion.

Sources, all normalised into the same `EventRecord` shape:

1. **Real `.evtx` files** -- Windows' on-disk format. On Windows this needs
   nothing extra: the built-in `wevtutil qe <file> /lf:true` renders every
   record as the same XML Event Viewer's "Details" tab shows, streamed and
   parsed incrementally so a large Security.evtx never sits in memory as one
   string. Elsewhere, the optional `python-evtx` package is used.
2. **Event XML** -- Event Viewer "Save All Events As... > XML", `wevtutil qe
   /f:xml` output, or a single <Event> document.
3. **JSON / JSON-Lines** -- one object per line or a JSON array, in any of
   the shapes real exports use: evtxkit's own normalised form
   (`{"EventID", "Channel", "TimeCreated", "Computer", "EventData"}`),
   Winlogbeat / Elastic ECS (`winlog.event_data`), `evtx_dump`
   (`Event.System` / `Event.EventData`), KAPE EvtxECmd (`Payload`), SIEM rows
   that carry the original XML (`_raw`, `event.original`), or flat rows with
   EventData fields at the top level.
4. **PowerShell history files** (`ConsoleHost_history.txt`) -- not a Windows
   *event* log at all, but the room material is explicit that it's an
   essential companion source. Parsed into the same `EventRecord` shape
   (`channel="PowerShellHistory"`, `event_id=EVT_POWERSHELL_HISTORY`) so
   every command-line-matching detector runs against it for free -- at the
   cost of the file's own real limitation: no per-command timestamps, so
   every entry gets `ts=0.0` and time-windowed correlation simply can't
   apply to it (documented, not silently wrong).

Timestamps without an explicit zone are taken as UTC -- Windows records
SystemTime in UTC, and guessing the analyst's local zone would shift every
correlation window by the machine's offset.
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator, Optional
from xml.etree import ElementTree as ET

from .models import EVT_POWERSHELL_HISTORY, EventRecord  # noqa: F401 (re-exported)

_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
_EVTX_MAGIC = b"ElfFile\x00"


class EventParseError(ValueError):
    """The input could not be read as Windows events; the message says why
    and what to do instead."""


# --------------------------------------------------------------------------
# Timestamps and channels
# --------------------------------------------------------------------------

_MS_DATE = re.compile(r"/Date\((-?\d+)(?:[+-]\d{4})?\)/")


def _parse_iso_ts(raw) -> float:
    """Epoch seconds (UTC) from the many ways exports write a time; 0.0 if none."""
    if raw is None or raw == "":
        return 0.0
    if isinstance(raw, dict):                       # {"#attributes": {"SystemTime": ...}}
        raw = (raw.get("#attributes") or {}).get("SystemTime") or raw.get("SystemTime") \
            or raw.get("value") or raw.get("DateTime") or ""
    if isinstance(raw, (int, float)):
        v = float(raw)
        return v / 1000.0 if v > 1e11 else v
    text = str(raw).strip()
    m = _MS_DATE.search(text)                        # PowerShell 5.1 ConvertTo-Json
    if m:
        return int(m.group(1)) / 1000.0
    if re.fullmatch(r"\d{9,13}(?:\.\d+)?", text):
        v = float(text)
        return v / 1000.0 if v > 1e11 else v
    # Windows writes 7 fractional digits; datetime accepts at most 6.
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p",
                    "%d/%m/%Y %H:%M:%S"):
            try:
                dt = datetime.strptime(str(raw).strip()[:len(fmt) + 4].strip(), fmt)
                break
            except ValueError:
                continue
        else:
            return 0.0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _norm_channel(channel: str) -> str:
    c = (channel or "").strip()
    low = c.lower()
    if "sysmon" in low:
        return "Sysmon"
    if low == "security":
        return "Security"
    if low == "system":
        return "System"
    if low in ("microsoft-windows-powershell/operational", "powershellcore/operational"):
        return "PowerShell"
    return c


# --------------------------------------------------------------------------
# XML
# --------------------------------------------------------------------------

def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _find(parent, tag: str):
    """Namespaced-then-bare find, without the classic ElementTree trap:
    `elem_a or elem_b` is wrong here because an Element with no child
    elements (e.g. `<EventID>4625</EventID>`, all text, no children) is
    falsy under `bool()` even though `find` genuinely found it -- so an
    `or`-chain would silently discard a real match and fall through to the
    bare-tag lookup. Explicit `is not None` checks avoid that."""
    found = parent.find(f"e:{tag}", _NS)
    if found is not None:
        return found
    return parent.find(tag)


def _findall(parent, tag: str):
    found = parent.findall(f"e:{tag}", _NS)
    if found:
        return found
    return parent.findall(tag)


def _element_to_record(root, index: int, raw: str = "") -> Optional[EventRecord]:
    system = _find(root, "System")
    if system is None:
        return None
    eid_el = _find(system, "EventID")
    try:
        event_id = int((eid_el.text or "0").strip()) if eid_el is not None and eid_el.text else 0
    except ValueError:
        event_id = 0
    channel_el = _find(system, "Channel")
    channel = _norm_channel(channel_el.text or "") if channel_el is not None else ""
    time_el = _find(system, "TimeCreated")
    ts = _parse_iso_ts(time_el.get("SystemTime", "")) if time_el is not None else 0.0
    computer_el = _find(system, "Computer")
    computer = (computer_el.text or "").strip() if computer_el is not None else ""
    provider_el = _find(system, "Provider")
    provider = provider_el.get("Name", "") if provider_el is not None else ""

    data: dict[str, str] = {}
    event_data = _find(root, "EventData")
    if event_data is not None:
        for i, d in enumerate(_findall(event_data, "Data")):
            name = d.get("Name")
            if name:
                data[name] = d.text or ""
            elif d.text:
                data[f"Data{i}"] = d.text            # classic events: unnamed values
    # UserData (1102 / 104 "log cleared", some Task Scheduler events) nests
    # its fields one level down in a provider-specific element.
    user_data = _find(root, "UserData")
    if user_data is not None:
        for container in user_data:
            for leaf in container:
                data.setdefault(_local(leaf.tag), leaf.text or "")

    record_el = _find(system, "EventRecordID")
    if record_el is not None and record_el.text:
        data.setdefault("EventRecordID", record_el.text.strip())
    exe_el = _find(system, "Execution")
    if exe_el is not None and exe_el.get("ProcessID"):
        data.setdefault("ExecutionProcessId", exe_el.get("ProcessID"))
    sec_el = _find(system, "Security")
    if sec_el is not None and sec_el.get("UserID"):
        data.setdefault("UserSid", sec_el.get("UserID"))

    return EventRecord(index=index, event_id=event_id, channel=channel or "Unknown",
                       ts=ts, computer=computer, data=data, raw=raw, provider=provider)


def _xml_to_event_record(xml_text: str, index: int) -> Optional[EventRecord]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    return _element_to_record(root, index, raw=xml_text)


def _iter_event_elements(chunks: Iterable) -> Iterator:
    """Incrementally parse <Events><Event/>...</Events> (or a lone <Event>)
    from byte or text chunks, yielding each finished <Event> element and
    dropping it from the tree so memory stays flat."""
    parser = ET.XMLPullParser(events=("start", "end"))
    root = None
    for chunk in chunks:
        parser.feed(chunk)
        for kind, elem in parser.read_events():
            if kind == "start":
                if root is None:
                    root = elem
                continue
            if _local(elem.tag) == "Event":
                yield elem
                if elem is not root:
                    try:
                        root.remove(elem)
                    except ValueError:
                        elem.clear()
    parser.close()


def _records_from_elements(elements: Iterable, source: str) -> list[EventRecord]:
    events: list[EventRecord] = []
    for elem in elements:
        rec = _element_to_record(elem, len(events))
        if rec is not None:
            rec.source = source
            events.append(rec)
    return events


def parse_xml_file(path: str) -> list[EventRecord]:
    """Event Viewer XML export / wevtutil XML / single-event XML."""
    def chunks():
        with open(path, "rb") as fh:
            while True:
                block = fh.read(1 << 16)
                if not block:
                    return
                yield block
    try:
        return _records_from_elements(_iter_event_elements(chunks()), path)
    except ET.ParseError as exc:
        raise EventParseError(f"{os.path.basename(path)} is not well-formed event XML: {exc}") from exc


# --------------------------------------------------------------------------
# .evtx
# --------------------------------------------------------------------------

def _evtx_via_wevtutil(path: str) -> list[EventRecord]:
    exe = shutil.which("wevtutil")
    if not exe:
        raise FileNotFoundError("wevtutil")
    cmd = [exe, "qe", os.path.abspath(path), "/lf:true", "/f:xml", "/e:Events", "/uni:true"]
    with tempfile.TemporaryFile() as err:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=err,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        reader = io.TextIOWrapper(proc.stdout, encoding="utf-16", errors="replace")
        try:
            events = _records_from_elements(
                _iter_event_elements(iter(lambda: reader.read(1 << 16), "")), path)
        except ET.ParseError:
            events = []
        finally:
            reader.close()
            rc = proc.wait()
        err.seek(0)
        message = err.read().decode("utf-16", "replace").strip()
    if rc != 0 and not events:
        raise EventParseError(f"wevtutil could not read {os.path.basename(path)}: "
                              f"{message.splitlines()[0] if message else f'exit code {rc}'}")
    return events


def _evtx_via_python_evtx(path: str) -> list[EventRecord]:
    from Evtx.Evtx import Evtx  # type: ignore

    events: list[EventRecord] = []
    with Evtx(path) as log:
        for record in log.records():
            rec = _xml_to_event_record(record.xml(), len(events))
            if rec is not None:
                rec.raw = ""
                rec.source = path
                events.append(rec)
    return events


def parse_evtx_file(path: str) -> list[EventRecord]:
    """Real binary .evtx ingestion: Windows' own wevtutil when available
    (no dependency), otherwise the optional `python-evtx` package."""
    if os.name == "nt" and shutil.which("wevtutil"):
        return _evtx_via_wevtutil(path)
    try:
        return _evtx_via_python_evtx(path)
    except ImportError as exc:
        raise EventParseError(
            "reading a .evtx file off Windows needs the optional 'python-evtx' package "
            "(pip install python-evtx). On Windows no install is needed -- the built-in "
            "wevtutil is used. Alternatively export the log as XML or JSON first."
        ) from exc


# --------------------------------------------------------------------------
# JSON shapes
# --------------------------------------------------------------------------

_ENVELOPE_KEYS = {
    "eventid", "event_id", "eventcode", "id", "channel", "logname", "log_name",
    "timecreated", "ts", "time", "@timestamp", "_time", "systemtime", "computer",
    "computername", "machinename", "hostname", "host", "eventdata", "event_data", "data",
    "message", "level", "keywords", "task", "opcode", "providername", "provider",
    "source", "sourcename", "recordid", "record_id", "eventrecordid", "_raw", "index",
    "sourcetype", "splunk_server", "linecount", "punct", "eventtype", "tag",
}


def _scalar(v) -> str:
    if v is None:
        return ""
    if isinstance(v, dict):
        return str(v.get("#text", v.get("value", "")) or "")
    if isinstance(v, list):
        return ", ".join(_scalar(x) for x in v)
    return str(v)


def _first(obj: dict, *keys: str):
    for k in keys:
        if k in obj and obj[k] not in (None, ""):
            return obj[k]
    lower = {str(k).lower(): v for k, v in obj.items()}
    for k in keys:
        v = lower.get(k.lower())
        if v not in (None, ""):
            return v
    return None


def _flatten_event_data(data) -> dict[str, str]:
    """EventData in its several JSON renderings -> {Name: value}."""
    if data is None:
        return {}
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except ValueError:
            return {"Data": data}
    if isinstance(data, dict) and "EventData" in data and isinstance(data["EventData"], (dict, list)):
        data = data["EventData"]
    if isinstance(data, dict) and "Data" in data and isinstance(data["Data"], (list, dict)):
        items = data["Data"] if isinstance(data["Data"], list) else [data["Data"]]
        out: dict[str, str] = {}
        for i, item in enumerate(items):
            if isinstance(item, dict):
                name = item.get("@Name") or item.get("Name") or item.get("name")
                value = item.get("#text", item.get("Value", item.get("value", item.get("text"))))
                out[str(name) if name else f"Data{i}"] = _scalar(value)
            else:
                out[f"Data{i}"] = _scalar(item)
        return out
    if isinstance(data, list):
        out = {}
        for i, item in enumerate(data):
            if isinstance(item, dict) and ("Name" in item or "@Name" in item):
                out[str(item.get("Name") or item.get("@Name"))] = _scalar(
                    item.get("Value", item.get("#text")))
            else:
                out[f"Data{i}"] = _scalar(item)
        return out
    if isinstance(data, dict):
        return {str(k): _scalar(v) for k, v in data.items() if not str(k).startswith("#")}
    return {}


def _record(event_id, channel, ts, computer, data, raw, provider="") -> EventRecord:
    try:
        eid = int(_scalar(event_id) or 0)
    except ValueError:
        eid = 0
    return EventRecord(index=0, event_id=eid, channel=_norm_channel(_scalar(channel)) or "Unknown",
                       ts=_parse_iso_ts(ts), computer=_scalar(computer), data=data, raw=raw,
                       provider=_scalar(provider))


def _record_from_obj(obj: Any, raw: str = "") -> Optional[EventRecord]:
    if not isinstance(obj, dict):
        return None

    # evtx_dump / xmltodict: {"Event": {"System": {...}, "EventData": {...}}}
    ev = obj.get("Event")
    if isinstance(ev, dict) and isinstance(ev.get("System"), dict):
        system = ev["System"]
        data = _flatten_event_data(ev.get("EventData"))
        user_data = ev.get("UserData")
        if isinstance(user_data, dict):
            for container in user_data.values():
                if isinstance(container, dict):
                    for k, v in container.items():
                        if not str(k).startswith("#"):
                            data.setdefault(str(k), _scalar(v))
        prov = system.get("Provider")
        prov_name = (prov.get("#attributes", prov) or {}).get("Name", "") if isinstance(prov, dict) else ""
        return _record(system.get("EventID"), system.get("Channel"), system.get("TimeCreated"),
                       system.get("Computer"), data, raw, prov_name)

    # SIEM rows that carry the original event XML
    for key in ("_raw", "Xml", "xml", "XML"):
        v = obj.get(key)
        if isinstance(v, str) and v.lstrip().startswith("<Event"):
            rec = _xml_to_event_record(v, 0)
            if rec is not None:
                rec.raw = raw
                return rec
    event_obj = obj.get("event")
    if isinstance(event_obj, dict) and isinstance(event_obj.get("original"), str) \
            and event_obj["original"].lstrip().startswith("<Event"):
        rec = _xml_to_event_record(event_obj["original"], 0)
        if rec is not None:
            return rec

    # Winlogbeat / Elastic Common Schema
    wl = obj.get("winlog")
    if isinstance(wl, dict):
        data = _flatten_event_data(wl.get("event_data"))
        if isinstance(wl.get("user_data"), dict):
            for k, v in wl["user_data"].items():
                data.setdefault(str(k), _scalar(v))
        host = obj.get("host") if isinstance(obj.get("host"), dict) else {}
        event_code = event_obj.get("code") if isinstance(event_obj, dict) else None
        pid = (wl.get("process") or {}).get("pid") if isinstance(wl.get("process"), dict) else None
        if pid is not None:
            data.setdefault("ExecutionProcessId", str(pid))
        if wl.get("record_id") is not None:
            data.setdefault("EventRecordID", str(wl["record_id"]))
        return _record(wl.get("event_id", event_code), wl.get("channel"), obj.get("@timestamp"),
                       wl.get("computer_name") or host.get("name"), data, raw,
                       wl.get("provider_name", ""))

    event_id = _first(obj, "EventID", "event_id", "EventId", "EventCode", "eventid", "Id")
    if event_id is None:
        return None
    # `Get-WinEvent | ConvertTo-Json` keeps values only by position -- say so
    # rather than silently producing events with no fields.
    if "Properties" in obj and isinstance(obj["Properties"], list) and "EventData" not in obj:
        raise EventParseError(
            "this looks like `Get-WinEvent | ConvertTo-Json` output, which stores event "
            "fields by position only (no names), so detectors cannot read them. Drop the "
            ".evtx file itself instead -- evtxkit reads it natively on Windows.")
    data_src = _first(obj, "EventData", "event_data", "data", "Payload")
    if data_src is not None:
        data = _flatten_event_data(data_src)
    else:   # flat export: EventData fields live at the top level
        data = {str(k): _scalar(v) for k, v in obj.items()
                if str(k).lower() not in _ENVELOPE_KEYS and not isinstance(v, (dict, list))}
    ts = _first(obj, "TimeCreated", "ts", "time", "@timestamp", "_time", "SystemTime", "UtcTime")
    return _record(event_id, _first(obj, "Channel", "channel", "LogName", "log_name"), ts,
                   _first(obj, "Computer", "computer", "MachineName", "ComputerName", "Hostname"),
                   data, raw, _first(obj, "ProviderName", "Provider") or "")


def parse_jsonl_line(line: str, index: int) -> Optional[EventRecord]:
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    rec = _record_from_obj(obj, raw=line)
    if rec is not None:
        rec.index = index
    return rec


def parse_json_file(path: str) -> list[EventRecord]:
    """JSON-Lines, a JSON array, or a single JSON object."""
    with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
        head = fh.read(2048)
        fh.seek(0)
        stripped = head.lstrip()
        events: list[EventRecord] = []
        if stripped.startswith("["):
            try:
                objs = json.load(fh)
            except json.JSONDecodeError as exc:
                raise EventParseError(f"{os.path.basename(path)}: invalid JSON array ({exc})") from exc
            for obj in objs if isinstance(objs, list) else [objs]:
                rec = _record_from_obj(obj, raw="")
                if rec is not None:
                    rec.index, rec.source = len(events), path
                    events.append(rec)
            return events
        for line in fh:
            rec = parse_jsonl_line(line, len(events))
            if rec is not None:
                rec.source = path
                events.append(rec)
        if not events and stripped.startswith("{"):
            fh.seek(0)                                   # one pretty-printed object
            try:
                rec = _record_from_obj(json.load(fh), raw="")
            except json.JSONDecodeError:
                rec = None
            if rec is not None:
                rec.source = path
                events.append(rec)
    return events


def parse_jsonl_file(path: str) -> list[EventRecord]:
    return parse_json_file(path)


# --------------------------------------------------------------------------
# PowerShell history
# --------------------------------------------------------------------------

_HISTORY_LINE_RE = re.compile(r"\S")


def parse_powershell_history(path: str, start_index: int = 0) -> list[EventRecord]:
    """ConsoleHost_history.txt -- one command per line, no timestamps (a
    real, stated limitation of this source: "does not log command
    outputs... " and carries no per-line time at all)."""
    events: list[EventRecord] = []
    idx = start_index
    with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
        for line in fh:
            if not _HISTORY_LINE_RE.search(line):
                continue
            cmd = line.rstrip("\n")
            events.append(EventRecord(
                index=idx, event_id=EVT_POWERSHELL_HISTORY, channel="PowerShellHistory",
                ts=0.0, data={"CommandLine": cmd, "Image": "powershell.exe"}, raw=cmd,
                source=path,
            ))
            idx += 1
    return events


# --------------------------------------------------------------------------
# Format detection + entry points
# --------------------------------------------------------------------------

def sniff_format(head: bytes, name: str = "") -> Optional[str]:
    """'evtx' | 'xml' | 'jsonl' | 'pshistory' | None from a file's first bytes."""
    low = name.lower()
    if head.startswith(_EVTX_MAGIC):
        return "evtx"
    if "consolehost_history" in low or low.endswith("_history.txt"):
        return "pshistory"
    text = head.lstrip(b"\xef\xbb\xbf \t\r\n")
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = head.decode("utf-16", "ignore").lstrip().encode("utf-8", "ignore")
    if text.startswith(b"<") and (b"<Event" in text[:4096]):
        return "xml"
    if text.startswith((b"{", b"[")):
        sample = text[:4096].lower()
        if any(k in sample for k in (b'"eventid"', b'"event_id"', b'"winlog"', b'"eventcode"',
                                     b'"eventrecordid"', b'"system"')):
            return "jsonl"
    return None


def detect_format(path: str) -> str:
    lower = path.lower()
    if lower.endswith(".evtx"):
        return "evtx"
    if "consolehost_history" in lower or lower.endswith("_history.txt"):
        return "pshistory"
    if lower.endswith(".xml"):
        return "xml"
    if lower.endswith((".json", ".jsonl", ".ndjson")):
        return "jsonl"
    try:
        with open(path, "rb") as fh:
            sniffed = sniff_format(fh.read(8192), path)
    except OSError:
        sniffed = None
    return sniffed or "jsonl"


def parse_event_file(path: str, format_hint: Optional[str] = None) -> list[EventRecord]:
    fmt = format_hint or detect_format(path)
    if fmt == "evtx":
        return parse_evtx_file(path)
    if fmt == "xml":
        return parse_xml_file(path)
    if fmt == "pshistory":
        return parse_powershell_history(path)
    return parse_json_file(path)


def parse_event_files(paths: Iterable[str]) -> list[EventRecord]:
    """Several sources as one stream (Security.evtx + Sysmon.evtx from one
    host correlate through Logon IDs and PIDs), re-indexed so every
    EventRecord.index is unique."""
    merged: list[EventRecord] = []
    for p in paths:
        for rec in parse_event_file(p):
            rec.index = len(merged)
            rec.source = rec.source or p
            merged.append(rec)
    return merged


def event_stats(events: list[EventRecord]) -> dict[str, Any]:
    """Counts and time range -- the `overview` numbers, reusable by reports."""
    by_id: dict[int, int] = {}
    by_channel: dict[str, int] = {}
    hosts: dict[str, int] = {}
    for e in events:
        by_id[e.event_id] = by_id.get(e.event_id, 0) + 1
        by_channel[e.channel] = by_channel.get(e.channel, 0) + 1
        if e.computer:
            hosts[e.computer] = hosts.get(e.computer, 0) + 1
    timed = [e.ts for e in events if e.ts > 0]
    return {
        "event_count": len(events),
        "by_event_id": dict(sorted(by_id.items(), key=lambda kv: -kv[1])),
        "by_channel": dict(sorted(by_channel.items(), key=lambda kv: -kv[1])),
        "hosts": dict(sorted(hosts.items(), key=lambda kv: -kv[1])),
        "first_ts": min(timed) if timed else None,
        "last_ts": max(timed) if timed else None,
        "untimed_events": len(events) - len(timed),
    }
