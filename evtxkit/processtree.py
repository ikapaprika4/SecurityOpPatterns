"""Process tree + logon correlation -- the two "join keys" the room
material leans on repeatedly: ProcessGuid/ParentProcessGuid to reconstruct
"what launched what" (Windows Threat Detection 1 & 3), and Logon ID to
answer "what did this specific login session do" across both Security and
Sysmon events (Windows Logging for SOC's own worked example: "Copy the
Logon ID field from the logon event... open Sysmon logs and search events
with the same Logon ID").

Keyed by ProcessGuid when available (globally unique, Sysmon-only) and
falls back to a `pid:<ProcessId>` string otherwise (Security log's 4688
has no GUID). The fallback is a real limitation worth stating rather than
hiding: PIDs are reused by the OS over time, so a `pid:` key can, in a
long-running log, collide across unrelated processes. Sysmon's GUID keying
doesn't have this problem, which is one more reason to prefer Sysmon over
bare 4688 (the room's own recommendation in Windows Logging for SOC).
"""

from __future__ import annotations

from collections import defaultdict

from .models import EventRecord, norm_logon_id


def _process_key(event: EventRecord) -> str:
    guid = event.process_guid
    if guid:
        return guid
    pid = event.process_id
    return f"pid:{pid}" if pid else f"idx:{event.index}"


def _parent_key(event: EventRecord) -> str:
    guid = event.parent_process_guid
    if guid:
        return guid
    pid = event.parent_process_id
    return f"pid:{pid}" if pid else ""


class ProcessTree:
    """Built once per analysis run from every process-creation event
    (Sysmon 1, and Security 4688 if present)."""

    def __init__(self, events: list[EventRecord]):
        self.by_key: dict[str, EventRecord] = {}
        self.children: dict[str, list[EventRecord]] = defaultdict(list)
        for e in events:
            if not e.is_process_create:
                continue
            key = _process_key(e)
            self.by_key[key] = e
            parent_key = _parent_key(e)
            if parent_key:
                self.children[parent_key].append(e)

    def parent_of(self, event: EventRecord) -> EventRecord | None:
        parent_key = _parent_key(event)
        return self.by_key.get(parent_key) if parent_key else None

    def children_of(self, event: EventRecord) -> list[EventRecord]:
        return self.children.get(_process_key(event), [])

    def ancestry(self, event: EventRecord, max_depth: int = 10) -> list[EventRecord]:
        """Immediate parent first, up to the root or max_depth."""
        chain = []
        current = event
        seen = set()
        for _ in range(max_depth):
            parent = self.parent_of(current)
            if parent is None or _process_key(parent) in seen:
                break
            chain.append(parent)
            seen.add(_process_key(parent))
            current = parent
        return chain

    def root_of(self, event: EventRecord) -> EventRecord:
        chain = self.ancestry(event)
        return chain[-1] if chain else event


def events_for_logon_id(events: list[EventRecord], logon_id: str) -> list[EventRecord]:
    """Every event whose session is `logon_id`. Compared in normalised form
    (Sysmon writes 0x3E7, Security 0x3e7; some exports use decimal)."""
    want = norm_logon_id(logon_id)
    if not want:
        return []
    return [e for e in events if e.logon_id == want]


def find_logon_event(events: list[EventRecord], logon_id: str, event_id: int = 4624) -> EventRecord | None:
    want = norm_logon_id(logon_id)
    for e in events:
        if e.event_id == event_id and norm_logon_id(e.get("TargetLogonId")) == want:
            return e
    return None
