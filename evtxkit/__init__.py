"""evtxkit -- Windows Security/Sysmon event log detection toolkit.

Reads real .evtx files (natively on Windows via wevtutil), Event Viewer XML
exports, JSON/JSON-Lines in the common SIEM shapes, or a PowerShell
ConsoleHost_history.txt, and runs every registered detector -- logon brute
force, backdoored users, persistence (services/tasks/startup/run-keys),
phishing/USB execution chains, discovery command sequences, collection/
credential-access/staging, ingress tool transfer / C2, log clearing and
obfuscated PowerShell -- covering the four-room Windows Logging / Windows
Threat Detection series this was built from.
"""

from __future__ import annotations

from typing import Iterable, Union

from .config import Config
from .detectors import run_detectors
from .models import AnalysisResult, EventRecord, Finding
from .parsers import event_stats, parse_event_file, parse_event_files
from .processtree import ProcessTree, events_for_logon_id, find_logon_event

__all__ = [
    "Config",
    "AnalysisResult",
    "EventRecord",
    "Finding",
    "ProcessTree",
    "analyze",
    "analyze_events",
    "events_for_logon_id",
    "find_logon_event",
]

__version__ = "1.1.0"


def analyze_events(events: list[EventRecord], config: Config | None = None,
                   path: str = "") -> AnalysisResult:
    """Run every registered detector over already-parsed events."""
    config = config or Config()
    findings = run_detectors(events, config)
    return AnalysisResult(path=path, events=events, findings=findings,
                          stats=event_stats(events))


def analyze(path: Union[str, Iterable[str]], config: Config | None = None,
            format_hint: str | None = None) -> AnalysisResult:
    """Top-level entry point: parse one event source -- or several from the
    same host, analysed as one stream -- and run every detector."""
    if isinstance(path, str):
        events = parse_event_file(path, format_hint=format_hint)
        return analyze_events(events, config, path)
    paths = list(path)
    return analyze_events(parse_event_files(paths), config, ", ".join(paths))
