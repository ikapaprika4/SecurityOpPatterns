"""
nsmkit -- a network security monitoring analysis toolkit.

Pipeline:  parse -> normalise -> enrich -> detect -> correlate -> report

    from nsmkit import analyze
    result = analyze(["firewall.log", "ids_alerts.log", "vpn_auth.log"])
    for f in result["findings"]:
        print(f.severity, f.title)
"""

from __future__ import annotations

from typing import Any, Sequence

from .config import Config, DEFAULT_CONFIG
from .correlate import Incident, correlate, summarise, vpn_pivots
from .detectors import REGISTRY
from .models import Action, Event, EventKind, Finding
from .parsers import read_file, read_files

__version__ = "1.0.0"

__all__ = [
    "Config", "DEFAULT_CONFIG", "Event", "EventKind", "Action", "Finding",
    "Incident", "read_file", "read_files", "correlate", "summarise",
    "vpn_pivots", "run_detectors", "analyze", "REGISTRY", "__version__",
]


def run_detectors(events: Sequence[Event],
                  config: Config | None = None,
                  only: Sequence[str] | None = None) -> list[Finding]:
    """Run every registered detector (or the named subset) over an event
    stream. A detector that raises is reported as an info finding and the
    rest still run -- the same isolation the CLI always had."""
    cfg = config or DEFAULT_CONFIG
    wanted = set(only) if only else None
    findings: list[Finding] = []
    for cls in REGISTRY:
        det = cls(cfg)
        if wanted and det.name not in wanted:
            continue
        try:
            findings.extend(det.run(events))
        except Exception as exc:  # noqa: BLE001
            findings.append(Finding(
                rule_id="NSM-ERR-001", title=f"Detector {det.name} failed", severity="info",
                confidence="low", description=f"{type(exc).__name__}: {exc}"))
    return findings


def analyze(paths: Sequence[str] | None = None,
            config: Config | None = None,
            only: Sequence[str] | None = None,
            events: Sequence[Event] | None = None) -> dict[str, Any]:
    """One-call pipeline: read files (or take already-parsed `events`),
    detect, correlate, summarise."""
    cfg = config or DEFAULT_CONFIG
    if events is None:
        events = read_files(paths or [])
    findings = run_detectors(events, cfg, only)
    return {
        "events": events,
        "findings": sorted(findings, key=lambda f: (-f.severity_rank, f.rule_id)),
        "incidents": correlate(findings, cfg),
        "summary": summarise(events, cfg),
        "vpn_pivots": vpn_pivots(events, cfg),
    }
