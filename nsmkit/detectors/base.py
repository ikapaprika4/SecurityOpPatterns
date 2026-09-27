"""Detector base class and registry."""

from __future__ import annotations

from typing import Iterable, Sequence

from ..config import Config, DEFAULT_CONFIG
from ..models import Event, Finding


class Detector:
    """
    A detector consumes the full event list and yields Findings.

    Subclasses set `name` / `rule_prefix` and implement `run`. Detectors are
    deliberately stateless between runs so they can be applied to a live
    sliding window as easily as to a historical file.
    """

    name: str = "detector"
    rule_prefix: str = "NSM"
    description: str = ""

    def __init__(self, config: Config | None = None):
        self.cfg = config or DEFAULT_CONFIG

    def run(self, events: Sequence[Event]) -> list[Finding]:
        raise NotImplementedError

    # -- shared helpers -------------------------------------------------

    def _window_ok(self, first, last, window_s: int) -> bool:
        if first is None or last is None:
            return False
        return (last - first).total_seconds() <= window_s

    @staticmethod
    def _bounds(events: Iterable[Event]):
        ts = [e.timestamp for e in events if e.timestamp]
        return (min(ts), max(ts)) if ts else (None, None)

    def _attach(self, finding: Finding, events: Sequence[Event]) -> Finding:
        first, last = self._bounds(events)
        finding.first_seen = finding.first_seen or first
        finding.last_seen = finding.last_seen or last
        for ev in events[: self.cfg.max_evidence_lines]:
            finding.add_evidence(ev.raw)
        return finding


REGISTRY: list[type[Detector]] = []


def register(cls: type[Detector]) -> type[Detector]:
    """Class decorator that adds a detector to the default run set."""
    REGISTRY.append(cls)
    return cls
