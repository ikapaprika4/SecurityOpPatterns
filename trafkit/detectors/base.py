"""Detector base class + registry -- same pattern as nsmkit/phishkit so a new
rule is always: subclass, decorate, done. Every detector runs inside a
try/except at the call site (see `run_detectors`) so one broken rule can't
take the rest of the run down with it."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..config import Config
from ..models import Finding, PacketRecord

REGISTRY: list[type["Detector"]] = []


def register(cls):
    REGISTRY.append(cls)
    return cls


class Detector(ABC):
    id: str = "UNSET"
    title: str = ""

    def __init__(self, cfg: Config):
        self.cfg = cfg

    @abstractmethod
    def run(self, packets: list[PacketRecord], ctx: "AnalysisContext") -> list[Finding]:
        ...

    def _finding(self, **kwargs) -> Finding:
        kwargs.setdefault("rule_id", self.id)
        kwargs.setdefault("title", self.title)
        return Finding(**kwargs)


class AnalysisContext:
    """Shared, precomputed context every detector can read without
    recomputing it -- hosts/conversations are expensive-ish to build and
    every scan/ARP/lateral-movement detector wants them."""

    def __init__(self, hosts: dict, conversations: list):
        self.hosts = hosts
        self.conversations = conversations


def run_detectors(packets: list[PacketRecord], ctx: AnalysisContext, cfg: Config) -> list[Finding]:
    findings: list[Finding] = []
    for det_cls in REGISTRY:
        det = det_cls(cfg)
        try:
            findings.extend(det.run(packets, ctx))
        except Exception as e:  # noqa: BLE001 -- isolation by design
            findings.append(Finding(
                rule_id=det.id, title=f"{det.title} (detector error)",
                severity="info", confidence="low",
                description=f"Detector {det_cls.__name__} raised {type(e).__name__}: {e}",
            ))
    findings.sort(key=lambda x: x.severity_rank, reverse=True)
    return findings
