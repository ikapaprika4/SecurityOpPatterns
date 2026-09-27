"""Detector ABC + registry -- same pattern as nsmkit/phishkit/trafkit/
waapkit. Each detector gets the full event list plus a pre-built
ProcessTree (constructed once per run, not per detector) and runs in
isolation: one detector raising never stops the others.
"""

from __future__ import annotations

import logging
import traceback
from abc import ABC, abstractmethod

from ..config import Config
from ..models import EventRecord, Finding
from ..processtree import ProcessTree

logger = logging.getLogger("evtxkit")

# ATT&CK techniques per rule, attached centrally after every run so each
# detector doesn't have to repeat them (and so they're listed in one place).
MITRE_BY_RULE: dict[str, list[str]] = {
    "EVTX-LOGON-BRUTE-01": ["T1110.001", "T1133"],
    "EVTX-LOGON-BRUTE-SUCCESS-01": ["T1110", "T1078", "T1021.001"],
    "EVTX-USER-NEW-01": ["T1136.001"],
    "EVTX-USER-BACKDOOR-ADMIN-01": ["T1136.001", "T1098"],
    "EVTX-USER-GROUP-01": ["T1098"],
    "EVTX-USER-PWRESET-01": ["T1098", "T1078.003"],
    "EVTX-PERSIST-SERVICE-01": ["T1543.003"],
    "EVTX-PERSIST-TASK-01": ["T1053.005"],
    "EVTX-PERSIST-STARTUP-01": ["T1547.001"],
    "EVTX-PERSIST-RUNKEY-01": ["T1547.001"],
    "EVTX-EXEC-DOUBLEEXT-01": ["T1036.007", "T1204.002"],
    "EVTX-EXEC-DOWNLOADED-ATTACHMENT-01": ["T1566.001", "T1204.002"],
    "EVTX-EXEC-LNK-PHISHING-01": ["T1566.001", "T1204.002", "T1059.001"],
    "EVTX-EXEC-REMOVABLE-01": ["T1091"],
    "EVTX-EXEC-ENCODED-PS-01": ["T1059.001", "T1027.010"],
    "EVTX-EXEC-PSSUSPICIOUS-01": ["T1059.001"],
    "EVTX-DISCOVERY-SEQ-01": ["T1033", "T1087.001", "T1082", "T1016"],
    "EVTX-COLLECT-SENSITIVE-01": ["T1005", "T1555"],
    "EVTX-COLLECT-ARCHIVE-01": ["T1560.001"],
    "EVTX-COLLECT-CREDSEARCH-01": ["T1552.001"],
    "EVTX-COLLECT-STEALER-01": ["T1005", "T1555.003"],
    "EVTX-C2-TRANSFER-01": ["T1105"],
    "EVTX-C2-SUSPICIOUS-NETWORK-01": ["T1071"],
    "EVTX-DEFENSE-LOGCLEAR-01": ["T1070.001"],
}


class Detector(ABC):
    id: str = "BASE"
    title: str = "Unnamed detector"
    tactic: str = "Unknown"   # MITRE tactic name

    def __init__(self, config: Config):
        self.config = config

    @abstractmethod
    def run(self, events: list[EventRecord], tree: ProcessTree) -> list[Finding]:
        raise NotImplementedError


REGISTRY: list[type[Detector]] = []


def register(cls: type[Detector]) -> type[Detector]:
    REGISTRY.append(cls)
    return cls


def run_detectors(events: list[EventRecord], config: Config) -> list[Finding]:
    tree = ProcessTree(events)
    findings: list[Finding] = []
    for det_cls in REGISTRY:
        detector = det_cls(config)
        try:
            findings.extend(detector.run(events, tree))
        except Exception as exc:  # noqa: BLE001 -- isolation is the point
            logger.debug("detector %s failed: %s", det_cls.id, traceback.format_exc())
            findings.append(
                Finding(
                    rule_id=f"{getattr(det_cls, 'id', det_cls.__name__)}-ERROR",
                    title=f"Detector {det_cls.__name__} failed",
                    tactic="Internal",
                    severity="info",
                    confidence="low",
                    description=f"{det_cls.__name__} raised {exc!r} and was skipped; "
                                 f"other detectors still ran.",
                )
            )
    for f in findings:
        if not f.mitre:
            f.mitre = list(MITRE_BY_RULE.get(f.rule_id, []))
    return findings
