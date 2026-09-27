"""
Core data model.

trafkit is packet-native (unlike a log-parsing toolkit): every packet becomes
a PacketRecord holding a flat, dot-namespaced field dict that mirrors
Wireshark's own field naming (`ip.src`, `tcp.flags.syn`, `http.request.method`,
...). That one representation is what both the display-filter engine and every
detector read from, so a filter expression and a detector's field access use
exactly the same names an analyst already knows from Wireshark.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# --------------------------------------------------------------------------
# Packets
# --------------------------------------------------------------------------

@dataclass(slots=True)
class PacketRecord:
    """One frame, with a flat Wireshark-style field dict plus a few hot fields
    promoted to real attributes because almost every detector needs them.
    Slotted: one of these exists per packet, so the per-instance __dict__
    was a real memory cost on large captures."""

    frame_number: int
    ts: float
    length: int
    fields: dict[str, Any] = field(default_factory=dict)
    summary: str = ""

    # Promoted for convenience / speed -- always mirrored into `fields` too.
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    proto: Optional[str] = None          # "tcp" | "udp" | "icmp" | "arp" | ...
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    @property
    def time(self) -> datetime:
        # Capture timestamps are UTC epochs; render them as UTC rather than
        # the analysing machine's local zone.
        return datetime.fromtimestamp(self.ts, tz=timezone.utc)

    def get(self, key: str, default: Any = None) -> Any:
        return self.fields.get(key, default)

    def has(self, prefix: str) -> bool:
        """True if any field is exactly `prefix` or nested under it (`prefix.*`)."""
        if prefix in self.fields:
            return True
        p = prefix + "."
        return any(k.startswith(p) for k in self.fields)


# --------------------------------------------------------------------------
# Hosts / conversations (NetworkMiner "Hosts" + Wireshark "Statistics")
# --------------------------------------------------------------------------

@dataclass
class Host:
    ip: str
    macs: set[str] = field(default_factory=set)
    hostnames: set[str] = field(default_factory=set)
    os_guess: Optional[str] = None
    os_confidence: str = "low"
    open_ports: set[int] = field(default_factory=set)
    packets_sent: int = 0
    packets_recv: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    def touch(self, ts: float) -> None:
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts


@dataclass
class Conversation:
    proto: str
    a_addr: str
    b_addr: str
    a_port: Optional[int] = None
    b_port: Optional[int] = None
    packets: int = 0
    bytes: int = 0
    start: Optional[float] = None
    end: Optional[float] = None

    @property
    def key(self) -> tuple:
        # Order-independent key so A->B and B->A merge into one conversation.
        ends = sorted([(self.a_addr, self.a_port), (self.b_addr, self.b_port)])
        return (self.proto, ends[0], ends[1])


# --------------------------------------------------------------------------
# Findings / artifacts
# --------------------------------------------------------------------------

@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str                       # info|low|medium|high|critical
    confidence: str                     # low|medium|high
    description: str
    frames: list[int] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    mitre: Optional[str] = None

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id, "title": self.title, "severity": self.severity,
            "confidence": self.confidence, "description": self.description,
            "frames": self.frames[:25], "evidence": self.evidence,
            "recommendation": self.recommendation, "mitre": self.mitre,
        }


@dataclass
class Credential:
    protocol: str
    frame: int
    src: str
    dst: str
    username: Optional[str] = None
    secret: Optional[str] = None
    secret_type: str = "cleartext"      # cleartext|hash|cookie
    detail: Optional[str] = None


@dataclass
class Artifact:
    kind: str                            # file|keyword|message|resolved_address
    frame: int
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisResult:
    path: str
    packets: list[PacketRecord] = field(default_factory=list)
    hosts: dict = field(default_factory=dict)
    conversations: list = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)   # e.g. a truncated / damaged capture

    @property
    def worst_severity(self) -> str:
        if not self.findings:
            return "info"
        rank = max(f.severity_rank for f in self.findings)
        for name, r in SEVERITY_ORDER.items():
            if r == rank:
                return name
        return "info"
