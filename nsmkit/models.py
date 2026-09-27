"""
Normalised event model for NSM analysis.

Every parser in nsmkit.parsers emits `Event` objects with this schema, so all
detectors operate on one shape regardless of whether the source was a firewall
text log, a Zeek CSV export, a Snort fast-alert file or a VPN auth log.

Field naming follows Elastic Common Schema (ECS) conventions loosely so the
output drops into Elastic/Splunk without renaming.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from soccore import netaddr as _netaddr


# --------------------------------------------------------------------------
# Enumerations
# --------------------------------------------------------------------------

class EventKind(str, Enum):
    """Coarse classification of what the log line describes."""
    NETWORK_FLOW = "network_flow"   # firewall / zeek conn / netflow
    IDS_ALERT = "ids_alert"         # snort / suricata alert
    AUTH = "auth"                   # VPN, SSH, AD logon
    DNS = "dns"                     # DNS query/response
    HTTP = "http"                   # proxy / web server / WAF
    FTP = "ftp"                     # FTP control channel command
    ICMP = "icmp"                   # ICMP echo / other
    ARP = "arp"                     # ARP request/reply
    TLS = "tls"                     # TLS handshake metadata
    OTHER = "other"


class Action(str, Enum):
    """Normalised disposition of the event."""
    ALLOW = "allow"
    BLOCK = "block"
    DROP = "drop"
    RESET = "reset"
    SUCCESS = "success"
    FAILURE = "failure"
    ALERT = "alert"
    UNKNOWN = "unknown"


# Vendor-specific verbs -> normalised Action.
# Extend this map when onboarding a new appliance; nothing else needs changing.
ACTION_ALIASES: dict[str, Action] = {
    "allow": Action.ALLOW, "allowed": Action.ALLOW, "accept": Action.ALLOW,
    "permit": Action.ALLOW, "pass": Action.ALLOW, "sf": Action.ALLOW,
    "block": Action.BLOCK, "blocked": Action.BLOCK, "deny": Action.BLOCK,
    "denied": Action.BLOCK, "reject": Action.BLOCK,
    "drop": Action.DROP, "dropped": Action.DROP,
    "reset": Action.RESET, "rst": Action.RESET,
    "success": Action.SUCCESS, "success_auth": Action.SUCCESS,
    "accepted": Action.SUCCESS, "ok": Action.SUCCESS,
    "fail": Action.FAILURE, "failed": Action.FAILURE, "failure": Action.FAILURE,
    "failed_auth": Action.FAILURE, "invalid": Action.FAILURE,
    "alert": Action.ALERT,
}


def normalise_action(raw: Optional[str]) -> Action:
    if not raw:
        return Action.UNKNOWN
    return ACTION_ALIASES.get(str(raw).strip().lower(), Action.UNKNOWN)


# --------------------------------------------------------------------------
# Event
# --------------------------------------------------------------------------

@dataclass
class Event:
    """One normalised log record."""

    # --- core ---
    timestamp: datetime
    kind: EventKind = EventKind.OTHER
    action: Action = Action.UNKNOWN
    source_type: str = "unknown"          # e.g. "firewall", "snort", "vpn_auth"
    raw: str = ""                         # original line, kept for evidence

    # --- network 5-tuple ---
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None        # tcp / udp / icmp

    # --- volume ---
    bytes_out: int = 0                    # src -> dst
    bytes_in: int = 0                     # dst -> src
    packets: int = 0
    duration: float = 0.0

    # --- identity ---
    user: Optional[str] = None
    assigned_ip: Optional[str] = None     # VPN pool address handed to the user

    # --- IDS ---
    signature: Optional[str] = None       # rule msg text
    sid: Optional[str] = None             # gid:sid:rev
    classification: Optional[str] = None
    priority: Optional[int] = None

    # --- application layer ---
    dns_query: Optional[str] = None
    dns_qtype: Optional[str] = None
    dns_rcode: Optional[str] = None
    dns_answer: Optional[str] = None
    dns_ttl: Optional[int] = None
    dns_is_response: Optional[bool] = None

    http_method: Optional[str] = None
    http_uri: Optional[str] = None
    http_host: Optional[str] = None       # domain / Host header / SNI
    http_status: Optional[int] = None
    user_agent: Optional[str] = None

    ftp_command: Optional[str] = None
    ftp_arg: Optional[str] = None

    # --- layer 2 ---
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    arp_opcode: Optional[int] = None      # 1 = request, 2 = reply
    arp_sender_ip: Optional[str] = None
    arp_sender_mac: Optional[str] = None
    arp_target_ip: Optional[str] = None
    arp_is_gratuitous: bool = False

    icmp_type: Optional[int] = None
    icmp_payload_len: Optional[int] = None

    # --- misc / passthrough ---
    extra: dict[str, Any] = field(default_factory=dict)

    # ---------------- derived helpers ----------------

    # Explicit RFC1918 + loopback + link-local + CGNAT + ULA (soccore.netaddr).
    # Deliberately NOT `ipaddress.is_private`, which also flags the RFC 5737
    # documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) --
    # exactly the addresses training material and sanitised logs use for the
    # *external* attacker, which would invert every direction check. The
    # shared classifier also unwraps IPv4-mapped IPv6 (::ffff:10.0.0.5).
    @classmethod
    def _is_private(cls, ip: Optional[str]) -> bool:
        return _netaddr.is_internal(ip)

    @property
    def src_is_internal(self) -> bool:
        return self._is_private(self.src_ip)

    @property
    def dst_is_internal(self) -> bool:
        return self._is_private(self.dst_ip)

    @property
    def direction(self) -> str:
        """inbound | outbound | internal | external | unknown"""
        s, d = self.src_ip, self.dst_ip
        if not s or not d:
            return "unknown"
        si, di = self.src_is_internal, self.dst_is_internal
        if si and di:
            return "internal"
        if not si and di:
            return "inbound"
        if si and not di:
            return "outbound"
        return "external"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat() if self.timestamp else None
        d["kind"] = self.kind.value
        d["action"] = self.action.value
        d["direction"] = self.direction
        return d


# --------------------------------------------------------------------------
# Finding
# --------------------------------------------------------------------------

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    """One detection result produced by a detector."""

    rule_id: str                          # e.g. "NSM-SCAN-002"
    title: str
    severity: str                         # info | low | medium | high | critical
    confidence: str                       # low | medium | high
    description: str
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    user: Optional[str] = None
    entity: Optional[str] = None          # free-form pivot key (domain, MAC, ...)
    mitre: list[str] = field(default_factory=list)   # ATT&CK technique IDs
    kill_chain: Optional[str] = None
    metrics: dict[str, Any] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)  # raw lines, capped
    recommendation: str = ""

    MAX_EVIDENCE = 10

    def add_evidence(self, line: str) -> None:
        if len(self.evidence) < self.MAX_EVIDENCE and line:
            self.evidence.append(line.strip())

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["first_seen"] = self.first_seen.isoformat() if self.first_seen else None
        d["last_seen"] = self.last_seen.isoformat() if self.last_seen else None
        return d
