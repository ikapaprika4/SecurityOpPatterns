"""
Data model for email analysis.

`ParsedEmail` is the normalised representation every analyser works from, so
adding a new input format (.eml, .msg, raw MIME from a mail API) means writing
one parser, not touching any rule.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Optional


# --------------------------------------------------------------------------
# Verdicts
# --------------------------------------------------------------------------

class Verdict(str, Enum):
    """Final disposition. Mirrors what a SOC analyst records when closing a case."""
    BENIGN = "benign"
    SPAM = "spam"
    SUSPICIOUS = "suspicious"
    PHISHING = "phishing"
    MALICIOUS = "malicious"        # weaponised: malware attachment or payload URL


class AuthResult(str, Enum):
    """SPF / DKIM / DMARC evaluation outcomes (RFC 7208 §2.6, RFC 7489)."""
    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"
    POLICY = "policy"
    UNKNOWN = "unknown"


# SPF result -> receiving-server action, per the SPF disposition table.
SPF_ACTION = {
    AuthResult.PASS: "accept",
    AuthResult.NEUTRAL: "accept",
    AuthResult.NONE: "accept",
    AuthResult.SOFTFAIL: "flag",
    AuthResult.PERMERROR: "flag",
    AuthResult.FAIL: "reject",
    AuthResult.TEMPERROR: "reject",
}


class PhishType(str, Enum):
    """Classification of the social-engineering vector."""
    SPAM = "spam"                      # unsolicited bulk
    MALSPAM = "malspam"                # bulk with a malicious payload
    PHISHING = "phishing"              # broad impersonation
    SPEAR_PHISHING = "spear_phishing"  # targeted, personalised
    WHALING = "whaling"                # targets executives
    BEC = "bec"                        # business email compromise
    SMISHING = "smishing"              # SMS
    VISHING = "vishing"                # voice


# --------------------------------------------------------------------------
# Components
# --------------------------------------------------------------------------

@dataclass
class EmailAddress:
    """A parsed address, split into the three parts of the anatomy."""
    raw: str = ""
    display_name: str = ""
    address: str = ""

    @property
    def local_part(self) -> str:
        """The username -- the mailbox on the destination system."""
        return self.address.split("@", 1)[0] if "@" in self.address else self.address

    @property
    def domain(self) -> str:
        """The domain -- which mail server is responsible for the message."""
        return self.address.split("@", 1)[1].lower() if "@" in self.address else ""

    def __str__(self) -> str:
        return f"{self.display_name} <{self.address}>" if self.display_name else self.address


@dataclass
class ReceivedHop:
    """One `Received:` header, i.e. one server in the delivery path.

    Headers are prepended, so index 0 is the LAST hop (closest to the
    recipient) and the highest index is the ORIGINATING server.
    """
    index: int
    raw: str
    from_host: Optional[str] = None
    from_ip: Optional[str] = None
    by_host: Optional[str] = None
    with_protocol: Optional[str] = None
    timestamp: Optional[datetime] = None
    delay_seconds: Optional[float] = None


@dataclass
class ExtractedURL:
    """A URL found in the message, with the analysis attached to it."""
    url: str
    source: str = "body"          # body | html_href | header | attachment | text
    display_text: str = ""        # anchor text -- mismatch with href is a red flag
    domain: str = ""
    scheme: str = ""
    path: str = ""
    is_shortener: bool = False
    is_ip_literal: bool = False   # http://203.0.113.10/login -- no domain at all
    is_tracking_pixel: bool = False
    lookalike_of: Optional[str] = None
    redirect_chain: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def defanged(self) -> str:
        from .iocs import defang
        return defang(self.url)


@dataclass
class Attachment:
    """A MIME part treated as a file, with hashes for reputation lookup."""
    filename: str
    content_type: str = ""
    content_disposition: str = ""
    transfer_encoding: str = ""
    size: int = 0
    data: bytes = b""
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    extension: str = ""
    is_dangerous: bool = False
    has_double_extension: bool = False
    macro_capable: bool = False
    embedded_urls: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def compute_hashes(self) -> None:
        if not self.data:
            return
        self.md5 = hashlib.md5(self.data).hexdigest()
        self.sha1 = hashlib.sha1(self.data).hexdigest()
        self.sha256 = hashlib.sha256(self.data).hexdigest()
        self.size = len(self.data)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("data", None)          # never serialise the payload itself
        return d


@dataclass
class AuthenticationResults:
    """Parsed `Authentication-Results` / `Received-SPF` plus any local evaluation."""
    spf: AuthResult = AuthResult.UNKNOWN
    dkim: AuthResult = AuthResult.UNKNOWN
    dmarc: AuthResult = AuthResult.UNKNOWN
    spf_domain: str = ""
    dkim_domain: str = ""
    dmarc_policy: str = ""            # none | quarantine | reject
    spf_aligned: Optional[bool] = None
    dkim_aligned: Optional[bool] = None
    raw_headers: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def spf_action(self) -> str:
        return SPF_ACTION.get(self.spf, "unknown")

    @property
    def all_passed(self) -> bool:
        return (self.spf is AuthResult.PASS
                and self.dkim is AuthResult.PASS
                and self.dmarc is AuthResult.PASS)

    @property
    def any_failed(self) -> bool:
        bad = {AuthResult.FAIL, AuthResult.SOFTFAIL, AuthResult.PERMERROR, AuthResult.TEMPERROR}
        return any(r in bad for r in (self.spf, self.dkim, self.dmarc))


# --------------------------------------------------------------------------
# ParsedEmail
# --------------------------------------------------------------------------

@dataclass
class ParsedEmail:
    """Everything extracted from one message."""

    # provenance
    source_path: str = ""
    raw: bytes = b""
    file_sha256: str = ""

    # --- header artifacts (the collection checklist) ---
    from_addr: Optional[EmailAddress] = None
    reply_to: Optional[EmailAddress] = None
    return_path: Optional[EmailAddress] = None
    sender: Optional[EmailAddress] = None          # Sender: header
    to: list[EmailAddress] = field(default_factory=list)
    cc: list[EmailAddress] = field(default_factory=list)
    bcc: list[EmailAddress] = field(default_factory=list)
    subject: str = ""
    date: Optional[datetime] = None
    message_id: str = ""
    x_originating_ip: str = ""
    originating_ip: str = ""                       # from the earliest Received hop
    received_chain: list[ReceivedHop] = field(default_factory=list)
    all_headers: list[tuple[str, str]] = field(default_factory=list)

    # --- body ---
    body_text: str = ""
    body_html: str = ""
    urls: list[ExtractedURL] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)

    # --- authentication ---
    auth: AuthenticationResults = field(default_factory=AuthenticationResults)

    # --- misc ---
    is_bcc_delivery: bool = False       # recipient appears in no To/Cc header
    parse_errors: list[str] = field(default_factory=list)

    def header(self, name: str) -> Optional[str]:
        low = name.lower()
        for k, v in self.all_headers:
            if k.lower() == low:
                return v
        return None

    def headers_all(self, name: str) -> list[str]:
        low = name.lower()
        return [v for k, v in self.all_headers if k.lower() == low]

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_path": self.source_path,
            "file_sha256": self.file_sha256,
            "from": str(self.from_addr) if self.from_addr else None,
            "from_address": self.from_addr.address if self.from_addr else None,
            "from_display_name": self.from_addr.display_name if self.from_addr else None,
            "reply_to": self.reply_to.address if self.reply_to else None,
            "return_path": self.return_path.address if self.return_path else None,
            "to": [a.address for a in self.to],
            "cc": [a.address for a in self.cc],
            "bcc": [a.address for a in self.bcc],
            "subject": self.subject,
            "date": self.date.isoformat() if self.date else None,
            "message_id": self.message_id,
            "originating_ip": self.originating_ip,
            "x_originating_ip": self.x_originating_ip,
            "hop_count": len(self.received_chain),
            "auth": {
                "spf": self.auth.spf.value, "spf_action": self.auth.spf_action,
                "dkim": self.auth.dkim.value, "dmarc": self.auth.dmarc.value,
                "dmarc_policy": self.auth.dmarc_policy,
                "spf_aligned": self.auth.spf_aligned,
                "dkim_aligned": self.auth.dkim_aligned,
            },
            "url_count": len(self.urls),
            "attachment_count": len(self.attachments),
            "is_bcc_delivery": self.is_bcc_delivery,
        }


# --------------------------------------------------------------------------
# Finding
# --------------------------------------------------------------------------

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    """One indicator raised by a detector."""
    rule_id: str                # "PH-HDR-001"
    title: str
    severity: str               # info | low | medium | high | critical
    confidence: str             # low | medium | high
    score: int                  # contribution to the overall phishing score
    description: str
    category: str = "general"   # header | body | url | attachment | auth | social
    evidence: list[str] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    recommendation: str = ""

    MAX_EVIDENCE = 8

    def add_evidence(self, item: str) -> None:
        if item and len(self.evidence) < self.MAX_EVIDENCE:
            self.evidence.append(str(item)[:400])

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisResult:
    """The complete case file for one email."""
    email: ParsedEmail
    findings: list[Finding] = field(default_factory=list)
    score: int = 0
    verdict: Verdict = Verdict.BENIGN
    phish_types: list[PhishType] = field(default_factory=list)
    iocs: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "score": self.score,
            "phish_types": [t.value for t in self.phish_types],
            "email": self.email.to_dict(),
            "findings": [f.to_dict() for f in
                         sorted(self.findings, key=lambda f: (-f.severity_rank, -f.score))],
            "iocs": self.iocs,
            "urls": [{"url": u.url, "defanged": u.defanged, "domain": u.domain,
                      "source": u.source, "display_text": u.display_text,
                      "is_shortener": u.is_shortener, "is_tracking_pixel": u.is_tracking_pixel,
                      "lookalike_of": u.lookalike_of, "notes": u.notes}
                     for u in self.email.urls],
            "attachments": [a.to_dict() for a in self.email.attachments],
        }
