"""
Enrichment helpers: entropy, encoding heuristics, domain handling, port
semantics, and timing statistics. Detectors import from here so the scoring
maths lives in exactly one place.
"""

from __future__ import annotations

import ipaddress
import math
import re
import statistics
from collections import Counter
from typing import Iterable, Optional, Sequence

from soccore import netaddr as _netaddr

# --------------------------------------------------------------------------
# Ports
# --------------------------------------------------------------------------

PORT_SERVICES: dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 69: "tftp", 80: "http", 88: "kerberos",
    110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    389: "ldap", 443: "https", 445: "smb", 465: "smtps", 514: "syslog",
    587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s",
    1080: "socks", 1433: "mssql", 1521: "oracle", 3128: "squid",
    3306: "mysql", 3389: "rdp", 4444: "metasploit-default", 5432: "postgres",
    5900: "vnc", 5985: "winrm", 5986: "winrm-tls", 6379: "redis",
    8000: "http-alt", 8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
    27017: "mongodb",
}

# Ports whose exposure at the perimeter is a finding in itself.
HIGH_RISK_PORTS: set[int] = {21, 22, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017}

# Ports commonly used by remote-access tooling / default C2 listeners.
SUSPICIOUS_PORTS: set[int] = {4444, 4445, 1337, 31337, 8081, 9001, 9002, 50050}

# Ports that carry lateral movement inside a LAN.
LATERAL_PORTS: set[int] = {22, 135, 139, 445, 3389, 5985, 5986}


def service_name(port: Optional[int]) -> str:
    if port is None:
        return "unknown"
    return PORT_SERVICES.get(port, f"port-{port}")


# --------------------------------------------------------------------------
# Addresses
# --------------------------------------------------------------------------

def is_private_ip(ip: Optional[str]) -> bool:
    """
    RFC1918 / loopback / link-local / CGNAT / ULA only.

    Not `ipaddress.is_private`, which also covers the RFC 5737 documentation
    ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). Sanitised logs use
    those for the *external* attacker, so treating them as internal would flip
    every direction and severity decision in the toolkit.
    """
    from .models import Event
    return Event._is_private(ip)


def in_networks(ip: Optional[str], networks: Sequence[str]) -> bool:
    """True if `ip` falls inside any CIDR in `networks` (IPv4-mapped IPv6
    such as ::ffff:10.0.0.5 is matched against IPv4 networks; parsed
    networks are cached, since detectors call this per event)."""
    if not ip or not networks:
        return False
    return _netaddr.in_networks(ip, networks)


def same_subnet(a: str, b: str, prefix: int = 24) -> bool:
    try:
        return (ipaddress.ip_network(f"{a}/{prefix}", strict=False) ==
                ipaddress.ip_network(f"{b}/{prefix}", strict=False))
    except ValueError:
        return False


# --------------------------------------------------------------------------
# Entropy and encoding
# --------------------------------------------------------------------------

def shannon_entropy(s: str) -> float:
    """Bits per character. Random base32/base64 lands around 4.5-5.0;
    English-like hostnames sit near 3.0-3.6."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


_B64_RE = re.compile(r"^[A-Za-z0-9+/=_\-]{16,}$")
_B32_RE = re.compile(r"^[A-Z2-7=]{16,}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]{16,}$")


def looks_encoded(s: str) -> Optional[str]:
    """Return 'hex' | 'base32' | 'base64' | None for a single label."""
    if not s or len(s) < 16:
        return None
    if _HEX_RE.match(s):
        return "hex"
    if _B32_RE.match(s.upper()) and s.isupper():
        return "base32"
    if _B64_RE.match(s):
        return "base64"
    return None


def digit_ratio(s: str) -> float:
    return sum(c.isdigit() for c in s) / len(s) if s else 0.0


def consonant_run(s: str) -> int:
    """Longest run of consonants -- machine-generated labels run long."""
    best = run = 0
    for c in s.lower():
        if c.isalpha() and c not in "aeiou":
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


# --------------------------------------------------------------------------
# Domains
# --------------------------------------------------------------------------

# Multi-part public suffixes seen most often; extend or swap for the PSL.
_MULTI_SUFFIX = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "com.au", "net.au",
    "co.nz", "com.br", "co.in", "com.cn", "com.tr", "co.za", "com.mx",
}


def registered_domain(fqdn: Optional[str]) -> Optional[str]:
    """'a.b.c.example.co.uk' -> 'example.co.uk'. Groups tunnelling subdomains
    under one key so per-domain query counts are meaningful."""
    if not fqdn:
        return None
    parts = fqdn.strip(".").lower().split(".")
    if len(parts) < 2:
        return fqdn.strip(".").lower()
    if len(parts) >= 3 and ".".join(parts[-2:]) in _MULTI_SUFFIX:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def subdomain_part(fqdn: Optional[str]) -> str:
    if not fqdn:
        return ""
    reg = registered_domain(fqdn) or ""
    host = fqdn.strip(".").lower()
    return host[: -(len(reg) + 1)] if reg and host.endswith(reg) and len(host) > len(reg) else ""


def longest_label(fqdn: Optional[str]) -> int:
    if not fqdn:
        return 0
    return max((len(p) for p in fqdn.strip(".").split(".")), default=0)


# --------------------------------------------------------------------------
# Timing / periodicity
# --------------------------------------------------------------------------

def intervals(timestamps: Sequence) -> list[float]:
    """Seconds between consecutive (sorted) timestamps."""
    ts = sorted(timestamps)
    return [(ts[i + 1] - ts[i]).total_seconds() for i in range(len(ts) - 1)]


def jitter_ratio(gaps: Sequence[float]) -> Optional[float]:
    """
    Coefficient of variation of the inter-arrival gaps.

    ~0.00  perfectly periodic (scripted beacon, cron)
    <0.15  low jitter -- treat as beaconing
    <0.35  jittered beacon (many C2 frameworks randomise +/-20-30%)
    >0.60  human / bursty traffic
    """
    clean = [g for g in gaps if g > 0]
    if len(clean) < 3:
        return None
    mean = statistics.fmean(clean)
    if mean <= 0:
        return None
    return statistics.pstdev(clean) / mean


def mad_over_median(gaps: Sequence[float]) -> Optional[float]:
    """Median-absolute-deviation / median -- robust against a few missed beacons."""
    clean = [g for g in gaps if g > 0]
    if len(clean) < 3:
        return None
    med = statistics.median(clean)
    if med <= 0:
        return None
    mad = statistics.median([abs(g - med) for g in clean])
    return mad / med


def dominant_period(gaps: Sequence[float], tolerance: float = 0.20) -> Optional[float]:
    """
    Median gap, if at least 70% of gaps fall within `tolerance` of it.
    Survives dropped beacons better than the mean does.
    """
    clean = [g for g in gaps if g > 0]
    if len(clean) < 3:
        return None
    med = statistics.median(clean)
    if med <= 0:
        return None
    within = sum(1 for g in clean if abs(g - med) <= tolerance * med)
    return med if within / len(clean) >= 0.70 else None


def off_hours(dt, start_hour: int = 20, end_hour: int = 6) -> bool:
    """True for timestamps outside the business day (local time assumed)."""
    h = dt.hour
    return h >= start_hour or h < end_hour


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0:
            return f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}PB"


def percentile(values: Iterable[float], pct: float) -> float:
    vals = sorted(values)
    if not vals:
        return 0.0
    k = (len(vals) - 1) * pct
    lo, hi = math.floor(k), math.ceil(k)
    if lo == hi:
        return vals[int(k)]
    return vals[lo] * (hi - k) + vals[hi] * (k - lo)
