"""
Internal vs. external address classification, shared by every kit.

Deliberately NOT `ipaddress.ip_address(x).is_private`: that flag is True for
the whole IANA special-purpose registry, including the RFC 5737 documentation
ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) -- exactly what
sanitised logs and training material use for the *external attacker*. Using it
inverts every direction check. Internal space is listed explicitly instead.

Also handles two shapes real logs produce that the per-kit copies missed:
IPv4-mapped IPv6 (`::ffff:10.0.0.5`, how Windows records IPv4 logons on a
dual-stack socket) and bracketed / zone-scoped literals (`[fe80::1%12]`).
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from typing import Iterable, Optional, Union

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

INTERNAL_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",     # RFC 1918
    "127.0.0.0/8", "169.254.0.0/16",                     # loopback, link-local
    "100.64.0.0/10",                                     # carrier-grade NAT (RFC 6598)
    "::1/128", "fc00::/7", "fe80::/10",                  # v6 loopback, ULA, link-local
))
_V4_INTERNAL = tuple(n for n in INTERNAL_NETWORKS if n.version == 4)
_V6_INTERNAL = tuple(n for n in INTERNAL_NETWORKS if n.version == 6)
_V4_NOT_ROUTABLE = tuple(ipaddress.ip_network(n) for n in ("0.0.0.0/8", "240.0.0.0/4"))


@lru_cache(maxsize=65536)
def parse(value: Optional[str]) -> Optional[IPAddress]:
    """Parse an address as logs write it; None if it is not one."""
    if not value:
        return None
    s = str(value).strip()
    if s.startswith("[") and "]" in s:
        s = s[1:s.index("]")]
    s = s.split("%", 1)[0]                    # zone index: fe80::1%12
    try:
        addr = ipaddress.ip_address(s)
    except ValueError:
        return None
    if addr.version == 6 and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def is_internal(value: Optional[str]) -> bool:
    """True for RFC 1918 / loopback / link-local / CGNAT / ULA addresses."""
    addr = parse(value)
    if addr is None:
        return False
    nets = _V4_INTERNAL if addr.version == 4 else _V6_INTERNAL
    return any(addr in n for n in nets)


def is_public(value: Optional[str]) -> bool:
    """A routable unicast address outside internal space -- the kind worth
    reporting as an indicator. Documentation ranges count as public."""
    addr = parse(value)
    if addr is None or addr.is_unspecified or addr.is_multicast or is_internal(value):
        return False
    if addr.version == 4 and (addr == ipaddress.IPv4Address("255.255.255.255")
                              or any(addr in n for n in _V4_NOT_ROUTABLE)):
        return False
    return True


def in_networks(value: Optional[str], networks: Iterable[str]) -> bool:
    """True if `value` falls inside any CIDR string in `networks`."""
    addr = parse(value)
    if addr is None:
        return False
    for net in networks:
        try:
            n = _network(net)
        except ValueError:
            continue
        if n.version == addr.version and addr in n:
            return True
    return False


@lru_cache(maxsize=1024)
def _network(cidr: str):
    return ipaddress.ip_network(cidr, strict=False)
