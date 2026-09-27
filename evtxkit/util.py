"""Small helpers shared across detectors: private-IP classification, path
normalization, substring matching, and the sliding-window aggregation
pattern used throughout nsmkit/trafkit/waapkit, reused here unchanged."""

from __future__ import annotations

import re
from typing import Optional

from soccore import netaddr

from .models import EventRecord


def is_private_or_reserved_ip(ip: str) -> bool:
    """True for genuinely internal addresses -- RFC1918 space, loopback,
    link-local, unspecified -- or anything that doesn't even parse as an IP
    (a hostname, "-", "::1", empty string, ...). Callers treat "can't
    prove it's external" as "not external" rather than guessing, since a
    brute-force count that silently includes internal admin tooling is
    worse than one that's occasionally too conservative.

    Deliberately narrower than the stdlib's own `ip.is_private`: that flag
    is True for the whole IANA special-purpose registry, which also
    covers the RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
    203.0.113.0/24) -- exactly the addresses this project's own synthetic
    fixtures use as "the attacker" throughout nsmkit/trafkit/waapkit.
    Using `is_private` here would have silently classified every synthetic
    external attacker IP as internal and suppressed every logon-brute-force
    finding against it (caught while building this detector's own test
    data -- see the build spec's trap list). A documentation-range address
    is not actually a private network, so it doesn't belong in this check;
    it belongs in a separate "this traffic is definitely synthetic/lab
    data" classifier if one is ever needed, which this isn't it.

    Uses soccore.netaddr, which also unwraps IPv4-mapped IPv6: Windows logs
    an IPv4 logon on a dual-stack socket as `::ffff:10.0.0.5`, which the
    previous version classified as external."""
    addr = netaddr.parse(ip)
    if addr is None:
        return True
    return addr.is_unspecified or netaddr.is_internal(ip)


def norm_path(path: str) -> str:
    return (path or "").strip().lower()


def any_substring(haystack: str, needles: tuple, ) -> Optional[str]:
    """Case-insensitive substring containment; returns the first matching
    needle, or None. `needles` entries are matched verbatim (not regex) --
    every list this is called against (discovery commands, tool-transfer
    patterns, sensitive paths, ...) is a literal-substring catalogue in
    Config, not a pattern language, on purpose: it's what a SOC analyst
    actually maintains and extends without needing to know regex."""
    if not haystack:
        return None
    low = haystack.lower()
    for needle in needles:
        if needle.lower() in low:
            return needle
    return None


_DOUBLE_EXT_RE = re.compile(
    r"\.[A-Za-z0-9]{2,5}\.(exe|com|scr|cpl|bat|cmd|vbs|vbe|js|jse|wsf|ps1|hta|msi)$",
    re.I,
)


def has_double_extension(path: str) -> bool:
    """image.jpg.exe -- Windows Threat Detection 1's own USB/phishing
    example ("photo_2024_1_12.jpg.exe")."""
    return bool(_DOUBLE_EXT_RE.search(path or ""))


def is_removable_drive_path(path: str, removable_drive_letters: tuple) -> bool:
    """A path like "E:\\malware.exe" -- not proof of a USB device (any
    non-C: mount matches, including a mapped network drive), but that's a
    stated limitation of this signal in the room material itself ("you may
    find evidence of execution from external drives"), not something this
    function can resolve on its own."""
    if len(path) < 2 or path[1] != ":":
        return False
    return path[0].upper() in removable_drive_letters


def windowed_groups(items: list[tuple[float, EventRecord]], window_s: float):
    """Sort by timestamp; for each starting point, accumulate everything
    within window_s of it, then advance past the whole batch rather than
    one item at a time. Shared with nsmkit/trafkit/waapkit's behavioral
    detectors -- same aggregation shape, different event type."""
    items = sorted(items, key=lambda t: t[0])
    n = len(items)
    i = 0
    while i < n:
        start_ts = items[i][0]
        j = i
        batch = []
        while j < n and items[j][0] - start_ts <= window_s:
            batch.append(items[j][1])
            j += 1
        yield batch
        i += 1 if len(batch) < 2 else len(batch)
