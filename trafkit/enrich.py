"""Small enrichment primitives shared by the tunnelling and cleartext
detectors -- kept separate from the detectors themselves so they're testable
in isolation, same split nsmkit uses."""

from __future__ import annotations

import math
import re
from collections import Counter

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_B32_RE = re.compile(r"^[A-Z2-7]+=*$")
_B64_RE = re.compile(r"^[A-Za-z0-9+/]+=*$")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def looks_encoded(label: str) -> bool:
    """True if `label` looks like base16/32/64 rather than a human-chosen
    subdomain -- long, dense in one alphabet, no vowniness."""
    if len(label) < 12:
        return False
    if _HEX_RE.match(label) and len(label) >= 16:
        return True
    if _B32_RE.match(label.upper()) and len(label) >= 16:
        return True
    if _B64_RE.match(label) and len(label) >= 16:
        return True
    return False


def digit_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(c.isdigit() for c in s) / len(s)
