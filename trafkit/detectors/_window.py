"""The "largest run of packets within T seconds" helper every trafkit
detector used a private copy of -- now one O(n) implementation (see
soccore.windows) instead of four O(n * window) ones."""

from __future__ import annotations

from collections import Counter
from typing import Callable, Hashable, Optional, Sequence

from soccore.windows import densest


def slide(items: Sequence, window_seconds: float, ts: Callable = lambda p: p.ts) -> Optional[list]:
    """The largest run of time-sorted `items` spanning <= window_seconds
    (first one on ties), or None for empty input."""
    if not items:
        return None
    lo, hi = densest([ts(p) for p in items], window_seconds)
    return list(items[lo:hi])


def largest_mixed_window(items: Sequence, window_seconds: float,
                         ts: Callable, key: Callable[..., Hashable]) -> Optional[list]:
    """The largest window (<= window_seconds) whose items carry more than one
    distinct key -- e.g. ARP replies for one IP from more than one MAC."""
    counts: Counter = Counter()
    best: Optional[tuple[int, int]] = None
    lo = 0
    for hi, item in enumerate(items):
        counts[key(item)] += 1
        while ts(item) - ts(items[lo]) > window_seconds:
            k = key(items[lo])
            counts[k] -= 1
            if not counts[k]:
                del counts[k]
            lo += 1
        if len(counts) > 1 and (best is None or hi + 1 - lo > best[1] - best[0]):
            best = (lo, hi + 1)
    return list(items[best[0]:best[1]]) if best else None
