"""
Sliding-window helpers for the "N things within T seconds" question every
behavioural detector asks.

The per-kit versions rebuilt a slice (and often a set) for every right-hand
edge, which is O(n * w) -- fine on a lab capture, minutes on a real firewall
log. These keep running counts instead: O(n) for sorted input. Both return
the FIRST window achieving the maximum, matching the originals' tie-breaking
exactly, so swapping them in changes speed, never results.
"""

from __future__ import annotations

from collections import Counter
from typing import Callable, Hashable, Sequence, TypeVar

T = TypeVar("T")


def densest(times: Sequence[float], window: float) -> tuple[int, int]:
    """(lo, hi) -- half-open indices of the largest run of sorted `times`
    spanning at most `window` seconds. (0, 0) for empty input."""
    best_lo = best_hi = lo = 0
    for hi, t in enumerate(times):
        while t - times[lo] > window:
            lo += 1
        if hi + 1 - lo > best_hi - best_lo:
            best_lo, best_hi = lo, hi + 1
    return best_lo, best_hi


def most_distinct(items: Sequence[T], time_of: Callable[[T], float],
                  key_of: Callable[[T], Hashable], window: float) -> tuple[int, int]:
    """(lo, hi) -- half-open indices of the window (items sorted by time)
    containing the most distinct `key_of` values within `window` seconds.
    (0, 0) for empty input."""
    counts: Counter = Counter()
    distinct = best = best_lo = best_hi = lo = 0
    for hi, item in enumerate(items):
        k = key_of(item)
        counts[k] += 1
        if counts[k] == 1:
            distinct += 1
        t = time_of(item)
        while t - time_of(items[lo]) > window:
            old = key_of(items[lo])
            counts[old] -= 1
            if counts[old] == 0:
                distinct -= 1
            lo += 1
        if distinct > best:
            best, best_lo, best_hi = distinct, lo, hi + 1
    return best_lo, best_hi
