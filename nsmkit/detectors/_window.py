"""Event-list adapters over soccore.windows: the detectors keep asking "which
run of these (time-sorted) events, within T seconds, is largest / touches
the most distinct X?", now in O(n) instead of O(n * window)."""

from __future__ import annotations

from datetime import datetime
from typing import Callable, Hashable, Sequence

from soccore.windows import densest, most_distinct

from ..models import Event

_EPOCH = datetime(1970, 1, 1)


def _secs(e: Event) -> float:
    # Naive datetimes subtracted from a naive epoch: no local-time
    # conversion, so DST changes cannot bend a window.
    return (e.timestamp - _EPOCH).total_seconds()


def best_count(events: Sequence[Event], window_s: float) -> list[Event]:
    lo, hi = densest([_secs(e) for e in events], window_s)
    return list(events[lo:hi])


def best_distinct(events: Sequence[Event], key: Callable[[Event], Hashable],
                  window_s: float) -> list[Event]:
    times = [_secs(e) for e in events]
    idx = range(len(events))
    lo, hi = most_distinct(idx, times.__getitem__, lambda i: key(events[i]), window_s)
    return list(events[lo:hi])
