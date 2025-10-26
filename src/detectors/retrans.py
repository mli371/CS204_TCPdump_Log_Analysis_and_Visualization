"""Helpers for retransmission detection based on seen TCP sequence ranges."""

from __future__ import annotations

from typing import MutableSequence, Sequence, Tuple

Range = Tuple[int, int]


def detect_retransmissions(seen_ranges: Sequence[Range], start: int, end: int) -> bool:
    """Return True when the provided byte-range overlaps any seen range."""

    if start >= end:
        return False

    for left, right in seen_ranges:
        if start < right and end > left:
            return True
    return False


def record_range(seen_ranges: MutableSequence[Range], start: int, end: int) -> None:
    """Insert a byte-range into the seen set, maintaining merged ordering."""

    if start >= end:
        return

    seen_ranges.append((start, end))
    if len(seen_ranges) == 1:
        return

    seen_ranges.sort(key=lambda rng: rng[0])
    merged: list[Range] = []
    cur_start, cur_end = seen_ranges[0]

    for next_start, next_end in seen_ranges[1:]:
        if next_start <= cur_end:
            cur_end = max(cur_end, next_end)
            continue
        merged.append((cur_start, cur_end))
        cur_start, cur_end = next_start, next_end

    merged.append((cur_start, cur_end))
    seen_ranges[:] = merged


__all__ = ["detect_retransmissions", "record_range"]
