"""Out-of-order detection helpers."""

from __future__ import annotations

from typing import Optional


def detect_out_of_order(seq: Optional[int], length: int, max_contig: Optional[int]) -> bool:
    """Return True if the new segment starts before the contiguous high-water mark."""

    if seq is None or length <= 0:
        return False
    if max_contig is None:
        return False
    return seq < max_contig


def advance_max_contig(current: Optional[int], seq: Optional[int], length: int) -> Optional[int]:
    """Update the contiguous high-water mark for a flow."""

    if seq is None or length <= 0:
        return current

    segment_end = seq + length
    if current is None:
        return segment_end

    if seq <= current + 1:
        return max(current, segment_end)

    return current


__all__ = ["detect_out_of_order", "advance_max_contig"]
