"""Basic unit tests for detector helpers."""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.detectors.out_of_order import advance_max_contig, detect_out_of_order
from src.detectors.retrans import detect_retransmissions, record_range


def test_retransmission_overlap_detection() -> None:
    seen_ranges: list[tuple[int, int]] = []

    assert not detect_retransmissions(seen_ranges, 1000, 1020)

    record_range(seen_ranges, 1000, 1020)
    assert seen_ranges == [(1000, 1020)]

    assert detect_retransmissions(seen_ranges, 1010, 1030)


def test_out_of_order_detection_and_progression() -> None:
    max_contig = None

    max_contig = advance_max_contig(max_contig, 1000, 100)
    assert max_contig == 1100

    assert detect_out_of_order(1050, 50, max_contig)
    assert not detect_out_of_order(1100, 20, max_contig)
