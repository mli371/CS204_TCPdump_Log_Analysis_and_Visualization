"""Unit tests for retransmission and out-of-order detection helpers."""

from tcpviz.src.detectors.out_of_order import advance_max_contig, detect_out_of_order
from tcpviz.src.detectors.retrans import detect_retransmissions, record_range


def test_retransmission_detects_overlapping_segment() -> None:
    seen = []

    # First segment populates the seen range but should not trigger.
    assert not detect_retransmissions(seen, start=1000, end=1100)
    record_range(seen, start=1000, end=1100)
    assert seen == [(1000, 1100)]

    # Second segment overlaps the existing window -> retransmission.
    assert detect_retransmissions(seen, start=1050, end=1120)

    # Record the overlapping segment and ensure the range is merged.
    record_range(seen, start=1050, end=1120)
    assert seen == [(1000, 1120)]


def test_out_of_order_detected_when_sequence_rolls_back() -> None:
    max_contig = None

    # First in-order segment defines the contiguous high-water mark.
    max_contig = advance_max_contig(max_contig, seq=2000, length=200)
    assert max_contig == 2200

    # A later packet starting before the high-water mark is out-of-order.
    assert detect_out_of_order(seq=2100, length=50, max_contig=max_contig)

    # New in-order data may extend the window and clear the alert condition.
    max_contig = advance_max_contig(max_contig, seq=2200, length=100)
    assert max_contig == 2300
    assert not detect_out_of_order(seq=2300, length=50, max_contig=max_contig)
