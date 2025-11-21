"""Tests for packet-loss inference heuristics."""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.parser.pcap_reader import FlowState, PacketInfo, _maybe_infer_loss


def _packet(ts: float, ack: int) -> PacketInfo:
    return PacketInfo(
        ts=ts,
        src="10.0.0.1",
        dst="10.0.0.2",
        sport=12345,
        dport=80,
        seq=None,
        ack=ack,
        payload_len=0,
        flags="A",
    )


def test_triple_duplicate_ack_triggers_loss_event() -> None:
    state = FlowState()
    flow_id = "10.0.0.1:12345->10.0.0.2:80"

    assert _maybe_infer_loss(state, _packet(0.0, 1000), flow_id) is None
    assert _maybe_infer_loss(state, _packet(0.1, 1000), flow_id) is None

    event = _maybe_infer_loss(state, _packet(0.2, 1000), flow_id)
    assert event is not None
    assert event["event"] == "loss_infer"
    assert event["ack"] == 1000
    assert event["extra"]["reason"] == "triple_duplicate_ack"


def test_ack_progress_resets_duplicate_counter() -> None:
    state = FlowState()
    flow_id = "10.0.0.1:12345->10.0.0.2:80"

    _maybe_infer_loss(state, _packet(0.0, 1000), flow_id)
    _maybe_infer_loss(state, _packet(0.1, 1000), flow_id)
    assert _maybe_infer_loss(state, _packet(0.2, 1500), flow_id) is None

    # Should require three duplicates for the new ACK value
    assert _maybe_infer_loss(state, _packet(0.3, 1500), flow_id) is None
    event = _maybe_infer_loss(state, _packet(0.4, 1500), flow_id)
    assert event is not None
    assert event["ack"] == 1500
    assert event["extra"]["dup_acks"] >= 3


def test_ack_stall_infers_loss_event_after_timeout() -> None:
    state = FlowState()
    flow_id = "10.0.0.1:12345->10.0.0.2:80"

    # Prime ACK tracking and outstanding data.
    _maybe_infer_loss(state, _packet(0.0, 2000), flow_id)
    state.outstanding_segments.append((2000, 2100, 0.0))
    state.last_ack_progress_ts = 0.0

    event = _maybe_infer_loss(state, _packet(0.5, 2000), flow_id)
    assert event is not None
    assert event["event"] == "loss_infer"
    assert event["extra"]["reason"] == "ack_stall_timeout"


def test_retransmission_without_dup_acks_infers_loss() -> None:
    state = FlowState()
    flow_id = "10.0.0.1:12345->10.0.0.2:80"

    # Track last ACK and outstanding data to mirror a stalled flow without dup ACKs.
    state.last_ack = 3000
    state.last_ack_progress_ts = 0.0
    state.outstanding_segments.append((3000, 3100, 0.0))
    packet = PacketInfo(
        ts=1.0,
        src="10.0.0.1",
        dst="10.0.0.2",
        sport=12345,
        dport=80,
        seq=3000,
        ack=None,
        payload_len=100,
        flags="A",
    )

    event = _maybe_infer_loss(state, packet, flow_id)
    assert event is None  # no dup-ack or stall yet
    # Simulate retransmission path calling timeout heuristic.
    from src.parser.pcap_reader import _maybe_infer_retrans_timeout

    timeout_event = _maybe_infer_retrans_timeout(state, packet, flow_id)
    assert timeout_event is not None
    assert timeout_event["event"] == "loss_infer"
    assert timeout_event["extra"]["reason"] == "retransmission_without_dup_acks"
