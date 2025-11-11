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
