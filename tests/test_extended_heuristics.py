"""Tests for extended congestion and anomaly heuristics."""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.parser.pcap_reader import (
    FlowState,
    PacketInfo,
    _maybe_emit_control_plane_anomalies,
    _maybe_infer_loss,
    _maybe_infer_retrans_timeout,
    SYN_TIMEOUT_SECONDS,
    ACK_STALL_THRESHOLD_MS,
)


def _packet(ts: float, flags: str = "A", seq: int = 0, ack: int = 0) -> PacketInfo:
    return PacketInfo(
        ts=ts,
        src="10.0.0.1",
        dst="10.0.0.2",
        sport=12345,
        dport=80,
        seq=seq,
        ack=ack,
        payload_len=0,
        flags=flags,
    )


def test_syn_timeout_triggers_anomaly() -> None:
    state = FlowState()
    flow_id = "10.0.0.1:12345->10.0.0.2:80"

    # Initial SYN
    syn_pkt = _packet(0.0, flags="S")
    events = _maybe_emit_control_plane_anomalies(state, syn_pkt, flow_id)
    assert len(events) == 0
    assert state.syn_seen
    assert state.syn_ts == 0.0

    # Packet after timeout without SYN-ACK
    # SYN_TIMEOUT_SECONDS is 3.0
    late_pkt = _packet(SYN_TIMEOUT_SECONDS + 0.1, flags="A")
    events = _maybe_emit_control_plane_anomalies(state, late_pkt, flow_id)
    
    assert len(events) == 1
    event = events[0]
    assert event["event"] == "handshake_anomaly"
    assert event["extra"]["reason"] == "syn_timeout"
    assert event["severity"] == "CRITICAL"


def test_rto_threshold_tuning() -> None:
    state = FlowState()
    flow_id = "10.0.0.1:12345->10.0.0.2:80"

    # Prime ACK tracking
    _maybe_infer_loss(state, _packet(0.0, ack=1000), flow_id)
    state.outstanding_segments.append((1000, 1100, 0.0))
    state.last_ack_progress_ts = 0.0
    
    # ACK_STALL_THRESHOLD_MS is 200.0
    # Packet just after threshold
    stall_pkt = _packet(0.201, ack=1000)
    
    event = _maybe_infer_loss(state, stall_pkt, flow_id)
    assert event is not None
    assert event["event"] == "loss_infer"
    assert event["extra"]["reason"] == "ack_stall_timeout"
    assert event["severity"] == "WARNING"


def test_event_severity_fields() -> None:
    state = FlowState()
    flow_id = "10.0.0.1:12345->10.0.0.2:80"

    # 1. Loss Inference (Triple Dup ACK) -> WARNING
    _maybe_infer_loss(state, _packet(0.0, ack=1000), flow_id)
    _maybe_infer_loss(state, _packet(0.1, ack=1000), flow_id)
    event = _maybe_infer_loss(state, _packet(0.2, ack=1000), flow_id)
    
    assert event is not None
    assert event["severity"] == "WARNING"

    # 2. RST Storm -> WARNING
    state = FlowState() # Reset state
    events = []
    for _ in range(3):
        events.extend(_maybe_emit_control_plane_anomalies(state, _packet(0.0, flags="R"), flow_id))
    
    assert any(e["event"] == "teardown_anomaly" and e["severity"] == "WARNING" for e in events)

