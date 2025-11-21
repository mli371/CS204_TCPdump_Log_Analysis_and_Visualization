"""Tests for handshake/teardown and zero-window anomaly detection."""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.parser.pcap_reader import FlowState, PacketInfo, _maybe_emit_control_plane_anomalies


def _packet(flags: str, window_size: int | None = None, ts: float = 0.0) -> PacketInfo:
    return PacketInfo(
        ts=ts,
        src="10.0.0.1",
        dst="10.0.0.2",
        sport=12345,
        dport=80,
        seq=1000,
        ack=None,
        payload_len=0,
        flags=flags,
        window_size=window_size,
    )


def test_repeated_syn_without_synack_flags_handshake_anomaly() -> None:
    state = FlowState()
    flow_id = "10.0.0.1:12345->10.0.0.2:80"

    assert _maybe_emit_control_plane_anomalies(state, _packet("S", ts=0.0), flow_id) == []
    assert _maybe_emit_control_plane_anomalies(state, _packet("S", ts=0.1), flow_id) == []
    events = _maybe_emit_control_plane_anomalies(state, _packet("S", ts=0.2), flow_id)

    assert events
    assert events[0]["event"] == "handshake_anomaly"
    assert events[0]["extra"]["reason"] == "syn_retry_without_synack"


def test_rst_storm_triggers_teardown_anomaly_once() -> None:
    state = FlowState()
    flow_id = "10.0.0.1:12345->10.0.0.2:80"

    assert _maybe_emit_control_plane_anomalies(state, _packet("R", ts=0.0), flow_id) == []
    events = _maybe_emit_control_plane_anomalies(state, _packet("R", ts=0.1), flow_id)
    assert events
    assert events[0]["event"] == "teardown_anomaly"
    assert events[0]["extra"]["reason"] == "rst_storm"

    # Subsequent RST should not emit a second anomaly
    assert _maybe_emit_control_plane_anomalies(state, _packet("R", ts=0.2), flow_id) == []


def test_zero_window_advertisement_emits_event() -> None:
    state = FlowState()
    flow_id = "10.0.0.1:12345->10.0.0.2:80"

    events = _maybe_emit_control_plane_anomalies(state, _packet("A", window_size=0, ts=0.0), flow_id)
    assert events
    assert events[0]["event"] == "zero_window"
    assert events[0]["extra"]["reason"] == "zero_window_advertisement"
