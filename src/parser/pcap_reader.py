"""PCAP reader utilities producing canonical TCP events."""

from __future__ import annotations

import contextlib
import logging
from collections import defaultdict
from dataclasses import asdict, dataclass, field
import ipaddress
from collections import deque
from pathlib import Path
from time import perf_counter
from typing import Any, Callable, Deque, Dict, Iterator, List, MutableMapping, Optional, Tuple

from src.logging_utils import get_logger
from src.detectors.out_of_order import advance_max_contig, detect_out_of_order
from src.detectors.retrans import detect_retransmissions, record_range

try:  # pyshark preferred
    import pyshark  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    pyshark = None  # type: ignore

try:
    import dpkt  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    dpkt = None  # type: ignore


_BACKEND_WARNINGS_EMITTED: set[str] = set()
LOGGER = get_logger(__name__)
DUP_ACK_THRESHOLD = 3
ACK_STALL_THRESHOLD_MS = 400.0
ACK_STALL_RTT_MULTIPLIER = 4.0


def _log_backend(message: str, level: int = logging.INFO) -> None:
    LOGGER.log(level=level, msg=message)


@dataclass
class Event:
    """Canonical representation for TCP timeline events."""

    ts: float
    event: str
    flow_id: str
    src: str
    dst: str
    sport: int
    dport: int
    seq: Optional[int]
    ack: Optional[int]
    length: Optional[int]
    flags: Optional[str]
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["len"] = data.pop("length")
        return data


@dataclass
class FlowState:
    """Per-flow bookkeeping for retransmission and reordering detection."""

    max_contig_seq_sent: Optional[int] = None
    seen_ranges: List[Tuple[int, int]] = field(default_factory=list)
    last_ack: Optional[int] = None
    last_ack_progress_ts: Optional[float] = None
    dup_ack_count: int = 0
    last_loss_ack: Optional[int] = None
    outstanding_segments: Deque[Tuple[int, int, float]] = field(default_factory=deque)
    cwnd_bytes: int = 0
    max_cwnd_bytes: int = 0
    rtt_ema_ms: Optional[float] = None
    rtt_sample_count: int = 0
    syn_seen: bool = False
    syn_ack_seen: bool = False
    syn_retry_count: int = 0
    syn_anomaly_reported: bool = False
    fin_count: int = 0
    fin_anomaly_reported: bool = False
    rst_count: int = 0
    rst_anomaly_reported: bool = False
    zero_window_count: int = 0


@dataclass
class PacketInfo:
    """Minimal packet representation extracted from captures."""

    ts: float
    src: str
    dst: str
    sport: int
    dport: int
    seq: Optional[int]
    ack: Optional[int]
    payload_len: int
    flags: Optional[str]
    window_size: Optional[int] = None


def parse_pcap(pcap_path: str | Path, benchmark_dir: Path | None = None) -> Dict[str, Any]:
    """Parse a PCAP/PCAPNG file and emit retransmission/out-of-order events."""

    path = Path(pcap_path)
    if not path.exists():
        raise FileNotFoundError(f"PCAP not found: {path}")

    if path.stat().st_size == 0:
        return _empty_summary()

    LOGGER.debug("Parsing capture %s", path)

    backends = _backend_iterators(path)
    if not backends:
        raise RuntimeError(f"Failed to parse {path}: no parsing backend available")

    errors: List[Tuple[str, Exception]] = []

    for backend_name, factory in backends:
        _log_backend(f"attempting {backend_name} backend for {path}")
        try:
            packet_iter = factory()
        except Exception as exc:
            errors.append((backend_name, exc))
            _log_backend(f"{backend_name} backend initialization failed: {exc}")
            continue

        start = perf_counter()
        try:
            summary = _consume_packets(packet_iter)
        except Exception as exc:
            errors.append((backend_name, exc))
            _log_backend(f"{backend_name} backend failed ({exc}); trying fallback")
            continue
        duration = perf_counter() - start
        summary["duration_seconds"] = duration

        _log_backend(
            f"using {backend_name} backend for {path}",
            level=logging.DEBUG if LOGGER.isEnabledFor(logging.DEBUG) else logging.INFO,
        )
        summary["backend"] = backend_name
        events_count = len(summary.get("events", []))
        total_packets = summary.get("total_packets", 0)
        throughput = (total_packets / duration) if duration > 0 else 0.0
        if benchmark_dir is not None:
            try:
                benchmark_dir.mkdir(parents=True, exist_ok=True)
                log_path = benchmark_dir / "benchmark.log"
                with log_path.open("a", encoding="utf-8") as handle:
                    handle.write(
                        "Backend={backend}\nTotal packets={total}\nParsed events={events}\n"
                        "Duration={duration_ms:.3f} ms\nThroughput={throughput:.2f} packets/s\n\n".format(
                            backend=backend_name,
                            total=total_packets,
                            events=events_count,
                            duration_ms=duration * 1000,
                            throughput=throughput,
                        )
                    )
            except OSError as exc:  # pragma: no cover - filesystem issues
                LOGGER.warning("Failed to write benchmark log: %s", exc)
        LOGGER.info(
            "Parsed %s packets (%s skipped, %s events) using %s backend in %.3f ms (%.2f packets/s)",
            total_packets,
            summary.get("skipped_packets", 0),
            events_count,
            backend_name,
            duration * 1000,
            throughput,
        )
        return summary

    if errors:
        names = ", ".join(name for name, _ in errors)
        last_exc = errors[-1][1]
        raise RuntimeError(f"Failed to parse {path} using backends: {names}") from last_exc

    raise RuntimeError(f"Failed to parse {path}: unable to initialise parsing backend")


def _consume_packets(packet_iter: Iterator[PacketInfo]) -> Dict[str, Any]:
    events: List[Dict[str, Any]] = []
    flow_states: Dict[str, FlowState] = defaultdict(FlowState)
    flow_event_breakdown: Dict[str, MutableMapping[str, int]] = defaultdict(lambda: defaultdict(int))
    event_counts: Dict[str, int] = {
        name: 0
        for name in (
            "retransmission",
            "out_of_order",
            "loss_infer",
            "handshake_anomaly",
            "teardown_anomaly",
            "zero_window",
        )
    }

    total_packets = 0
    skipped_packets = 0

    try:
        for packet in packet_iter:
            total_packets += 1

            if not packet.src or not packet.dst:
                skipped_packets += 1
                LOGGER.debug("Skipping packet without IP information: %s", packet)
                continue

            flow_id = _build_flow_id(packet.src, packet.sport, packet.dst, packet.dport)
            state = flow_states[flow_id]
            previous_max = state.max_contig_seq_sent

            length = packet.payload_len
            seq = packet.seq
            triggered: List[str] = []

            start = seq if seq is not None else None
            end = seq + length if seq is not None else None

            anomaly_events = _maybe_emit_control_plane_anomalies(state, packet, flow_id)
            for anomaly in anomaly_events:
                events.append(anomaly)
                name = anomaly.get("event")
                if name:
                    event_counts[name] = event_counts.get(name, 0) + 1
                    flow_event_breakdown[flow_id][name] += 1

            loss_event = _maybe_infer_loss(state, packet, flow_id)
            if loss_event:
                events.append(loss_event)
                event_counts["loss_infer"] = event_counts.get("loss_infer", 0) + 1
                flow_event_breakdown[flow_id]["loss_infer"] += 1

            if seq is not None and length > 0 and end is not None:
                _record_outstanding_segment(state, seq, end, packet.ts)
                if detect_retransmissions(state.seen_ranges, start, end):
                    triggered.append("retransmission")
                if detect_out_of_order(seq, length, state.max_contig_seq_sent):
                    triggered.append("out_of_order")
                record_range(state.seen_ranges, start, end)
                state.max_contig_seq_sent = advance_max_contig(state.max_contig_seq_sent, seq, length)
            elif seq is not None:
                state.max_contig_seq_sent = advance_max_contig(state.max_contig_seq_sent, seq, length)

            if not triggered:
                continue

            if "retransmission" in triggered:
                timeout_loss = _maybe_infer_retrans_timeout(state, packet, flow_id)
                if timeout_loss:
                    events.append(timeout_loss)
                    event_counts["loss_infer"] = event_counts.get("loss_infer", 0) + 1
                    flow_event_breakdown[flow_id]["loss_infer"] += 1

            for event_name in dict.fromkeys(triggered):
                event_counts[event_name] = event_counts.get(event_name, 0) + 1
                flow_event_breakdown[flow_id][event_name] += 1

                extra: Dict[str, Any] = {}
                if event_name == "retransmission":
                    extra["reason"] = "segment_overlap"
                if event_name == "out_of_order":
                    extra["max_contig_seq_sent_before"] = previous_max
                _attach_congestion_snapshot(extra, state)

                event_obj = Event(
                    ts=packet.ts,
                    event=event_name,
                    flow_id=flow_id,
                    src=packet.src,
                    dst=packet.dst,
                    sport=packet.sport,
                    dport=packet.dport,
                    seq=seq,
                    ack=packet.ack,
                    length=length if length >= 0 else None,
                    flags=packet.flags,
                    extra=extra,
                )
                events.append(event_obj.to_dict())
    finally:
        _close_iterator(packet_iter)

    top_flows = sorted(
        (
            (flow_id, sum(event_counts_per_flow.values()), event_counts_per_flow)
            for flow_id, event_counts_per_flow in flow_event_breakdown.items()
        ),
        key=lambda item: item[1],
        reverse=True,
    )[:3]

    summary = {
        "events": events,
        "total_packets": total_packets,
        "tcp_packets": total_packets - skipped_packets,
        "event_counts": event_counts,
        "top_flows": [
            {
                "flow_id": flow_id,
                "event_count": count,
                "event_breakdown": dict(event_breakdown),
            }
            for flow_id, count, event_breakdown in top_flows
        ],
        "skipped_packets": skipped_packets,
        "flow_metrics": _build_flow_metrics(flow_states),
    }

    return summary


def _close_iterator(packet_iter: Iterator[PacketInfo]) -> None:
    close = getattr(packet_iter, "close", None)
    if callable(close):
        with contextlib.suppress(Exception):
            close()


def _backend_iterators(path: Path) -> List[Tuple[str, Callable[[], Iterator[PacketInfo]]]]:
    factories: List[Tuple[str, Callable[[], Iterator[PacketInfo]]]] = []

    if pyshark is not None:
        factories.append(("pyshark", lambda p=path: _iter_pyshark_packets(p)))
    else:
        if "pyshark_missing" not in _BACKEND_WARNINGS_EMITTED:
            _log_backend("pyshark backend unavailable (module not installed); falling back to dpkt")
            _BACKEND_WARNINGS_EMITTED.add("pyshark_missing")

    if dpkt is not None:
        factories.append(("dpkt", lambda p=path: _iter_dpkt_packets(p)))
    else:
        if "dpkt_missing" not in _BACKEND_WARNINGS_EMITTED:
            _log_backend("dpkt backend unavailable; TCP parsing will be limited")
            _BACKEND_WARNINGS_EMITTED.add("dpkt_missing")

    return factories


def _empty_summary() -> Dict[str, Any]:
    return {
        "events": [],
        "total_packets": 0,
        "tcp_packets": 0,
        "event_counts": {name: 0 for name in ("retransmission", "out_of_order", "loss_infer")},
        "top_flows": [],
        "flow_metrics": [],
    }


def _build_flow_id(src: str, sport: int, dst: str, dport: int) -> str:
    return f"{src}:{sport}->{dst}:{dport}"


def _maybe_infer_loss(state: FlowState, packet: PacketInfo, flow_id: str) -> Optional[Dict[str, Any]]:
    ack = packet.ack
    if ack is None:
        return None

    ack_value = int(ack)

    if state.last_ack is None or ack_value > state.last_ack:
        _handle_ack_progress(state, ack_value, packet.ts)
        state.last_ack = ack_value
        state.last_ack_progress_ts = packet.ts
        state.dup_ack_count = 1
        state.last_loss_ack = None
        return None

    if ack_value == state.last_ack:
        state.dup_ack_count += 1
    else:
        state.last_ack = ack_value
        state.dup_ack_count = 1
        return None

    stall_event = _maybe_emit_ack_stall(state, packet, flow_id, ack_value)
    if stall_event:
        return stall_event

    if state.dup_ack_count >= max(DUP_ACK_THRESHOLD, 1) and state.last_loss_ack != ack_value:
        state.last_loss_ack = ack_value
        event = {
            "ts": packet.ts,
            "event": "loss_infer",
            "flow_id": flow_id,
            "src": packet.src,
            "dst": packet.dst,
            "sport": packet.sport,
            "dport": packet.dport,
            "seq": packet.seq,
            "ack": packet.ack,
            "len": packet.payload_len if packet.payload_len >= 0 else None,
            "flags": packet.flags,
            "extra": {
                "reason": "triple_duplicate_ack",
                "dup_acks": state.dup_ack_count,
            },
        }
        _attach_congestion_snapshot(event["extra"], state)
        return event

    return None


def _record_outstanding_segment(state: FlowState, seq_start: int, seq_end: int, ts: float) -> None:
    length = max(seq_end - seq_start, 0)
    if length <= 0:
        return
    state.outstanding_segments.append((seq_start, seq_end, ts))
    state.cwnd_bytes += length
    state.max_cwnd_bytes = max(state.max_cwnd_bytes, state.cwnd_bytes)


def _handle_ack_progress(state: FlowState, ack_value: int, ts: float) -> None:
    while state.outstanding_segments and ack_value >= state.outstanding_segments[0][1]:
        start, end, sent_ts = state.outstanding_segments.popleft()
        seg_len = max(end - start, 0)
        state.cwnd_bytes = max(state.cwnd_bytes - seg_len, 0)
        sample_ms = max((ts - sent_ts) * 1000.0, 0.0)
        _update_rtt(state, sample_ms)


def _maybe_infer_retrans_timeout(
    state: FlowState, packet: PacketInfo, flow_id: str
) -> Optional[Dict[str, Any]]:
    ack_value = state.last_ack
    if ack_value is None:
        return None
    if state.dup_ack_count >= max(DUP_ACK_THRESHOLD, 1):
        return None
    if state.last_loss_ack == ack_value:
        return None

    stall_ms = None
    threshold_ms = _stall_threshold_ms(state)
    if state.last_ack_progress_ts is not None:
        stall_ms = max((packet.ts - state.last_ack_progress_ts) * 1000.0, 0.0)

    state.last_loss_ack = ack_value
    event = {
        "ts": packet.ts,
        "event": "loss_infer",
        "flow_id": flow_id,
        "src": packet.src,
        "dst": packet.dst,
        "sport": packet.sport,
        "dport": packet.dport,
        "seq": packet.seq,
        "ack": packet.ack,
        "len": packet.payload_len if packet.payload_len >= 0 else None,
        "flags": packet.flags,
        "extra": {
            "reason": "retransmission_without_dup_acks",
            "dup_acks": state.dup_ack_count,
            "stall_ms": stall_ms,
            "threshold_ms": threshold_ms,
        },
    }
    _attach_congestion_snapshot(event["extra"], state)
    return event


def _maybe_emit_control_plane_anomalies(
    state: FlowState, packet: PacketInfo, flow_id: str
) -> List[Dict[str, Any]]:
    flags = packet.flags or ""
    emitted: List[Dict[str, Any]] = []

    if "S" in flags and "A" not in flags:
        if not state.syn_seen:
            state.syn_seen = True
            state.syn_retry_count = 1
        else:
            state.syn_retry_count += 1
            if not state.syn_ack_seen and not state.syn_anomaly_reported and state.syn_retry_count >= 3:
                event = _build_event(
                    "handshake_anomaly",
                    packet,
                    flow_id,
                    reason="syn_retry_without_synack",
                    retries=state.syn_retry_count,
                )
                _attach_congestion_snapshot(event["extra"], state)
                emitted.append(event)
                state.syn_anomaly_reported = True
    if "S" in flags and "A" in flags:
        state.syn_ack_seen = True

    if "R" in flags:
        state.rst_count += 1
        if not state.rst_anomaly_reported and state.rst_count >= 2:
            event = _build_event(
                "teardown_anomaly",
                packet,
                flow_id,
                reason="rst_storm",
                rst_count=state.rst_count,
            )
            _attach_congestion_snapshot(event["extra"], state)
            emitted.append(event)
            state.rst_anomaly_reported = True

    if "F" in flags:
        state.fin_count += 1
        if not state.fin_anomaly_reported and state.fin_count >= 4:
            event = _build_event(
                "teardown_anomaly",
                packet,
                flow_id,
                reason="fin_storm",
                fin_count=state.fin_count,
            )
            _attach_congestion_snapshot(event["extra"], state)
            emitted.append(event)
            state.fin_anomaly_reported = True

    if packet.window_size == 0:
        state.zero_window_count += 1
        event = _build_event(
            "zero_window",
            packet,
            flow_id,
            reason="zero_window_advertisement",
            zero_window_count=state.zero_window_count,
        )
        _attach_congestion_snapshot(event["extra"], state)
        emitted.append(event)

    return emitted


def _build_event(
    name: str,
    packet: PacketInfo,
    flow_id: str,
    **extra_fields: Any,
) -> Dict[str, Any]:
    extra: Dict[str, Any] = {"reason": extra_fields.pop("reason", None)}
    extra.update({k: v for k, v in extra_fields.items() if v is not None})
    event = {
        "ts": packet.ts,
        "event": name,
        "flow_id": flow_id,
        "src": packet.src,
        "dst": packet.dst,
        "sport": packet.sport,
        "dport": packet.dport,
        "seq": packet.seq,
        "ack": packet.ack,
        "len": packet.payload_len if packet.payload_len >= 0 else None,
        "flags": packet.flags,
        "extra": extra,
    }
    return event


def _maybe_emit_ack_stall(
    state: FlowState, packet: PacketInfo, flow_id: str, ack_value: int
) -> Optional[Dict[str, Any]]:
    if not state.outstanding_segments:
        return None
    if state.last_ack_progress_ts is None:
        return None

    stall_ms = max((packet.ts - state.last_ack_progress_ts) * 1000.0, 0.0)
    threshold_ms = _stall_threshold_ms(state)
    if stall_ms < threshold_ms:
        return None
    if state.last_loss_ack == ack_value:
        return None

    state.last_loss_ack = ack_value
    event = {
        "ts": packet.ts,
        "event": "loss_infer",
        "flow_id": flow_id,
        "src": packet.src,
        "dst": packet.dst,
        "sport": packet.sport,
        "dport": packet.dport,
        "seq": packet.seq,
        "ack": packet.ack,
        "len": packet.payload_len if packet.payload_len >= 0 else None,
        "flags": packet.flags,
        "extra": {
            "reason": "ack_stall_timeout",
            "stall_ms": stall_ms,
            "dup_acks": state.dup_ack_count,
            "outstanding_segments": len(state.outstanding_segments),
            "threshold_ms": threshold_ms,
        },
    }
    _attach_congestion_snapshot(event["extra"], state)
    return event


def _update_rtt(state: FlowState, sample_ms: float, alpha: float = 0.25) -> None:
    if sample_ms <= 0:
        return
    if state.rtt_ema_ms is None:
        state.rtt_ema_ms = sample_ms
    else:
        state.rtt_ema_ms = (1 - alpha) * state.rtt_ema_ms + alpha * sample_ms
    state.rtt_sample_count += 1


def _attach_congestion_snapshot(extra: Dict[str, Any], state: FlowState) -> None:
    extra["cwnd_bytes"] = state.cwnd_bytes
    extra["max_cwnd_bytes"] = state.max_cwnd_bytes
    extra["rtt_ema_ms"] = state.rtt_ema_ms


def _build_flow_metrics(flow_states: Dict[str, FlowState]) -> List[Dict[str, Any]]:
    metrics: List[Dict[str, Any]] = []
    for flow_id, state in flow_states.items():
        metrics.append(
            {
                "flow_id": flow_id,
                "avg_rtt_ms": state.rtt_ema_ms,
                "rtt_samples": state.rtt_sample_count,
                "current_cwnd_bytes": state.cwnd_bytes,
                "max_cwnd_bytes": state.max_cwnd_bytes,
            }
        )
    metrics.sort(key=lambda item: item["max_cwnd_bytes"] or 0, reverse=True)
    return metrics


def _stall_threshold_ms(state: FlowState) -> float:
    if state.rtt_ema_ms is None:
        return ACK_STALL_THRESHOLD_MS
    dynamic = state.rtt_ema_ms * ACK_STALL_RTT_MULTIPLIER
    return max(ACK_STALL_THRESHOLD_MS, dynamic)


def _iter_pyshark_packets(path: Path) -> Iterator[PacketInfo]:
    if pyshark is None:  # pragma: no cover - guarded at call-site
        raise RuntimeError("pyshark backend unavailable")

    capture = pyshark.FileCapture(
        str(path),
        display_filter="tcp",
        keep_packets=False,
        use_json=True,
    )
    try:
        for pkt in capture:
            try:
                ts = float(pkt.sniff_timestamp)
                tcp = getattr(pkt, "tcp", None)
                if tcp is None:
                    continue

                ip_layer = getattr(pkt, "ip", None)
                if ip_layer is None:
                    ip_layer = getattr(pkt, "ipv6", None)
                if ip_layer is None:
                    continue

                src = _string_field(getattr(ip_layer, "src", None))
                dst = _string_field(getattr(ip_layer, "dst", None))
                sport = _int_field(getattr(tcp, "srcport", None))
                dport = _int_field(getattr(tcp, "dstport", None))
                seq = _int_field(getattr(tcp, "seq", None))
                ack = _int_field(getattr(tcp, "ack", None))
                payload_len = _int_field(getattr(tcp, "len", None)) or 0
                flags = _pyshark_flag_string(tcp)
                window_size = _int_field(getattr(tcp, "window_size_value", None))

                if None in (src, dst, sport, dport):
                    continue

                yield PacketInfo(
                    ts=ts,
                    src=src,
                    dst=dst,
                    sport=sport,
                    dport=dport,
                    seq=seq,
                    ack=ack,
                    payload_len=payload_len,
                    flags=flags,
                    window_size=window_size,
                )
            except (AttributeError, ValueError, TypeError):
                continue
    finally:
        with contextlib.suppress(Exception):  # pragma: no cover - cleanup best effort
            capture.close()


def _iter_dpkt_packets(path: Path) -> Iterator[PacketInfo]:
    if dpkt is None:  # pragma: no cover - guarded at call-site
        raise RuntimeError("dpkt backend unavailable")

    with path.open("rb") as handle:
        reader: Any
        try:
            reader = dpkt.pcap.Reader(handle)
        except (dpkt.dpkt.NeedData, ValueError):
            handle.seek(0)
            reader = dpkt.pcapng.Reader(handle)

        datalink = getattr(reader, "datalink", lambda: dpkt.pcap.DLT_EN10MB)()

        for ts, buf in reader:
            try:
                src, dst, sport, dport, seq, ack, payload_len, flags = _decode_dpkt_frame(
                    datalink, buf
                )
                if src is None:
                    continue
                yield PacketInfo(
                    ts=float(ts),
                    src=src,
                    dst=dst,
                    sport=sport,
                    dport=dport,
                    seq=seq,
                    ack=ack,
                    payload_len=payload_len,
                    flags=flags,
                    window_size=getattr(tcp, "win", None),
                )
            except (ValueError, AttributeError, dpkt.UnpackError):
                continue


def _decode_dpkt_frame(
    datalink: int,
    buf: bytes,
) -> Tuple[Optional[str], Optional[str], int, int, Optional[int], Optional[int], int, Optional[str]]:
    if dpkt is None:  # pragma: no cover - guarded at call-site
        return None, None, 0, 0, None, None, 0, None

    ip = None
    if datalink == dpkt.pcap.DLT_EN10MB:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
    elif datalink == dpkt.pcap.DLT_RAW:
        ip = dpkt.ip.IP(buf)
    elif datalink == dpkt.pcap.DLT_NULL:
        ip = dpkt.ip.IP(buf[4:])
    else:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data

    if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
        return None, None, 0, 0, None, None, 0, None

    tcp = ip.data
    if not isinstance(tcp, dpkt.tcp.TCP):
        return None, None, 0, 0, None, None, 0, None

    src = _format_ip(ip.src)
    dst = _format_ip(ip.dst)
    if src is None or dst is None:
        return None, None, 0, 0, None, None, 0, None

    seq = int(tcp.seq)
    ack = int(tcp.ack) if tcp.flags & dpkt.tcp.TH_ACK else None
    payload_len = len(tcp.data)
    flags = _dpkt_flag_string(tcp.flags)

    return src, dst, tcp.sport, tcp.dport, seq, ack, payload_len, flags


def _pyshark_flag_string(tcp_layer: Any) -> Optional[str]:
    flags = []
    mapping = [
        ("flags_fin", "F"),
        ("flags_syn", "S"),
        ("flags_rst", "R"),
        ("flags_push", "P"),
        ("flags_ack", "A"),
        ("flags_urg", "U"),
        ("flags_ece", "E"),
        ("flags_cwr", "C"),
    ]
    for attr, letter in mapping:
        value = getattr(tcp_layer, attr, None)
        if value in ("1", "True", "true", 1):
            flags.append(letter)
    return "|".join(flags) if flags else None


def _dpkt_flag_string(flags: int) -> Optional[str]:
    if dpkt is None:
        return None

    mapping = [
        (dpkt.tcp.TH_FIN, "F"),
        (dpkt.tcp.TH_SYN, "S"),
        (dpkt.tcp.TH_RST, "R"),
        (dpkt.tcp.TH_PUSH, "P"),
        (dpkt.tcp.TH_ACK, "A"),
        (dpkt.tcp.TH_URG, "U"),
        (getattr(dpkt.tcp, "TH_ECE", 0), "E"),
        (getattr(dpkt.tcp, "TH_CWR", 0), "C"),
    ]

    letters = [letter for mask, letter in mapping if mask and flags & mask]
    return "|".join(letters) if letters else None


def _int_field(value: Any) -> Optional[int]:
    if value in (None, ""):
        return None
    try:
        return int(str(value))
    except (ValueError, TypeError):
        return None


def _string_field(value: Any) -> Optional[str]:
    if value is None:
        return None
    return str(value)


def _format_ip(raw: bytes) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return None


__all__ = ["Event", "FlowState", "PacketInfo", "parse_pcap", "_maybe_infer_loss"]
