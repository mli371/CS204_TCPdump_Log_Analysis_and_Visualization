"""PCAP reader utilities producing canonical TCP events."""

from __future__ import annotations

import contextlib
import logging
from collections import defaultdict
from dataclasses import asdict, dataclass, field
import ipaddress
from pathlib import Path
from time import perf_counter
from typing import Any, Callable, Dict, Iterator, List, MutableMapping, Optional, Tuple

from tcpviz.src.logging_utils import get_logger
from tcpviz.src.detectors.out_of_order import advance_max_contig, detect_out_of_order
from tcpviz.src.detectors.retrans import detect_retransmissions, record_range

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
    event_counts: Dict[str, int] = {name: 0 for name in ("retransmission", "out_of_order")}

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

            if seq is not None and length > 0 and end is not None:
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

            for event_name in dict.fromkeys(triggered):
                event_counts[event_name] = event_counts.get(event_name, 0) + 1
                flow_event_breakdown[flow_id][event_name] += 1

                extra: Dict[str, Any] = {}
                if event_name == "retransmission":
                    extra["reason"] = "segment_overlap"
                if event_name == "out_of_order":
                    extra["max_contig_seq_sent_before"] = previous_max

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
        "event_counts": {name: 0 for name in ("retransmission", "out_of_order")},
        "top_flows": [],
    }


def _build_flow_id(src: str, sport: int, dst: str, dport: int) -> str:
    return f"{src}:{sport}->{dst}:{dport}"


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


__all__ = ["Event", "parse_pcap"]
