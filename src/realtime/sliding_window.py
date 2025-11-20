"""Per-flow sliding window monitoring for retransmission alerts."""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime
from typing import Deque, Dict, Optional, Tuple

from tcpviz.src.logging_utils import get_logger

Event = Dict[str, object]
LOGGER = get_logger(__name__)

WARN_THRESHOLD = 10
CRITICAL_THRESHOLD = 50
COLOR_WARN = "\033[93m"
COLOR_CRITICAL = "\033[91m"
COLOR_RESET = "\033[0m"


class SlidingWindowMonitor:
    """Track event counts per-flow and emit threshold alerts."""

    def __init__(
        self,
        window_seconds: int = 60,
        threshold: int = 10,
        thresholds: Optional[Dict[str, int]] = None,
        warn_thresholds: Optional[Dict[str, int]] = None,
        critical_thresholds: Optional[Dict[str, int]] = None,
        event_name: str = "retransmission",
        enable_color: bool = True,
    ) -> None:
        self.window_seconds = window_seconds
        self.threshold = threshold
        self.thresholds = thresholds or {}
        self.warn_thresholds = warn_thresholds or {}
        self.critical_thresholds = critical_thresholds or {}
        self.event_name = event_name
        self.enable_color = enable_color
        self._flow_windows: Dict[str, Dict[str, Deque[float]]] = defaultdict(lambda: defaultdict(deque))
        self._alerted_flows: Dict[Tuple[str, str], str] = {}

    def add(self, event: Event) -> None:
        ts = float(event.get("ts", 0.0))
        flow_id = event.get("flow_id")
        if not flow_id:
            return

        self._trim_flows(ts)

        event_name = str(event.get("event", ""))
        window = self._flow_windows[event_name][str(flow_id)]
        window.append(ts)

    def maybe_alert(self, now: Optional[float] = None) -> None:
        now_ts = float(now if now is not None else 0.0)
        if now_ts <= 0:
            from time import time as _time

            now_ts = _time()

        self._trim_flows(now_ts)

        for event_name, flow_windows in list(self._flow_windows.items()):
            for flow_id, window in list(flow_windows.items()):
                count = len(window)
                severity = self._determine_severity(event_name, count)

                threshold = self._threshold(event_name)
                if severity is None or count < threshold:
                    if (event_name, flow_id) in self._alerted_flows:
                        LOGGER.debug("Clearing alert state for %s/%s", event_name, flow_id)
                        self._alerted_flows.pop((event_name, flow_id), None)
                    if not window:
                        flow_windows.pop(flow_id, None)
                    continue

                previous = self._alerted_flows.get((event_name, flow_id))
                if previous == severity:
                    continue

                iso_time = datetime.fromtimestamp(now_ts).isoformat()
                alert = {
                    "severity": severity,
                    "event": event_name,
                    "flow": flow_id,
                    "count": count,
                    "window_seconds": self.window_seconds,
                    "thresholds": {
                        "alert": threshold,
                        "warn": self._warn_threshold(event_name),
                        "critical": self._critical_threshold(event_name),
                    },
                    "timestamp": iso_time,
                }
                message = self._apply_color(
                    f"[{severity}] {iso_time} flow={flow_id} event={event_name} count={count} "
                    f"window={self.window_seconds}s threshold={threshold}",
                    severity,
                )

                if severity == "CRITICAL":
                    LOGGER.error("%s | %s", message, alert)
                elif severity == "WARN":
                    LOGGER.warning("%s | %s", message, alert)
                else:
                    LOGGER.info("%s | %s", message, alert)

                self._alerted_flows[(event_name, flow_id)] = severity

                if not window:
                    flow_windows.pop(flow_id, None)

    def _apply_color(self, message: str, severity: str) -> str:
        if not self.enable_color:
            return message
        if severity == "CRITICAL":
            return f"{COLOR_CRITICAL}{message}{COLOR_RESET}"
        if severity == "WARN":
            return f"{COLOR_WARN}{message}{COLOR_RESET}"
        return message

    def _determine_severity(self, event: str, count: int) -> Optional[str]:
        if count >= self._critical_threshold(event):
            return "CRITICAL"
        if count >= max(self._threshold(event), self._warn_threshold(event)):
            return "WARN"
        if count >= self._threshold(event):
            return "ALERT"
        return None

    def _trim_flows(self, now: float) -> None:
        cutoff = now - self.window_seconds
        for event_name, flow_windows in list(self._flow_windows.items()):
            for flow_id, window in list(flow_windows.items()):
                while window and window[0] < cutoff:
                    window.popleft()
                if not window:
                    flow_windows.pop(flow_id, None)
                    self._alerted_flows.pop((event_name, flow_id), None)
            if not flow_windows:
                self._flow_windows.pop(event_name, None)

    def snapshot(self) -> Dict[str, int]:
        snapshot: Dict[str, int] = {}
        for event_name, flow_windows in self._flow_windows.items():
            for flow_id, window in flow_windows.items():
                snapshot[f"{event_name}:{flow_id}"] = len(window)
        return snapshot

    def _threshold(self, event: str) -> int:
        return int(self.thresholds.get(event, self.threshold))

    def _warn_threshold(self, event: str) -> int:
        return int(self.warn_thresholds.get(event, WARN_THRESHOLD))

    def _critical_threshold(self, event: str) -> int:
        return int(self.critical_thresholds.get(event, CRITICAL_THRESHOLD))


__all__ = ["SlidingWindowMonitor"]
