"""Per-flow sliding window monitoring for retransmission alerts."""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime
from typing import Deque, Dict, Optional

from tcpviz.src.logging_utils import get_logger

Event = Dict[str, object]
LOGGER = get_logger(__name__)

WARN_THRESHOLD = 10
CRITICAL_THRESHOLD = 50
COLOR_WARN = "\033[93m"
COLOR_CRITICAL = "\033[91m"
COLOR_RESET = "\033[0m"


class SlidingWindowMonitor:
    """Track retransmission counts per-flow and emit threshold alerts."""

    def __init__(
        self,
        window_seconds: int = 60,
        threshold: int = 10,
        event_name: str = "retransmission",
        enable_color: bool = True,
    ) -> None:
        self.window_seconds = window_seconds
        self.threshold = threshold
        self.event_name = event_name
        self.enable_color = enable_color
        self._flow_windows: Dict[str, Deque[float]] = defaultdict(deque)
        self._alerted_flows: Dict[str, str] = {}

    def add(self, event: Event) -> None:
        ts = float(event.get("ts", 0.0))
        flow_id = event.get("flow_id")
        if not flow_id:
            return

        self._trim_flows(ts)

        if event.get("event") != self.event_name:
            return

        window = self._flow_windows[str(flow_id)]
        window.append(ts)

    def maybe_alert(self, now: Optional[float] = None) -> None:
        now_ts = float(now if now is not None else 0.0)
        if now_ts <= 0:
            from time import time as _time

            now_ts = _time()

        self._trim_flows(now_ts)

        for flow_id, window in list(self._flow_windows.items()):
            count = len(window)
            severity = self._determine_severity(count)

            if severity is None or count < self.threshold:
                if flow_id in self._alerted_flows:
                    LOGGER.debug("Clearing alert state for flow %s", flow_id)
                    self._alerted_flows.pop(flow_id, None)
                if not window:
                    self._flow_windows.pop(flow_id, None)
                continue

            previous = self._alerted_flows.get(flow_id)
            if previous == severity:
                continue

            iso_time = datetime.fromtimestamp(now_ts).isoformat()
            message = (
                f"[{severity}] {iso_time} flow={flow_id} retransmissions={count} "
                f"window={self.window_seconds}s threshold={self.threshold}"
            )
            message = self._apply_color(message, severity)

            if severity == "CRITICAL":
                LOGGER.error(message)
            elif severity == "WARN":
                LOGGER.warning(message)
            else:
                LOGGER.info(message)

            self._alerted_flows[flow_id] = severity

            if not window:
                self._flow_windows.pop(flow_id, None)

    def _apply_color(self, message: str, severity: str) -> str:
        if not self.enable_color:
            return message
        if severity == "CRITICAL":
            return f"{COLOR_CRITICAL}{message}{COLOR_RESET}"
        if severity == "WARN":
            return f"{COLOR_WARN}{message}{COLOR_RESET}"
        return message

    def _determine_severity(self, count: int) -> Optional[str]:
        if count >= CRITICAL_THRESHOLD:
            return "CRITICAL"
        if count >= max(self.threshold, WARN_THRESHOLD):
            return "WARN"
        if count >= self.threshold:
            return "ALERT"
        return None

    def _trim_flows(self, now: float) -> None:
        cutoff = now - self.window_seconds
        for flow_id, window in list(self._flow_windows.items()):
            while window and window[0] < cutoff:
                window.popleft()
            if not window:
                self._flow_windows.pop(flow_id, None)
                self._alerted_flows.pop(flow_id, None)

    def snapshot(self) -> Dict[str, int]:
        return {flow_id: len(window) for flow_id, window in self._flow_windows.items()}


__all__ = ["SlidingWindowMonitor"]
