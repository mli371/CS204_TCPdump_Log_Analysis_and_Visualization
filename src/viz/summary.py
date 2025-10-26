"""Summaries for TCP event collections."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Mapping

import plotly.express as px

from tcpviz.src.logging_utils import get_logger

Event = Mapping[str, object]
LOGGER = get_logger(__name__)

EVENTS_OF_INTEREST = {"retransmission", "out_of_order"}


def summarize(events: Iterable[Event]) -> Counter:
    """Count events by type."""

    counter: Counter = Counter()
    for event in events:
        counter[str(event.get("event", "unknown"))] += 1
    return counter


def render_summary(events_path: str | Path, output_dir: str | Path | None = None) -> Path:
    """Render a per-flow summary chart for retransmissions and out-of-order events."""

    events_file = Path(events_path)
    events = _load_events(events_file)

    counts: Dict[str, Dict[str, int]] = {}
    for event in events:
        flow_id = event.get("flow_id")
        event_name = event.get("event")
        if not flow_id or event_name not in EVENTS_OF_INTEREST:
            continue
        flow_counts = counts.setdefault(str(flow_id), {"retransmission": 0, "out_of_order": 0})
        flow_counts[str(event_name)] = flow_counts.get(str(event_name), 0) + 1

    rows: List[Dict[str, object]] = []
    for flow_id, metrics in counts.items():
        for event_name, value in metrics.items():
            if value <= 0:
                continue
            rows.append({"flow_id": flow_id, "event": event_name, "count": value})

    target_dir = Path(output_dir) if output_dir else events_file.parent
    target_dir.mkdir(parents=True, exist_ok=True)
    output_path = target_dir / "summary.html"

    if not rows:
        placeholder = """
        <!DOCTYPE html>
        <html lang="en">
        <head><meta charset="utf-8"><title>tcpviz summary</title></head>
        <body><h1>tcpviz summary</h1><p>No retransmission/out_of_order events available.</p></body>
        </html>
        """
        output_path.write_text(placeholder, encoding="utf-8")
        LOGGER.info("No summary events for %s; wrote placeholder to %s", events_path, output_path)
        return output_path

    fig = px.bar(
        rows,
        x="flow_id",
        y="count",
        color="event",
        barmode="group",
        labels={"flow_id": "Flow", "count": "Event count", "event": "Event type"},
        title="tcpviz flow summary",
    )

    fig.update_layout(margin=dict(l=40, r=40, t=80, b=40))

    fig.write_html(output_path, include_plotlyjs="cdn", full_html=True)
    LOGGER.info("Wrote summary chart with %s data points to %s", len(rows), output_path)
    return output_path


def _load_events(events_path: Path) -> List[dict]:
    events: List[dict] = []
    with events_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                LOGGER.debug("Skipping malformed JSONL line in %s: %s", events_path, line)
    return events


__all__ = ["render_summary", "summarize"]
