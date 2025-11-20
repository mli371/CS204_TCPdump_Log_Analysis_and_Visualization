"""Interactive timeline rendering for TCP events using Plotly."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List

import plotly.express as px

from src.logging_utils import get_logger

LOGGER = get_logger(__name__)


def _load_events(events_path: Path) -> List[dict]:
    events: List[dict] = []
    with events_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line))
    return events


def _to_plot_rows(events: Iterable[dict]) -> List[dict]:
    rows: List[dict] = []
    for event in events:
        ts = event.get("ts")
        flow_id = event.get("flow_id")
        event_type = event.get("event")

        if ts is None or flow_id is None or event_type is None:
            continue

        rows.append(
            {
                "timestamp": float(ts),
                "flow_id": str(flow_id),
                "event": str(event_type),
                "seq": event.get("seq"),
                "ack": event.get("ack"),
                "len": event.get("len"),
                "flags": event.get("flags"),
                "extra_json": json.dumps(event.get("extra", {}), sort_keys=True),
            }
        )
    return rows


def render(events_path: str | Path, output_dir: str | Path | None = None) -> Path:
    """Render events into an interactive Plotly timeline."""

    events_file = Path(events_path)
    events = _load_events(events_file)
    rows = _to_plot_rows(events)

    target_dir = Path(output_dir) if output_dir else events_file.parent
    target_dir.mkdir(parents=True, exist_ok=True)
    output_path = target_dir / "timeline.html"

    if not rows:
        html = """
        <!DOCTYPE html>
        <html lang=\"en\">
        <head><meta charset=\"utf-8\"><title>tcpviz timeline</title></head>
        <body><h1>tcpviz timeline</h1><p>No events available.</p></body>
        </html>
        """
        output_path.write_text(html, encoding="utf-8")
        LOGGER.info("No events available for %s; wrote placeholder timeline to %s", events_path, output_path)
        return output_path

    fig = px.scatter(
        rows,
        x="timestamp",
        y="flow_id",
        color="event",
        symbol="event",
        hover_data={
            "timestamp": True,
            "flow_id": True,
            "event": True,
        "seq": True,
        "ack": True,
        "len": True,
        "flags": True,
        "extra_json": True,
        },
        category_orders={"event": sorted({row["event"] for row in rows})},
        labels={"timestamp": "Timestamp (s)", "flow_id": "Flow"},
        title="tcpviz timeline",
    )

    fig.update_layout(legend_title_text="Event", hovermode="closest")

    fig.write_html(output_path, include_plotlyjs="cdn", full_html=True)
    LOGGER.info("Wrote timeline with %s points to %s", len(rows), output_path)

    return output_path


__all__ = ["render"]
