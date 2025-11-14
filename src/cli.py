"""Command line interface for tcpviz."""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import click

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
PROJECT_PARENT = PACKAGE_ROOT.parent
if str(PROJECT_PARENT) not in sys.path:
    sys.path.insert(0, str(PROJECT_PARENT))

ARTIFACTS_ROOT = PACKAGE_ROOT / "artifacts"
SESSION_PREFIX = "session"

DEFAULT_WINDOW = 60
DEFAULT_THRESHOLD = 10
DEFAULT_POLL_INTERVAL = 2.0

ENV_WINDOW = "TCPVIZ_WINDOW"
ENV_THRESHOLD = "TCPVIZ_THRESHOLD"
ENV_POLL_INTERVAL = "TCPVIZ_POLL_INTERVAL"

from tcpviz.src.logging_utils import configure_logging, get_logger
from tcpviz.src.parser import parse_pcap
from tcpviz.src.realtime import SlidingWindowMonitor, tail_pcaps
from tcpviz.src.viz import render as render_timeline
from tcpviz.src.viz import render_summary as render_summary_chart

LOGGER = get_logger(__name__)

@click.group()
@click.option(
    "--verbose",
    is_flag=True,
    default=False,
    help="Enable debug logging output.",
)
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """TCP visualisation utilities."""

    configure_logging(verbose)
    ctx.obj = {"verbose": verbose}


def _create_session_dir(prefix: str = SESSION_PREFIX) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    ARTIFACTS_ROOT.mkdir(parents=True, exist_ok=True)
    session_dir = ARTIFACTS_ROOT / f"{prefix}_{timestamp}"
    session_dir.mkdir(parents=True, exist_ok=True)
    LOGGER.debug("Created session directory at %s", session_dir)
    return session_dir


def _resolve_output_dir(preferred: Path | None = None) -> Path:
    if preferred:
        try:
            preferred_resolved = preferred.resolve()
            artifacts_root = ARTIFACTS_ROOT.resolve()
            if artifacts_root == preferred_resolved or artifacts_root in preferred_resolved.parents:
                preferred.mkdir(parents=True, exist_ok=True)
                return preferred
        except OSError:
            LOGGER.debug("Unable to resolve preferred output directory %s", preferred)
    return _create_session_dir()


def _resolve_config(value, env_var: str, default, cast):
    if value is not None:
        return value
    raw = os.getenv(env_var)
    if raw is None:
        return default
    try:
        return cast(raw)
    except (ValueError, TypeError):
        LOGGER.warning("Invalid value for %s=%r; falling back to %s", env_var, raw, default)
        return default


@cli.command("parse-pcap")
@click.option("--in", "input_path", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True, help="PCAP/PCAPNG input path")
def parse_pcap_command(input_path: Path) -> None:
    """Parse a capture into canonical JSONL events."""

    session_dir = _create_session_dir()
    LOGGER.info("Parsing capture from %s", input_path)
    summary = parse_pcap(input_path, benchmark_dir=session_dir)
    events = summary.get("events", [])
    events_path = session_dir / "events.jsonl"

    with events_path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event) + "\n")

    event_counts = summary.get("event_counts", {})
    click.echo(
        f"Processed {summary.get('total_packets', 0)} packets "
        f"(TCP: {summary.get('tcp_packets', 0)}, skipped: {summary.get('skipped_packets', 0)})"
    )
    click.echo(f"Wrote {len(events)} events to {events_path}")
    click.echo(f"Session directory: {session_dir}")
    if summary.get("backend"):
        click.echo(f"Backend: {summary['backend']}")

    click.echo("Event counts:")
    for event_name in ("retransmission", "out_of_order", "loss_infer"):
        click.echo(f"  {event_name}: {event_counts.get(event_name, 0)}")

    top_flows = summary.get("top_flows", [])
    if top_flows:
        click.echo("Top flows by event volume:")
        for entry in top_flows:
            breakdown = ", ".join(
                f"{etype}:{count}" for etype, count in entry["event_breakdown"].items()
            )
            click.echo(f"  {entry['flow_id']} -> {entry['event_count']} [{breakdown}]")
    else:
        click.echo("No flows with retransmission/out_of_order events detected.")

    flow_metrics = summary.get("flow_metrics", [])
    if flow_metrics:
        click.echo("Sample flow congestion metrics:")
        for entry in flow_metrics[:3]:
            click.echo(
                f"  {entry['flow_id']}: avg_rtt_ms={entry.get('avg_rtt_ms')} "
                f"current_cwnd_bytes={entry.get('current_cwnd_bytes')} "
                f"max_cwnd_bytes={entry.get('max_cwnd_bytes')}"
            )


@cli.command("plot")
@click.option("--in", "events_path", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True, help="JSONL events path")
def plot_command(events_path: Path) -> None:
    """Render an interactive (stub) timeline."""

    output_dir = _resolve_output_dir(events_path.parent)
    output_path = render_timeline(events_path, output_dir=output_dir)
    click.echo(f"Timeline written to {output_path}")
    LOGGER.info("Rendered timeline from %s to %s", events_path, output_path)


@cli.command("summary")
@click.option("--in", "events_path", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True, help="JSONL events path")
def summary_command(events_path: Path) -> None:
    """Render a per-flow retransmission/out-of-order summary chart."""

    output_dir = _resolve_output_dir(events_path.parent)
    output_path = render_summary_chart(events_path, output_dir=output_dir)
    click.echo(f"Summary written to {output_path}")
    LOGGER.info("Rendered summary from %s to %s", events_path, output_path)


@cli.command("monitor")
@click.option("--pcap-path", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True, help="Rolling PCAP/PCAPNG file to watch")
@click.option(
    "--window",
    default=None,
    type=int,
    show_default=False,
    help=f"Sliding window size in seconds (default {DEFAULT_WINDOW}; env {ENV_WINDOW})",
)
@click.option(
    "--threshold",
    default=None,
    type=int,
    show_default=False,
    help=f"Retransmission threshold per flow (default {DEFAULT_THRESHOLD}; env {ENV_THRESHOLD})",
)
@click.option(
    "--poll-interval",
    default=None,
    type=float,
    show_default=False,
    help=f"Polling interval for tailing the capture (default {DEFAULT_POLL_INTERVAL}; env {ENV_POLL_INTERVAL})",
)
def monitor_command(pcap_path: Path, window: int | None, threshold: int | None, poll_interval: float | None) -> None:
    """Continuously monitor a rolling capture and alert on retransmissions."""

    window_seconds = _resolve_config(window, ENV_WINDOW, DEFAULT_WINDOW, int)
    threshold_value = _resolve_config(threshold, ENV_THRESHOLD, DEFAULT_THRESHOLD, int)
    poll_value = _resolve_config(poll_interval, ENV_POLL_INTERVAL, DEFAULT_POLL_INTERVAL, float)

    monitor = SlidingWindowMonitor(window_seconds=window_seconds, threshold=threshold_value)
    click.echo(
        "Press Ctrl+C to stop. Monitoring retransmissions with "
        f"window={window_seconds}s threshold={threshold_value} poll_interval={poll_value}s."
    )
    LOGGER.info(
        "Monitoring %s with window=%ss threshold=%s poll_interval=%ss",
        pcap_path,
        window_seconds,
        threshold_value,
        poll_value,
    )

    try:
        for event in tail_pcaps(pcap_path, poll_interval=poll_value):
            monitor.add(event)
            event_ts = event.get("ts")
            ts = float(event_ts) if event_ts is not None else time.time()
            monitor.maybe_alert(ts)
    except KeyboardInterrupt:
        click.echo("Stopped monitoring.")


if __name__ == "__main__":
    cli()
