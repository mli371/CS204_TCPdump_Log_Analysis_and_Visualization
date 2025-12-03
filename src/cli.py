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
ENV_LOSS_THRESHOLD = "TCPVIZ_LOSS_THRESHOLD"
ENV_OOO_THRESHOLD = "TCPVIZ_OOO_THRESHOLD"

from tcpviz.src.logging_utils import configure_logging, get_logger
from tcpviz.src.parser import parse_pcap
from tcpviz.src.realtime import SlidingWindowMonitor, tail_pcaps
from tcpviz.src.viz import render as render_timeline
from tcpviz.src.viz import render_summary as render_summary_chart
from tcpviz.src.netem import apply_netem, restore_netem, NetemError

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
    for event_name in (
        "retransmission",
        "out_of_order",
        "loss_infer",
        "handshake_anomaly",
        "teardown_anomaly",
        "zero_window",
    ):
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
    "--loss-threshold",
    default=None,
    type=int,
    show_default=False,
    help=f"Loss inference threshold per flow (default {DEFAULT_THRESHOLD}; env {ENV_LOSS_THRESHOLD})",
)
@click.option(
    "--ooo-threshold",
    default=None,
    type=int,
    show_default=False,
    help=f"Out-of-order threshold per flow (default {DEFAULT_THRESHOLD}; env {ENV_OOO_THRESHOLD})",
)
@click.option(
    "--poll-interval",
    default=None,
    type=float,
    show_default=False,
    help=f"Polling interval for tailing the capture (default {DEFAULT_POLL_INTERVAL}; env {ENV_POLL_INTERVAL})",
)
def monitor_command(
    pcap_path: Path,
    window: int | None,
    threshold: int | None,
    loss_threshold: int | None,
    ooo_threshold: int | None,
    poll_interval: float | None,
) -> None:
    """Continuously monitor a rolling capture and alert on retransmissions."""

    window_seconds = _resolve_config(window, ENV_WINDOW, DEFAULT_WINDOW, int)
    threshold_value = _resolve_config(threshold, ENV_THRESHOLD, DEFAULT_THRESHOLD, int)
    loss_threshold_value = _resolve_config(loss_threshold, ENV_LOSS_THRESHOLD, threshold_value, int)
    ooo_threshold_value = _resolve_config(ooo_threshold, ENV_OOO_THRESHOLD, threshold_value, int)
    poll_value = _resolve_config(poll_interval, ENV_POLL_INTERVAL, DEFAULT_POLL_INTERVAL, float)

    thresholds = {
        "retransmission": threshold_value,
        "loss_infer": loss_threshold_value,
        "out_of_order": ooo_threshold_value,
        "handshake_anomaly": threshold_value,
        "teardown_anomaly": threshold_value,
        "zero_window": threshold_value,
    }

    monitor = SlidingWindowMonitor(
        window_seconds=window_seconds,
        threshold=threshold_value,
        thresholds=thresholds,
    )
    click.echo(
        "Press Ctrl+C to stop. Monitoring retransmissions with "
        f"window={window_seconds}s thresholds={thresholds} poll_interval={poll_value}s."
    )
    LOGGER.info(
        "Monitoring %s with window=%ss thresholds=%s poll_interval=%ss",
        pcap_path,
        window_seconds,
        thresholds,
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


@cli.command("netem")
@click.option("--interface", "-i", required=True, help="Network interface to shape (e.g., eth0)")
@click.option("--delay", type=float, help="Base delay in ms (applied via netem)")
@click.option("--jitter", type=float, help="Jitter in ms (optional, pairs with delay)")
@click.option("--loss", type=float, help="Packet loss percentage (e.g., 5 for 5%)")
@click.option("--reorder", type=float, help="Packet reordering percentage (e.g., 20 for 20%)")
@click.option("--rate", type=str, help="Rate limit (e.g., '1mbit'); uses HTB to combine with netem")
@click.option("--burst", type=str, default="32kbit", show_default=True, help="Burst size for rate limiting (with --rate)")
@click.option("--latency", type=str, default="400ms", show_default=True, help="Latency for token bucket (with --rate)")
@click.option("--ingress", is_flag=True, default=False, help="Apply to ingress via IFB redirection")
@click.option("--ifb", type=str, default="ifb0", show_default=True, help="IFB device name when using --ingress")
@click.option("--restore", "restore_only", is_flag=True, default=False, help="Restore interface to normal (remove netem/htb)")
def netem_command(
    interface: str,
    delay: float | None,
    jitter: float | None,
    loss: float | None,
    reorder: float | None,
    rate: str | None,
    burst: str,
    latency: str,
    ingress: bool,
    ifb: str,
    restore_only: bool,
) -> None:
    """Apply or clear tc/netem impairments for testing."""

    if restore_only:
        restore_netem(interface, ifb=ifb)
        click.echo(f"Restored {interface} (and {ifb} if present).")
        return

    if not any(param is not None for param in (delay, jitter, loss, reorder, rate)):
        raise click.UsageError("Specify at least one impairment option (delay/jitter/loss/reorder/rate) or use --restore.")

    try:
        apply_netem(
            interface=interface,
            delay_ms=delay,
            jitter_ms=jitter,
            loss_pct=loss,
            reorder_pct=reorder,
            rate=rate,
            burst=burst,
            latency=latency,
            ingress=ingress,
            ifb=ifb,
        )
    except NetemError as exc:
        raise click.ClickException(str(exc))

    mode = "ingress" if ingress else "egress"
    click.echo(
        f"Applied netem on {interface} ({mode}) "
        f"delay={delay}ms jitter={jitter}ms loss={loss}% reorder={reorder}% rate={rate}"
    )


if __name__ == "__main__":
    cli()
