"""Helpers to apply and clear tc/netem impairments via the CLI."""

from __future__ import annotations

import subprocess
from typing import Iterable, List, Sequence

from src.logging_utils import get_logger

LOGGER = get_logger(__name__)


class NetemError(RuntimeError):
    """Raised when tc/netem commands fail."""


def _run(cmd: Sequence[str], ignore_error: bool = False) -> None:
    try:
        subprocess.run(cmd, check=True, text=True, capture_output=True)
    except subprocess.CalledProcessError as exc:
        if ignore_error:
            return
        LOGGER.error("Command failed: %s | stdout=%s stderr=%s", " ".join(cmd), exc.stdout, exc.stderr)
        raise NetemError(f"Command failed: {' '.join(cmd)}") from exc


def _ensure_ifb(ifb: str) -> None:
    # Best-effort load module and bring IFB up.
    _run(["modprobe", "ifb"], ignore_error=True)
    result = subprocess.run(["ip", "link", "show", ifb], capture_output=True, text=True)
    if result.returncode != 0:
        _run(["ip", "link", "add", ifb, "type", "ifb"])
    _run(["ip", "link", "set", ifb, "up"])


def _apply_netem_qdisc(
    dev: str,
    netem_args: Iterable[str],
    rate: str | None,
    burst: str,
    latency: str,
) -> None:
    args_list = list(netem_args)
    if rate:
        # Use HTB root for rate limiting, attach netem to the class.
        _run(["tc", "qdisc", "replace", "dev", dev, "root", "handle", "1:", "htb", "default", "1"])
        _run(["tc", "class", "replace", "dev", dev, "parent", "1:", "classid", "1:1", "htb", "rate", rate])
        if args_list:
            _run(["tc", "qdisc", "replace", "dev", dev, "parent", "1:1", "handle", "10:", "netem", *args_list])
        else:
            _run(["tc", "qdisc", "replace", "dev", dev, "parent", "1:1", "handle", "10:", "fq_codel"])
    else:
        if not args_list:
            raise NetemError("No netem parameters provided; nothing to apply.")
        _run(["tc", "qdisc", "replace", "dev", dev, "root", "netem", *args_list])


def apply_netem(
    interface: str,
    delay_ms: float | None = None,
    jitter_ms: float | None = None,
    loss_pct: float | None = None,
    reorder_pct: float | None = None,
    rate: str | None = None,
    burst: str = "32kbit",
    latency: str = "400ms",
    ingress: bool = False,
    ifb: str = "ifb0",
) -> None:
    """Apply a netem profile (and optional rate limit) to an interface.

    If ingress=True, traffic is redirected to an IFB device and shaped there.
    """

    netem_args: List[str] = []
    if delay_ms is not None:
        if jitter_ms is not None:
            netem_args += ["delay", f"{delay_ms}ms", f"{jitter_ms}ms"]
        else:
            netem_args += ["delay", f"{delay_ms}ms"]
    if loss_pct is not None:
        netem_args += ["loss", f"{loss_pct}%"]
    if reorder_pct is not None:
        netem_args += ["reorder", f"{reorder_pct}%"]

    target_dev = interface
    if ingress:
        target_dev = ifb
        _ensure_ifb(ifb)
        # Mirror ingress traffic into IFB.
        _run(["tc", "qdisc", "replace", "dev", interface, "ingress"])
        _run(
            [
                "tc",
                "filter",
                "replace",
                "dev",
                interface,
                "parent",
                "ffff:",
                "protocol",
                "ip",
                "u32",
                "match",
                "u32",
                "0",
                "0",
                "action",
                "mirred",
                "egress",
                "redirect",
                "dev",
                ifb,
            ]
        )

    _apply_netem_qdisc(target_dev, netem_args, rate=rate, burst=burst, latency=latency)
    LOGGER.info(
        "Applied netem on %s (ingress=%s) delay=%sms jitter=%sms loss=%s%% reorder=%s%% rate=%s",
        target_dev,
        ingress,
        delay_ms,
        jitter_ms,
        loss_pct,
        reorder_pct,
        rate,
    )


def restore_netem(interface: str, ifb: str = "ifb0") -> None:
    """Remove netem/tc shaping from the interface (and IFB if present)."""

    _run(["tc", "qdisc", "del", "dev", interface, "root"], ignore_error=True)
    _run(["tc", "qdisc", "del", "dev", interface, "ingress"], ignore_error=True)
    _run(["tc", "filter", "del", "dev", interface, "parent", "ffff:"], ignore_error=True)
    _run(["tc", "qdisc", "del", "dev", ifb, "root"], ignore_error=True)
    _run(["ip", "link", "set", ifb, "down"], ignore_error=True)
    LOGGER.info("Restored interface %s (and %s if present) to normal", interface, ifb)


__all__ = ["apply_netem", "restore_netem", "NetemError"]
