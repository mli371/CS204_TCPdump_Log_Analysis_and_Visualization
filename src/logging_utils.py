"""Logging helpers for tcpviz."""

from __future__ import annotations

import logging

DEFAULT_LOG_LEVEL = logging.INFO


def configure_logging(verbose: bool = False) -> None:
    """Configure root logging for CLI entrypoints."""

    level = logging.DEBUG if verbose else DEFAULT_LOG_LEVEL
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a module-level logger."""

    return logging.getLogger(name if name else "tcpviz")


__all__ = ["configure_logging", "get_logger"]
