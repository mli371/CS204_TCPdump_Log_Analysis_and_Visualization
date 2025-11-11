#!/usr/bin/env python3
"""Symlink the newest capture file to a fixed path for realtime monitoring."""

from __future__ import annotations

import argparse
import glob
import time
from pathlib import Path


def _newest_file(pattern: str) -> Path | None:
    paths = [Path(p).expanduser().resolve() for p in glob.glob(pattern)]
    if not paths:
        return None
    return max(paths, key=lambda p: p.stat().st_mtime)


def main() -> None:
    parser = argparse.ArgumentParser(description="Symlink newest capture file to a fixed path")
    parser.add_argument("source_glob", help="Glob pattern for rolling capture files, e.g. /tmp/rolling_*.pcapng")
    parser.add_argument("target", help="Path of the symlink to update, e.g. /tmp/rolling-current.pcapng")
    parser.add_argument("--interval", type=float, default=1.0, help="Polling interval in seconds")
    args = parser.parse_args()

    target_path = Path(args.target).expanduser()
    target_path.parent.mkdir(parents=True, exist_ok=True)
    pattern = args.source_glob

    while True:
        latest = _newest_file(pattern)
        if latest is not None and latest.exists():
            try:
                if target_path.is_symlink() or target_path.exists():
                    target_path.unlink()
                target_path.symlink_to(latest)
                print(f"Updated symlink: {target_path} -> {latest}")
            except OSError as exc:
                print(f"Failed to update symlink: {exc}")
        else:
            print(f"No files matched pattern {pattern}")
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
