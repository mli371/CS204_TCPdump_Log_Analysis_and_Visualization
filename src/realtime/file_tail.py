"""Incremental tailing for rolling PCAP/PCAPNG captures."""

from __future__ import annotations

import time
from collections import deque
from pathlib import Path
from threading import Event as ThreadEvent
from typing import Deque, Dict, Iterator, Tuple

try:  # pragma: no cover - optional dependency
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:
    FileSystemEventHandler = None  # type: ignore
    Observer = None  # type: ignore

from src.logging_utils import get_logger

Event = Dict[str, object]
EventId = Tuple[object, ...]
MAX_SEEN_EVENTS = 100_000
LOGGER = get_logger(__name__)


def tail_pcaps(
    pcap_path: str | Path,
    poll_interval: float = 2.0,
) -> Iterator[Event]:
    """Yield newly observed events from a rolling PCAP/PCAPNG file.

    The implementation polls the file size on a fixed cadence (default 2s).
    Whenever new data is detected the capture is reparsed via ``parse_pcap`` and
    only previously unseen events are emitted. This provides a minimal-yet-usable
    approximation of incremental parsing without requiring deep packet buffering.
    """

    path = Path(pcap_path)
    if not path.exists():
        raise FileNotFoundError(f"PCAP not found: {path}")

    from src.parser import parse_pcap  # local import to avoid cycles

    seen: set[EventId] = set()
    seen_queue: Deque[EventId] = deque()
    last_size = -1
    first_iteration = True

    observer = None
    change_event: ThreadEvent | None = None
    if Observer and FileSystemEventHandler:
        try:
            observer, change_event = _start_watchdog(path)
            LOGGER.info("Using watchdog observer for %s", path)
        except Exception as exc:  # pragma: no cover
            LOGGER.warning("Failed to start watchdog observer (%s); falling back to polling", exc)
            observer = None
            change_event = None

    try:
        while True:
            try:
                current_size = path.stat().st_size
            except FileNotFoundError:
                raise FileNotFoundError(f"PCAP not found: {path}") from None

            if last_size != -1 and current_size < last_size:
                LOGGER.info("Detected capture rotation for %s; resetting state", path)
                seen.clear()
                seen_queue.clear()
                last_size = current_size

            if current_size != last_size and current_size > 0:
                try:
                    summary = parse_pcap(path)
                except Exception as exc:
                    LOGGER.warning("tail_pcaps parse error: %s", exc)
                else:
                    events = summary.get("events", [])

                    def _event_ts(evt: Event) -> float:
                        value = evt.get("ts")
                        try:
                            return float(value)
                        except (TypeError, ValueError):
                            return 0.0

                    events = sorted(events, key=_event_ts)
                    emitted = 0
                    for event in events:
                        identity = _event_identity(event)
                        if identity in seen:
                            continue
                        seen.add(identity)
                        seen_queue.append(identity)
                        if len(seen_queue) > MAX_SEEN_EVENTS:
                            old = seen_queue.popleft()
                            seen.discard(old)
                        yield event
                        emitted += 1
                    if emitted:
                        LOGGER.info("Emitted %s new events from %s", emitted, path)
                    last_size = current_size
            elif current_size == 0 and last_size != 0:
                last_size = 0

            if change_event and not first_iteration:
                LOGGER.debug("Awaiting filesystem events up to %ss", poll_interval)
                change_event.wait(timeout=poll_interval)
                change_event.clear()
            else:
                LOGGER.debug("Sleeping for %ss before next poll", poll_interval)
                time.sleep(poll_interval)

            first_iteration = False
    finally:
        if observer:
            observer.stop()
            observer.join()


def _event_identity(event: Event) -> EventId:
    return (
        event.get("ts"),
        event.get("event"),
        event.get("flow_id"),
        event.get("seq"),
        event.get("ack"),
        event.get("len"),
        event.get("flags"),
    )


def follow_pcap(
    pcap_path: str | Path,
    poll_interval: float = 2.0,
) -> Iterator[Event]:
    """Backward compatibility wrapper for ``tail_pcaps``."""

    yield from tail_pcaps(pcap_path, poll_interval=poll_interval)


def _start_watchdog(path: Path) -> Tuple[Observer, ThreadEvent]:
    if Observer is None or FileSystemEventHandler is None:
        raise RuntimeError("watchdog not available")

    change_event = ThreadEvent()

    class _Handler(FileSystemEventHandler):
        def _matches(self, event_path: str) -> bool:
            return Path(event_path).resolve() == path.resolve()

        def on_modified(self, event):  # type: ignore[override]
            if not event.is_directory and self._matches(event.src_path):
                change_event.set()

        def on_created(self, event):  # type: ignore[override]
            if not event.is_directory and self._matches(event.src_path):
                change_event.set()

        def on_moved(self, event):  # type: ignore[override]
            targets = [event.src_path, event.dest_path]
            if any(self._matches(p) for p in targets if p):
                change_event.set()

    observer = Observer()
    handler = _Handler()
    observer.schedule(handler, str(path.parent), recursive=False)
    observer.start()
    return observer, change_event


__all__ = ["tail_pcaps", "follow_pcap"]
