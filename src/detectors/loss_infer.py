"""Loss inference detector stub."""

from __future__ import annotations

from typing import Iterable, List, MutableMapping

EventLike = MutableMapping[str, object]


def infer_loss(packets: Iterable[EventLike]) -> List[EventLike]:
    """Return events that are already classified as loss inference."""

    return [pkt for pkt in packets if pkt.get("event") == "loss_infer"]


__all__ = ["infer_loss"]
