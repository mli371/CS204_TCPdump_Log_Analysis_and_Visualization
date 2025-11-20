# Pending Implementation Plans

## Packet-Loss Inference
✅ Implemented: per-flow ACK tracking, triple-duplicate-ACK heuristic, JSONL/viz integration, and tests (see `src/parser/pcap_reader.py`, `tests/test_loss_inference.py`).

## Congestion Modelling Enhancements
✅ Implemented per-flow cwnd proxies, RTT EMA tracking, summary output, and CLI visibility (see `src/parser/pcap_reader.py` and README).

## Watchdog-Based Monitoring & Cross-Platform Validation
✅ Implemented watchdog-backed monitor with README cross-platform notes (see `src/realtime/file_tail.py`, README).

## Extended Congestion/Anomaly Heuristics
1. **RTO-style loss detection**: tune thresholds (ACK-stall floor/RTT multiplier) and validate on varied pcaps to reduce false positives.
2. **Handshake / teardown checks**: add time-based missing SYN+ACK heuristics and validate the existing retry/storm/zero-window detectors on diverse captures.
3. **Severity policy**: add alert stream tests and refine per-event defaults based on operator feedback.
