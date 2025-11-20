# Pending Implementation Plans

## Packet-Loss Inference
✅ Implemented: per-flow ACK tracking, triple-duplicate-ACK heuristic, JSONL/viz integration, and tests (see `src/parser/pcap_reader.py`, `tests/test_loss_inference.py`).

## Congestion Modelling Enhancements
✅ Implemented per-flow cwnd proxies, RTT EMA tracking, summary output, and CLI visibility (see `src/parser/pcap_reader.py` and README).

## Watchdog-Based Monitoring & Cross-Platform Validation
✅ Implemented watchdog-backed monitor with README cross-platform notes (see `src/realtime/file_tail.py`, README).

## Extended Congestion/Anomaly Heuristics
1. **RTO-style loss detection**: tune adaptive stall thresholds (RTT-aware), add configurability, and evaluate false-positive rates on mixed workloads.
2. **Handshake / teardown checks**: detect missing SYN+ACK, repeated SYNs, zero-window probes, or FIN/RST storms to expand alert coverage.
3. **Severity policy**: make WARN/CRITICAL thresholds configurable per-event-type (loss, retrans, out-of-order) and emit structured JSON for alerting pipelines.
