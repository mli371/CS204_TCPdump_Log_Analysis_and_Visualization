# tcpviz

`tcpviz` is a Python toolkit for analysing TCP captures (pcap/pcapng) with an emphasis on retransmission, inferred packet loss, and out-of-order behaviour. The CLI normalises packets into JSONL events, detects anomalies, renders Plotly dashboards, and tails rolling captures for near real-time alerting.

## Feature highlights
- **Dual-backend parsing** (pyshark → dpkt fallback) with per-run benchmarking, backend selection, and skipped-packet tracking.
- **Detectors & congestion proxies**: retransmission/out-of-order/loss inference plus cwnd/RTT estimators exposed in event metadata and summaries.
- **Loss inference heuristics**: triple-duplicate-ACK detection, ACK-stall timeouts with adaptive thresholds, and retransmission-without-dup-ACK detection, all with cwnd/RTT snapshots for context.
- **Control-plane anomalies**: repeated SYN without SYN-ACK, RST/FIN storms, and zero-window advertisements to catch handshake/teardown edge cases.
- **Realtime monitoring**: sliding-window WARN/CRITICAL alerts, watchdog-based tailer, configurable thresholds and poll intervals.
- **Visual workflow**: Plotly timeline, per-flow summary, combined dashboard (timeline + summary) generated via helper script.
- **CLI-first tooling**: `parse-pcap`, `plot`, `summary`, `monitor`, and automation scripts (`watch_latest_capture.py`, `generate_dashboard.sh`).

## Environment setup

### System prerequisites (Ubuntu/WSL)
```bash
sudo apt update && sudo apt install tshark tcpdump dumpcap
sudo usermod -aG wireshark $USER
newgrp wireshark
sudo setcap cap_net_raw,cap_net_admin+eip $(which dumpcap)
```
(On Windows use Npcap/Dumpcap; on macOS ensure FSEvents access is enabled.)

### Conda environment
```bash
conda env create -f environment.yml
conda activate CS204
```

## Routine commands
All commands below assume `pwd` is the repo root `tcpviz/`.

### Parsing & visualisation
```bash
python -m src.cli parse-pcap --in samples/test.pcapng
python -m src.cli plot --in artifacts/session_*/events.jsonl
python -m src.cli summary --in artifacts/session_*/events.jsonl
```
Each command writes into `artifacts/session_YYYYmmdd_HHMM/` and prints the exact paths.

### Combined dashboard (manual)
```bash
python - <<'PY'
from pathlib import Path
from src.viz.report import generate_report
latest = sorted(Path('artifacts').glob('session_*'))[-1]
print(generate_report(latest / 'events.jsonl'))
PY
```
Outputs `report.html` next to the timeline/summary.

### Realtime monitor
```bash
python -m src.cli monitor \
  --pcap-path /path/to/rolling.pcapng \
  --window 60 \
  --threshold 10 \
  --poll-interval 2.0
```
Environment variables `TCPVIZ_WINDOW`, `TCPVIZ_THRESHOLD`, `TCPVIZ_POLL_INTERVAL` override defaults. Sliding window alerts emit `[WARN]` (10–49), `[CRITICAL]` (≥50) severities (ANSI colours optional).

Monitor thresholds per event type:
- `TCPVIZ_THRESHOLD` (retransmissions), `TCPVIZ_LOSS_THRESHOLD` (loss inference), `TCPVIZ_OOO_THRESHOLD` (out-of-order). CLI options mirror these flags.
- Alert lines include structured payloads alongside human-readable text for downstream pipelines.

## Rolling capture workflow (recommended)
1. **Start a rolling capture** (Linux/WSL example):
   ```bash
   mkdir /tmp/CS204
   dumpcap -i eth0 -b filesize:800 -b files:80 -w /tmp/CS204/rolling.pcapng
   ```
<<<<<<< HEAD
  > Tip: replace `eth0` with the interface name returned by `dumpcap -D` on your host (e.g., `en0`, `wlan0`).
=======
   /tmp/CS204 need to be created before running.
>>>>>>> 4d7f1a1 (update docs)
2. **Maintain a stable symlink** to the newest file:
   ```bash
   mkdir -p ~/tcpviz-links
   python scripts/watch_latest_capture.py \
     "/tmp/CS204/rolling_*.pcapng" \
     ~/tcpviz-links/rolling-current.pcapng
   ```
  > **Non-VM macOS tip:** When `dumpcap` runs with `sudo`, the rotated files under `/tmp/CS204/` are owned by root, while `monitor` normally runs as your user. Stop the capture/watcher terminals (Ctrl+C), then fix ownership before restarting:
  > ```bash
  > sudo chown -R <your-user>:staff /private/tmp/CS204
  > sudo chmod a+r /private/tmp/CS204/rolling_*.pcapng
  > ```
  > Restart the watcher and `monitor` afterwards to avoid permission errors when tailing the capture.
3. **Run the monitor** against the symlink:
   ```bash
<<<<<<< HEAD
   python -m src.cli monitor --pcap-path ~/tcpviz-links/rolling-current.pcapng --window 120 --threshold 5
   ```
4. **Generate dashboards** from the same capture:
   ```bash
   TCPVIZ_WAIT_ATTEMPTS=60 TCPVIZ_STABLE_ATTEMPTS=60 TCPVIZ_WAIT_DELAY=1 scripts/generate_dashboard.sh ~/tcpviz-links/rolling-current.pcapng

=======
   python -m src.cli monitor \
     --pcap-path ../tcpviz-links/rolling-current.pcapng \
     --window 60 --threshold 10
   ```
4. **Generate dashboards** from the same capture:
   ```bash
   scripts/generate_dashboard.sh ../tcpviz-links/rolling-current.pcapng
>>>>>>> 4d7f1a1 (update docs)
   ```
   Open `artifacts/session_<timestamp>/timeline.html`, `summary.html`, and `report.html` in a browser.

## Netem CLI (ingress/egress impairment)
Apply or clear tc/netem profiles via the built-in CLI (requires root). Replace `eth0` with your interface. If `sudo python` is not found, use the wrapper `scripts/netem_cli.sh` (inherits your PATH/PYTHONPATH).
```bash
# 300ms delay + 10% loss on egress
scripts/netem_cli.sh -i eth0 --delay 300 --loss 10

# Ingress shaping via IFB: delay+jitter+loss+reorder to affect downloads
scripts/netem_cli.sh -i eth0 --ingress --delay 200 --jitter 80 --loss 10 --reorder 20

# Rate limit 1mbit with netem (HTB parent + netem child)
scripts/netem_cli.sh -i eth0 --rate 1mbit --delay 100 --loss 5

# Restore to normal
scripts/netem_cli.sh -i eth0 --restore
```
> WSL2 note: if `RTNETLINK answers: Operation not supported` appears, run these on a full Linux VM/host.

### Loss inference heuristics
- **Triple duplicate ACKs**: emits `loss_infer` with `extra.reason=triple_duplicate_ack` once per ACK value.
- **ACK stall timeout**: flags loss when ACK progress freezes while data is outstanding. The timeout uses the max of a floor (default 400ms) and an RTT-aware multiplier (default 4× smoothed RTT). See `ACK_STALL_THRESHOLD_MS` and `ACK_STALL_RTT_MULTIPLIER` in `src/parser/pcap_reader.py`.
- **Retransmission without dup ACKs**: if a retransmission appears before dup-ACK thresholds are hit, a `loss_infer` is emitted with `extra.reason=retransmission_without_dup_acks`.
- Timeline hover shows `extra_json` (reason, stall_ms/threshold_ms, cwnd/RTT snapshots). Summary charts aggregate by event type (not reason).
- **Tuning**: adjust the two constants above or add CLI/env wiring if you need more aggressive timeouts on low-latency links; re-run `parse-pcap` after changes.

### Handshake/teardown/zero-window anomalies
- Repeated SYNs without SYN-ACK emit `handshake_anomaly` with retry count.
- Multiple RST/FIN packets emit `teardown_anomaly` (storm detection).
- Zero-window advertisements emit `zero_window` events.
- These appear in timeline hovers via `extra_json` and in summary charts under their own event category.

### Windows capture handoff
```powershell
tshark -D
dumpcap -i <ID> -b filesize:200 -b files:30 -w C:\pcaps\rolling.pcapng
```
Share `C:\pcaps` into WSL (e.g. `/mnt/c/pcaps`) so the monitor tailer can read it.

> ⚠️ tcpviz cannot recover the true congestion window (cwnd); congestion proxies are heuristic. Document limitations in reports.

## Logging & benchmarking
- Logging defaults to INFO (`--verbose` enables DEBUG). Watchdog/polling events log when files rotate or emit new events.
- `parse-pcap` writes `benchmark.log` in each session directory summarising backend, duration, throughput, event counts.

## Packaging (single-file executable)
```bash
conda activate CS204
pip install pyinstaller
pyinstaller --onefile -n tcpviz src/cli.py
```

## Development notes
- Tests live in `tests/`; run `conda activate CS204 && pytest -q` or `make test`.
- `make mvp` executes a stub E2E run with `conda run`.
- Helper scripts:
  - `scripts/watch_latest_capture.py` – keep `rolling-current.pcapng` linked to the newest capture segment.
  - `scripts/generate_dashboard.sh` – parse (optional) + plot + summary + combined report.

## Proposal alignment
Relative to `Proposal.md` (“Real-Time TCPdump Log Analysis and Visualization”):

**Delivered**
- Dual-backend parsing with benchmarking, skipped-packet stats, and artefact scoping.
- Retransmission/out-of-order/packet-loss detection + per-flow sliding-window alerts (WARN/CRITICAL) backed by watchdog tailer.
- Congestion proxies (cwnd bytes, RTT EMA) attached to events and CLI summaries.
- Plotly timeline, flow summary, combined dashboard, plus automation scripts for reproducible reports.
- CLI workflow (`parse-pcap`, `plot`, `summary`, `monitor`) with logging, env-configurable thresholds, consistent session directories.

**Pending / future work**
- Tune and validate loss-anomaly heuristics on more captures (adjust ACK-stall/RTO thresholds, reduce false positives).
- Add time-based handshake/teardown checks (e.g., missing SYN+ACK timers) and broaden validation pcaps.
- Document verified runs on macOS/Windows beyond WSL (currently validated manually but not formally recorded).
