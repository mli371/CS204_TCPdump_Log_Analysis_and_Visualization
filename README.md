# tcpviz

`tcpviz` is a Python toolkit for analysing TCP captures (pcap/pcapng) with an emphasis on retransmission, inferred packet loss, and out-of-order behaviour. The CLI normalises packets into JSONL events, detects anomalies, renders Plotly dashboards, and tails rolling captures for near real-time alerting.

## Feature highlights
- **Dual-backend parsing** (pyshark → dpkt fallback) with per-run benchmarking, backend selection, and skipped-packet tracking.
- **Detectors & congestion proxies**: retransmission/out-of-order/loss inference plus cwnd/RTT estimators exposed in event metadata and summaries.
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
(Windows 使用 Npcap/Dumpcap；macOS 需启用 FSEvents 监听权限。)

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

## Rolling capture workflow (recommended)
1. **Start a rolling capture** (Linux/WSL example):
   ```bash
   dumpcap -i eth0 -b filesize:50 -b files:10 -w /tmp/CS204/rolling.pcapng
   ```
2. **Maintain a stable symlink** to the newest file:
   ```bash
   mkdir -p ~/tcpviz-links
   python scripts/watch_latest_capture.py \
     "/tmp/CS204/rolling_*.pcapng" \
     ~/tcpviz-links/rolling-current.pcapng
   ```
3. **Run the monitor** against the symlink:
   ```bash
   python -m src.cli monitor \
     --pcap-path ~/tcpviz-links/rolling-current.pcapng \
     --window 60 --threshold 10
   ```
4. **Generate dashboards** from the same capture:
   ```bash
   scripts/generate_dashboard.sh ~/tcpviz-links/rolling-current.pcapng
   ```
   Open `artifacts/session_<timestamp>/timeline.html`, `summary.html`, and `report.html` in a browser.

### Windows capture handoff
```powershell
tshark -D
dumpcap -i <ID> -b filesize:50 -b files:10 -w C:\pcaps\rolling.pcapng
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
- Replace heuristic loss inference with additional signals (RTO-style detection, zero-window probes, SYN/FIN anomaly tracking) per NEXT_ACTIONS.md.
- Document verified runs on macOS/Windows beyond WSL (currently validated manually but not formally recorded).
