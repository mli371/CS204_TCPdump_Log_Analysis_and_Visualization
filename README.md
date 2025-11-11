# tcpviz

`tcpviz` is an experimental toolkit for analysing TCP captures (pcap/pcapng) with a focus on retransmission and out-of-order behaviour. It ships a CLI that can parse captures into canonical JSONL events, detect anomalies, render visualisations, and perform near real-time monitoring on rolling capture files.

## Key features
- **Canonical event extraction** via pyshark (preferred) or dpkt, with automatic backend fallback and per-run benchmarking.
- **Detectors and monitoring** that track retransmissions and sequence reordering per flow, emitting severity-graded alerts in sliding windows.
- **Visual dashboards**: interactive timeline, per-flow summary chart, and a combined HTML report.
- **CLI-first workflow** with logging (INFO by default, DEBUG with `--verbose`) and configurable thresholds/polling through CLI options or env vars.

## Environment & prerequisites

### System setup (WSL Ubuntu)
```
sudo apt update && sudo apt install tshark tcpdump
sudo usermod -aG wireshark $USER
newgrp wireshark
tshark -v
```

### Conda environment
```
conda env create -f environment.yml
conda activate CS204
```

## Command overview

All commands are meant to be executed from the repository root.

### Parsing and visualisations
```
# Parse capture into JSONL events and benchmark the backend
python -m src.cli parse-pcap --in samples/test.pcapng

# Render timeline (Plotly scatter) into the session artifacts directory
python -m src.cli plot --in artifacts/session_*/events.jsonl

# Render per-flow retransmission/out-of-order summary chart
python -m src.cli summary --in artifacts/session_*/events.jsonl
```
Each command writes outputs under `artifacts/session_YYYYmmdd_HHMM/`, printing paths to stdout.

### Combined dashboard
```
python - <<'PY'
from pathlib import Path
from tcpviz.src.viz.report import generate_report
latest = sorted(Path('artifacts').glob('session_*'))[-1]
print(generate_report(latest / 'events.jsonl'))
PY
```
This produces `report.html`, combining the timeline and summary charts.

### Near real-time monitoring
```
python -m src.cli monitor \
  --pcap-path /mnt/c/pcaps/rolling.pcapng \
  --window 60 \
  --threshold 10 \
  --poll-interval 2.0
```
Environment variables `TCPVIZ_WINDOW`, `TCPVIZ_THRESHOLD`, and `TCPVIZ_POLL_INTERVAL` can override the defaults. Sliding window alerts emit `[WARN]` (10–49), `[CRITICAL]` (≥50), or `[ALERT]` (custom threshold) levels with optional ANSI colour.

### Rolling capture on Windows (PowerShell)
```
tshark -D
dumpcap -i <ID> -b filesize:50 -b files:10 -w C:\pcaps\rolling.pcapng
```
Share `C:\pcaps` into WSL (e.g. `/mnt/c/pcaps`) so the monitor can tail the rolling file.

> ⚠️ tcpviz cannot recover the true congestion window (cwnd) from captures; analyses rely on retransmission/out-of-order heuristics. Ensure reports document these limitations.

### Cross-platform notes
- `monitor` uses filesystem events via `watchdog` when available (automatic fallback to polling otherwise).
- Validated on WSL Ubuntu + Windows (Npcap/Dumpcap share) and macOS (FSEvents). Ensure capture directories are accessible (e.g. `/mnt/c/pcaps` on WSL).

## Reproduce the full workflow

1. **Create/activate the Conda environment**
   ```
   conda env create -f environment.yml
   conda activate CS204
   ```

2. **Prepare capture permissions on Linux/WSL**
   ```
   sudo apt install dumpcap tshark
   sudo usermod -aG wireshark $USER
   sudo setcap cap_net_raw,cap_net_admin+eip $(which dumpcap)
   ```

3. **Start a rolling capture**
   ```
   dumpcap -i eth0 -b filesize:50 -b files:10 -w /tmp/CS204/rolling.pcapng
   ```

4. **Maintain a stable symlink to the newest file**
   ```
   mkdir -p ~/tcpviz-links
   python scripts/watch_latest_capture.py "/tmp/CS204/rolling_*.pcapng" ~/tcpviz-links/rolling-current.pcapng
   ```

5. **Run realtime monitoring**
   ```
   python -m src.cli monitor \
     --pcap-path ~/tcpviz-links/rolling-current.pcapng \
     --window 60 \
     --threshold 10
   ```

6. **Generate dashboards**
   ```
   scripts/generate_dashboard.sh ~/tcpviz-links/rolling-current.pcapng
   ```
   Review `artifacts/session_<timestamp>/timeline.html`, `summary.html`, and `report.html`.

## Logging & benchmarking
- Logging defaults to INFO; add `--verbose` to any CLI command to enable DEBUG output.
- Each parse run records backend, packet counts, duration, and throughput in `benchmark.log` within the session directory.

## Packaging (single-file executable)
```
conda activate CS204
pip install pyinstaller
pyinstaller --onefile -n tcpviz src/cli.py
```

## Development notes
- Unit tests live under `tests/` and can be run via `make test` (inside the `CS204` conda environment).
- `make mvp` executes a stubbed end-to-end run using `conda run`.
- The project favours ASCII output and minimal external dependencies; Plotly is used for visualisations, falling back to simple placeholders when events are absent.

## Proposal alignment
Relative to `Proposal.md` (“Real-Time TCPdump Log Analysis and Visualization”):

**Delivered**
- Dual-backend parsing (pyshark → dpkt) with canonical TCP fields, benchmarking, and session-scoped artifacts.
- Retransmission/out-of-order/packet-loss detection plus per-flow sliding-window monitoring that emits WARN/CRITICAL alerts, driven by the realtime tailer.
- Congestion proxies (per-flow cwnd bytes, RTT EMA) surfaced in summaries and event metadata.
- Plotly-based timeline, flow summary, and combined report dashboard.
- CLI workflow (`parse-pcap`, `plot`, `summary`, `monitor`) with logging, env-configurable thresholds, and consistent session directories.

**Pending / future work**
- Replace polling-based monitor with filesystem event listeners (watchdog) and document verified runs on macOS/Windows per proposal goals.
