# Repository Handbook (for collaborators and agents)

## Project Layout
- `src/` – production code (CLI in `src/cli.py`, subpackages for `parser`, `detectors`, `realtime`, `viz`, etc.).
- `scripts/` – helper utilities (`watch_latest_capture.py`, `generate_dashboard.sh`).
- `tests/` – pytest suites mirroring the `src/` tree.
- `artifacts/` – generated sessions (timeline/summary/report); never commit.
- `samples/` – placeholder inputs (safe pcaps or `.gitkeep`).
- `environment.yml` – Conda definition; `Makefile` exposes common workflows.

## Getting Started
```bash
conda env create -f environment.yml   # or make init
conda activate CS204
```
On WSL/macOS install capture tooling (`dumpcap`, `tshark`) and apply the necessary capabilities (`setcap cap_net_raw,cap_net_admin+eip $(which dumpcap)`). Windows users should install Npcap/Dumpcap.

## Common Workflows
- **Parse & visualise**:
  ```bash
  python -m src.cli parse-pcap --in samples/test.pcapng
  python -m src.cli plot --in artifacts/session_*/events.jsonl
  python -m src.cli summary --in artifacts/session_*/events.jsonl
  scripts/generate_dashboard.sh /path/to/capture.pcapng
  ```
- **Realtime monitor**:
  ```bash
  python -m src.cli monitor --pcap-path ~/tcpviz-links/rolling-current.pcapng --window 60 --threshold 10
  ```
- **Helper scripts**:
  - `scripts/watch_latest_capture.py "glob" ~/tcpviz-links/rolling-current.pcapng` keeps a symlink pointed at the newest rolling capture.
  - `scripts/generate_dashboard.sh <pcap>` parses (optional), plots, summarises, and generates a combined HTML report.
- **Makefile targets**:
  `make parse PCAP=...`, `make monitor PCAP=...`, `make dashboard PCAP=...`, `make test` (pytest), `make init`.

## Coding Standards
- Python 3.11, four-space indentation, type hints, concise docstrings.
- Module/function names in `snake_case`, classes in `UpperCamelCase`.
- Keep logging consistent with `logging_utils` (INFO default, DEBUG via `--verbose`).
- Avoid committing artifacts, caches, or pcaps; `.gitignore` already excludes these.

## Testing
- Create unit tests alongside features under `tests/` (pytest).
- Mock or provide safe sample pcaps; do not expose sensitive traffic.
- Run `conda activate CS204 && pytest -q` (or `make test`) before committing.

## Commit & PR Expectations
- Commit subjects: imperative mood, ≤72 chars (e.g., “Add RTT proxy to summary output”).
- Include code + tests + docs updates in the same commit when practical.
- PRs should describe the change, link issues, and mention commands run.

## Security & Configuration Notes
- When adding new env vars, prefix with `TCPVIZ_` and document usage in README.
- Use the helper scripts to avoid storing raw captures in the repo; scrub or synthesize samples before sharing.
- If you require additional OS capabilities, document them in README/NEXT_ACTIONS so others can reproduce the setup.
