#!/usr/bin/env bash
set -euo pipefail

# Usage: scripts/generate_dashboard.sh [capture.pcapng]
# If a capture path is provided, we parse it first. Otherwise we reuse the latest session.

if [[ ${1:-} != "" ]]; then
  python -m src.cli parse-pcap --in "$1"
fi

LATEST_SESSION=$(ls -1dt artifacts/session_* 2>/dev/null | head -n 1 || true)
if [[ -z "$LATEST_SESSION" ]]; then
  echo "No session artifacts found. Run parse-pcap or provide a capture path." >&2
  exit 1
fi

EVENTS_FILE="$LATEST_SESSION/events.jsonl"

python -m src.cli plot --in "$EVENTS_FILE"
python -m src.cli summary --in "$EVENTS_FILE"

export SESSION_PATH="$LATEST_SESSION"

python - <<'PY'
import os
from pathlib import Path
from src.viz.report import generate_report

session = Path(os.environ["SESSION_PATH"])
report_path = generate_report(session / "events.jsonl")
print(f"Combined report written to {report_path}")
PY
