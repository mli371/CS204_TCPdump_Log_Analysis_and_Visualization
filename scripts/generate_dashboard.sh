#!/usr/bin/env bash
set -euo pipefail

# Usage: scripts/generate_dashboard.sh [capture.pcapng]
# If a capture path is provided, we parse it first. Otherwise we reuse the latest session.

wait_for_file() {
  local path="$1"
  local attempts="${2:-5}"
  local delay="${3:-2}"
  for ((i=1; i<=attempts; i++)); do
    # -e follows symlinks; -h would detect broken symlinks
    if [[ -e "$path" ]]; then
      return 0
    fi
    echo "Waiting for capture to exist: $path (attempt $i/$attempts)..." >&2
    sleep "$delay"
  done
  return 1
}

wait_for_stable_file() {
  local path="$1"
  local attempts="${2:-5}"
  local delay="${3:-2}"
  local prev_size=""
  for ((i=1; i<=attempts; i++)); do
    if [[ ! -e "$path" ]]; then
      echo "Capture not accessible yet: $path (attempt $i/$attempts)..." >&2
      sleep "$delay"
      continue
    fi
    local size
    size=$(stat -c "%s" "$path" 2>/dev/null || true)
    if [[ -z "$size" ]]; then
      echo "Capture stat failed (attempt $i/$attempts), retrying..." >&2
      sleep "$delay"
      continue
    fi
    if [[ "$size" == "$prev_size" && "$size" != "0" ]]; then
      return 0
    fi
    prev_size="$size"
    sleep "$delay"
  done
  return 1
}

if [[ ${1:-} != "" ]]; then
  WAIT_ATTEMPTS=${TCPVIZ_WAIT_ATTEMPTS:-10}
  WAIT_DELAY=${TCPVIZ_WAIT_DELAY:-1}
  STABLE_ATTEMPTS=${TCPVIZ_STABLE_ATTEMPTS:-10}
  STABLE_DELAY=${TCPVIZ_STABLE_DELAY:-1}

  if ! wait_for_file "$1" "$WAIT_ATTEMPTS" "$WAIT_DELAY"; then
    echo "Capture not found: $1" >&2
    exit 1
  fi
  # Guard against rotating captures: ensure the file exists and size is stable before parsing.
  if ! wait_for_stable_file "$1" "$STABLE_ATTEMPTS" "$STABLE_DELAY"; then
    echo "Capture is not stable/readable: $1" >&2
    exit 1
  fi
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
