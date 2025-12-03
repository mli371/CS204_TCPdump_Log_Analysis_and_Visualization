#!/usr/bin/env bash
set -euo pipefail

# Wrapper to run the tcpviz netem CLI with sudo while preserving PATH/PYTHONPATH.
# Usage: scripts/netem_cli.sh -i eth0 --delay 200 --loss 10 ...

PYBIN="${PYBIN:-$(command -v python || true)}"
if [[ -z "$PYBIN" ]]; then
  echo "python not found; set PYBIN to your interpreter (e.g., \$CONDA_PREFIX/bin/python)" >&2
  exit 1
fi

sudo env "PATH=$PATH" "PYTHONPATH=${PYTHONPATH:-}" "$PYBIN" -m src.cli netem "$@"
