#!/usr/bin/env bash
# DKCISSP Email Analyzer — one-click launcher (Linux / macOS)
#
# Double-click this file (or run `./run.sh` / `bash run.sh`) and it will:
#   1. Create a private virtual environment on first run (./.venv)
#   2. Install everything needed (first run only — fast after that)
#   3. Start the local web UI
#   4. Open it in your browser automatically
#
# Nothing you paste into the tool ever leaves your machine.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

PY=python3
command -v "$PY" >/dev/null 2>&1 || PY=python
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "Python 3.9+ is required but was not found."
  echo "Install it from https://www.python.org/downloads/ and run this again."
  read -rp "Press Enter to exit..." _
  exit 1
fi

if [ ! -d ".venv" ]; then
  echo "First-time setup — this takes a minute..."
  "$PY" -m venv .venv
  ./.venv/bin/pip install -q --upgrade pip
  ./.venv/bin/pip install -q -e ".[web]"
fi

export PORT="${PORT:-5000}"
URL="http://127.0.0.1:${PORT}"

(
  sleep 1.5
  if command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL" >/dev/null 2>&1
  elif command -v open >/dev/null 2>&1; then open "$URL" >/dev/null 2>&1
  fi
) &

echo ""
echo "DKCISSP Email Analyzer is starting at $URL"
echo "Leave this window open while you use it. Close it (Ctrl+C) when done."
echo ""
exec ./.venv/bin/dkcissp-email-analyzer-web
