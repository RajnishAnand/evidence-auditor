#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$ROOT_DIR/.venv"
COMMAND="${1:-start}"

if [[ "$COMMAND" == "stop" ]]; then
  echo "The TUI runs in the foreground; press q or Ctrl-C to stop it."
  exit 0
fi
if [[ "$COMMAND" != "start" && "$COMMAND" != "tui" ]]; then
  echo "Usage: $0 [start|tui|stop]" >&2
  exit 2
fi
if [[ ! -x "$VENV/bin/python" ]]; then
  echo "Missing project environment: $VENV" >&2
  echo "Create it with: python -m venv .venv && .venv/bin/python -m pip install -e '.[test]'" >&2
  exit 1
fi

exec "$VENV/bin/python" -m backend.app.tui
