#!/usr/bin/env bash
# Sherlock OSINT & Due Diligence Runner
set -e

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
cd "$DIR"

# Ensure venv exists
if [ ! -d "$DIR/.venv" ]; then
    echo "Virtual environment missing at $DIR/.venv. Creating..."
    uv venv "$DIR/.venv"
    VIRTUAL_ENV="$DIR/.venv" uv pip install -e .
fi

# If CLI arguments were provided, pass through to sherlock binary
if [ $# -gt 0 ]; then
    exec "$DIR/.venv/bin/sherlock" "$@"
else
    # Default: launch interactive dashboard
    exec "$DIR/.venv/bin/sherlock" tui
fi
