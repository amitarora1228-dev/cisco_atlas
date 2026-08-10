#!/usr/bin/env bash
# Project ATLAS - start the unified web shell on macOS or Linux.
#
# ATLAS runs directly on the host; there is no container. This script owns the
# whole contract: virtualenv, pinned dependencies, PYTHONPATH for the package
# layout, and the tshark preflight.
#
#   ./run.sh            start on 127.0.0.1:8000
#   ./run.sh 0.0.0.0    bind all interfaces (see the warning below)
#   ATLAS_PORT=9000 ./run.sh

set -euo pipefail

cd "$(dirname "$0")"

HOST="${1:-127.0.0.1}"
PORT="${ATLAS_PORT:-8000}"
VENV=".venv"

# Application start-up must never install packages; that is this script's job.
export DARTHAWK_AUTO_INSTALL=0
export PYTHONPATH="$PWD/packages/capture_inspector:$PWD/packages/darthawk:$PWD/packages/atlas_core:$PWD/apps"

python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || {
  echo "ERROR: Python 3.10 or newer is required." >&2
  exit 1
}

if [ ! -d "$VENV" ]; then
  echo "[atlas] creating virtualenv"
  python3 -m venv "$VENV"
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"

echo "[atlas] installing pinned dependencies"
python -m pip install --quiet --upgrade pip
python -m pip install --quiet \
  -r packages/capture_inspector/requirements.txt \
  -r packages/darthawk/requirements.txt \
  -r requirements-web.txt

# Capture Inspector skips packet analysis silently when tshark is absent, which
# looks identical to an empty capture. Say so here instead.
if command -v tshark >/dev/null 2>&1; then
  echo "[atlas] tshark: $(tshark --version | head -n1)"
else
  echo "[atlas] WARNING: tshark not found - packet analysis will be DISABLED."
  echo "[atlas]          DART bundle analysis is unaffected."
  echo "[atlas]          Install with: apt-get install tshark   (or: brew install wireshark)"
fi

if [ "$HOST" != "127.0.0.1" ] && [ "$HOST" != "localhost" ]; then
  echo "[atlas] NOTE: binding to $HOST exposes ATLAS beyond this machine."
  echo "[atlas]       Uploads contain captures and DART bundles. Put an"
  echo "[atlas]       authenticating reverse proxy in front before doing this."
fi

echo "[atlas] http://$HOST:$PORT"
exec uvicorn web.main:app --host "$HOST" --port "$PORT"
