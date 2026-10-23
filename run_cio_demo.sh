#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

if ! command -v python3 >/dev/null 2>&1 && ! command -v python >/dev/null 2>&1; then
    echo "[-] Python 3 is not found in PATH. Please install Python 3.8+ to run this demo."
    exit 1
fi

PY_BIN="python3"
if ! command -v python3 >/dev/null 2>&1; then
    PY_BIN="python"
fi

case "$1" in
    workforce|--workforce|-workforce)
        shift
        exec "$PY_BIN" demo_cio_workforce.py "$@"
        ;;
    remote|--remote|-remote)
        shift
        exec "$PY_BIN" demo_remote_cio.py "$@"
        ;;
    v3|--v3|-v3)
        shift
        exec "$PY_BIN" demo_v3_cio.py "$@"
        ;;
    *)
        exec "$PY_BIN" demo_v3_cio.py "$@"
        ;;
esac
