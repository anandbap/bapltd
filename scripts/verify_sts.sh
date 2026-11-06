#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if command -v python3 >/dev/null 2>&1; then
    exec python3 "$SCRIPT_DIR/verify_sts_obo_exchange.py" "$@"
else
    exec python "$SCRIPT_DIR/verify_sts_obo_exchange.py" "$@"
fi
