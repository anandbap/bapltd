#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/scripts/review_session.sh" ]; then
    exec "$SCRIPT_DIR/scripts/review_session.sh" "$@"
else
    echo "[-] Error: review_session.sh not found in $SCRIPT_DIR/scripts" >&2
    exit 1
fi
