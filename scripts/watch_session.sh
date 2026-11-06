#!/usr/bin/env bash
# ==============================================================================
# BAP Session Liveness Watcher (POSIX)
# Periodically verifies process liveness and notifies control plane on exit
# ==============================================================================
SERVER_URL="${1:-}"
SESSION_ID="${2:-}"
WATCH_PID="${3:-}"

if [ -z "$SERVER_URL" ] || [ -z "$SESSION_ID" ]; then
    exit 0
fi

if [ -z "$WATCH_PID" ] || [ "$WATCH_PID" -le 0 ]; then
    WATCH_PID=$PPID
fi

while kill -0 "$WATCH_PID" 2>/dev/null; do
    sleep 2
done

curl -s -X POST "$SERVER_URL/api/v1/sessions/end" \
    -H "Content-Type: application/json" \
    -d "{\"session_id\":\"$SESSION_ID\",\"reason\":\"Agent process exited\"}" >/dev/null 2>&1 || true

if [ -f ".bap-session.json" ]; then
    rm -f ".bap-session.json" 2>/dev/null || true
fi
