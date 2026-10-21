#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_NAME="$(basename "$0" .sh)"
PS1_FILE="$SCRIPT_DIR/${BASE_NAME}.ps1"

if command -v powershell.exe >/dev/null 2>&1 && [ -f "$PS1_FILE" ]; then
    if command -v wslpath >/dev/null 2>&1; then
        WIN_PS1="$(wslpath -w "$PS1_FILE")"
    else
        WIN_PS1="$PS1_FILE"
    fi
    exec powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$WIN_PS1" "$@"
elif command -v pwsh >/dev/null 2>&1 && [ -f "$PS1_FILE" ]; then
    exec pwsh -NoProfile -File "$PS1_FILE" "$@"
else
    export PATH="$SCRIPT_DIR:$PATH"
    export BAP_SESSION_ID="sess-${BASE_NAME}-$$-$(date +%s)"
    export LTD_SOURCE="copilot"

    TARGET_BIN="code"
    if [ -f "$SCRIPT_DIR/bapedge" ]; then
        exec "$SCRIPT_DIR/bapedge" exec "$TARGET_BIN" "$@"
    elif command -v bapedge >/dev/null 2>&1; then
        exec bapedge exec "$TARGET_BIN" "$@"
    elif command -v "$TARGET_BIN" >/dev/null 2>&1; then
        exec "$TARGET_BIN" "$@"
    else
        echo "[BAP] Error: neither bapedge nor $TARGET_BIN found in PATH." >&2
        exit 1
    fi
fi
