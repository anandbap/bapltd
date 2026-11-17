#!/usr/bin/env bash
# BAP governed launcher (macOS / Linux / WSL / Git Bash).
# This file MUST keep LF line endings (see .gitattributes).
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_NAME="$(basename "$0" .sh)"
PS1_FILE="$SCRIPT_DIR/${BASE_NAME}.ps1"

# Windows-hosted POSIX shells (Git Bash / MSYS2 / Cygwin) delegate to the native
# PowerShell launcher. The .ps1 launchers are Windows-only, so they are never
# used on macOS, Linux or WSL (even when pwsh is installed there).
case "$(uname -s 2>/dev/null)" in
    MINGW*|MSYS*|CYGWIN*)
        if [ -f "$PS1_FILE" ] && command -v powershell.exe >/dev/null 2>&1; then
            WIN_PS1="$PS1_FILE"
            if command -v cygpath >/dev/null 2>&1; then
                WIN_PS1="$(cygpath -w "$PS1_FILE")"
            fi
            exec powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$WIN_PS1" "$@"
        fi
        ;;
esac

# Native POSIX path. BAP launcher flags are consumed here and are never
# forwarded to the agent CLI (which would reject them as unknown options).
AGENT_ARGS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --server=*|--server-url=*)
            export BAP_SERVER_URL="${1#*=}"
            export BAP_CONTROL_PLANE_URL="$BAP_SERVER_URL"
            ;;
        --server|--server-url)
            if [ $# -gt 1 ]; then
                shift
                export BAP_SERVER_URL="$1"
                export BAP_CONTROL_PLANE_URL="$BAP_SERVER_URL"
            fi
            ;;
        *)
            AGENT_ARGS+=("$1")
            ;;
    esac
    shift
done

# Append common install locations that a non-login shell / GUI-launched
# terminal on macOS often lacks (Homebrew, npm -g, native installers).
export PATH="$SCRIPT_DIR:$PATH:/opt/homebrew/bin:/usr/local/bin:$HOME/.local/bin:$HOME/.claude/local"
export BAP_SESSION_ID="sess-${BASE_NAME}-$$-$(date +%s)"
export LTD_SOURCE="copilot"

TARGET_BIN="copilot"
if [ -f "$SCRIPT_DIR/bapedge" ]; then
    exec "$SCRIPT_DIR/bapedge" exec "$TARGET_BIN" "${AGENT_ARGS[@]}"
elif command -v bapedge >/dev/null 2>&1; then
    exec bapedge exec "$TARGET_BIN" "${AGENT_ARGS[@]}"
elif command -v "$TARGET_BIN" >/dev/null 2>&1; then
    exec "$TARGET_BIN" "${AGENT_ARGS[@]}"
else
    echo "[BAP] Error: neither bapedge nor $TARGET_BIN found in PATH." >&2
    exit 1
fi
