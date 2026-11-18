#!/usr/bin/env bash
# BAP governed launcher for OpenAI Codex CLI (macOS / Linux / WSL / Git Bash).
# This file MUST keep LF line endings (see .gitattributes).
#
# On macOS/Linux this behaves like the Windows launcher: it injects the generated CODEX.md/AGENTS.md,
# MCP config and hooks, enrolls the session, runs codex itself (NOT wrapped in `bapedge exec`), and
# restores the original files on exit. Cleanup also runs at the next startup (see bap_posix_engine.sh).
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
export LTD_SOURCE="codex"

TARGET_BIN="codex"

# Locate the shared POSIX engine (transactional injection + startup/last-session cleanup).
BAP_ENGINE=""
for _c in "$SCRIPT_DIR/bap_posix_engine.sh" "$SCRIPT_DIR/launchers/bap_posix_engine.sh" \
          "$SCRIPT_DIR/../launchers/bap_posix_engine.sh" "$SCRIPT_DIR/bap/launchers/bap_posix_engine.sh" \
          "$HOME/.bap/launchers/bap_posix_engine.sh" "$HOME/bin/bap_posix_engine.sh"; do
    if [ -f "$_c" ]; then BAP_ENGINE="$_c"; break; fi
done

if [ -n "$BAP_ENGINE" ]; then
    if ! command -v "$TARGET_BIN" >/dev/null 2>&1; then
        echo "[BAP] Error: OpenAI Codex CLI ('$TARGET_BIN') not found in PATH." >&2
        exit 1
    fi
    # shellcheck source=/dev/null
    . "$BAP_ENGINE"
    rc=0
    bap_governed_run codex "OpenAI Codex CLI" -- "$TARGET_BIN" "${AGENT_ARGS[@]}" || rc=$?
    exit "$rc"
fi

# Legacy path (engine not installed): no per-session injection or cleanup.
echo "[BAP] WARNING: bap_posix_engine.sh not found; starting without per-session hook/policy injection." >&2
if [ -f "$SCRIPT_DIR/bapedge" ]; then
    exec "$SCRIPT_DIR/bapedge" exec "$TARGET_BIN" "${AGENT_ARGS[@]}"
elif command -v bapedge >/dev/null 2>&1; then
    exec bapedge exec "$TARGET_BIN" "${AGENT_ARGS[@]}"
elif command -v "$TARGET_BIN" >/dev/null 2>&1; then
    echo "[BAP] WARNING: bapedge not found; running $TARGET_BIN UNGOVERNED." >&2
    exec "$TARGET_BIN" "${AGENT_ARGS[@]}"
else
    echo "[BAP] Error: neither bapedge nor $TARGET_BIN found in PATH." >&2
    exit 1
fi
