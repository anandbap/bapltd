#!/usr/bin/env bash
# BAP governed Claude Code launcher (macOS / Linux / WSL / Git Bash).
# This file MUST keep LF line endings (see .gitattributes); a CRLF shebang
# ("bash\r") makes the script fail to start on macOS/Linux.
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_NAME="$(basename "$0" .sh)"
PS1_FILE="$SCRIPT_DIR/${BASE_NAME}.ps1"

# Windows-hosted POSIX shells (Git Bash / MSYS2 / Cygwin) delegate to the native
# PowerShell launcher, which implements the full transactional hook custody.
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

chmod +x "$SCRIPT_DIR/bapedge" "$SCRIPT_DIR/cchook/interceptor" 2>/dev/null || true
# Append common install locations that a non-login shell / GUI-launched
# terminal on macOS often lacks (Homebrew, npm -g, native installers).
export PATH="$SCRIPT_DIR:$SCRIPT_DIR/cchook:$PATH:/opt/homebrew/bin:/usr/local/bin:$HOME/.local/bin:$HOME/.claude/local"

# Server resolution order: --server flag / leading URL > $BAP_SERVER_URL > bap-config.json > default.
SERVER_URL="${BAP_SERVER_URL:-}"
AGENT_ARGS=()

# Backward compatible: a leading bare URL is the server.
case "${1:-}" in
    http://*|https://*) SERVER_URL="$1"; shift ;;
esac

# BAP launcher flags are consumed here and are never forwarded to claude,
# which would reject them as unknown options.
while [ $# -gt 0 ]; do
    case "$1" in
        --server=*|--server-url=*)
            SERVER_URL="${1#*=}"
            ;;
        --server|--server-url)
            if [ $# -gt 1 ]; then
                shift
                SERVER_URL="$1"
            fi
            ;;
        *)
            AGENT_ARGS+=("$1")
            ;;
    esac
    shift
done

if [ -z "$SERVER_URL" ] && [ -f "bap-config.json" ]; then
    SERVER_URL=$(grep -o '"controlplane_url": *"[^"]*"' bap-config.json | cut -d'"' -f4)
fi
if [ -z "$SERVER_URL" ] && [ -f "$SCRIPT_DIR/bap-config.json" ]; then
    SERVER_URL=$(grep -o '"controlplane_url": *"[^"]*"' "$SCRIPT_DIR/bap-config.json" | cut -d'"' -f4)
fi
if [ -z "$SERVER_URL" ]; then
    SERVER_URL="http://localhost:8080"
fi
SERVER_URL="${SERVER_URL%/}"

echo "==============================================================================="
echo "  CLAUDE CODE - BOUNDED AUTHORITY PLANE (BAP) GOVERNED CLIENT"
echo "  Working Directory: $(pwd)"
echo "  Target Control Plane: $SERVER_URL"
echo "==============================================================================="

export BAP_SESSION_ID="sess-claude-$$-$(date +%s)"
export BAP_SERVER_URL="$SERVER_URL"
export BAP_CONTROL_PLANE_URL="$SERVER_URL"
export LTD_SOURCE="claude-code"

# Start native detached bapedge session watcher
if [ -x "$SCRIPT_DIR/bapedge" ]; then
    "$SCRIPT_DIR/bapedge" watch --server "$SERVER_URL" --session-id "$BAP_SESSION_ID" --detach 2>/dev/null || true
elif command -v bapedge >/dev/null 2>&1; then
    bapedge watch --server "$SERVER_URL" --session-id "$BAP_SESSION_ID" --detach 2>/dev/null || true
fi

if ! command -v claude >/dev/null 2>&1; then
    echo "[BAP] Error: Claude Code CLI ('claude') not found in PATH." >&2
    echo "      Install with: npm install -g @anthropic-ai/claude-code" >&2
    exit 1
fi

# Execute Claude Code in current workspace directory
exec claude "${AGENT_ARGS[@]}"
