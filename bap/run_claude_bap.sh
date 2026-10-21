#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
chmod +x "$SCRIPT_DIR/bapedge" "$SCRIPT_DIR/cchook/interceptor" 2>/dev/null || true
export PATH="$SCRIPT_DIR:$SCRIPT_DIR/cchook:$PATH"

SERVER_URL="${1:-}"
if [ -z "$SERVER_URL" ] && [ -f "bap-config.json" ]; then
    SERVER_URL=$(grep -o '"controlplane_url": *"[^"]*"' bap-config.json | cut -d'"' -f4)
elif [ -z "$SERVER_URL" ] && [ -f "$SCRIPT_DIR/bap-config.json" ]; then
    SERVER_URL=$(grep -o '"controlplane_url": *"[^"]*"' "$SCRIPT_DIR/bap-config.json" | cut -d'"' -f4)
fi
if [ -z "$SERVER_URL" ]; then
    SERVER_URL="http://localhost:8080"
fi

echo "==============================================================================="
echo "  CLAUDE CODE - BOUNDED AUTHORITY PLANE (BAP) GOVERNED CLIENT"
echo "  Working Directory: $(pwd)"
echo "  Target Control Plane: $SERVER_URL"
echo "==============================================================================="

export BAP_SESSION_ID="sess-claude-$$-$(date +%s)"
export BAP_SERVER_URL="$SERVER_URL"

# Start native detached bapedge session watcher
"$SCRIPT_DIR/bapedge" watch --server "$SERVER_URL" --session-id "$BAP_SESSION_ID" --detach 2>/dev/null || true

# Execute Claude Code in current workspace directory
exec claude "$@"
