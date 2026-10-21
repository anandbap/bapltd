#!/bin/sh
# GitHub Copilot Terminal Execution Wrapper for POSIX
# Routes Copilot commands through ltd-agent with Cedar security policies

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -f "$SCRIPT_DIR/copilot_interceptor" ]; then
    exec "$SCRIPT_DIR/copilot_interceptor" "$@"
elif [ -f "$SCRIPT_DIR/../bap-edge/bapedge" ]; then
    exec "$SCRIPT_DIR/../bap-edge/bapedge" exec --source copilot --raw "$@"
elif [ -f "$SCRIPT_DIR/../ltd-agent/ltd-agent" ]; then
    exec "$SCRIPT_DIR/../ltd-agent/ltd-agent" exec --source copilot --raw "$@"
else
    exec bapedge exec --source copilot --raw "$@"
fi

