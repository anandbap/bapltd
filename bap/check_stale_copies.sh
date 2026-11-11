#!/usr/bin/env bash
# ==============================================================================
# BAP Asset Integrity Audit: Checking for Stale Copies across Fleet
# ==============================================================================
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if command -v pwsh >/dev/null 2>&1; then
    exec pwsh -NoProfile -File "$SCRIPT_DIR/check_stale_copies.ps1" "$@"
elif command -v powershell.exe >/dev/null 2>&1; then
    exec powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_DIR/check_stale_copies.ps1" "$@"
else
    echo "[-] PowerShell (pwsh) is required to run check_stale_copies." >&2
    exit 1
fi
