#!/bin/bash
# BAP Edge post-install script for macOS .pkg installers
set -e

INSTALL_BIN="/usr/local/bin/bapedge"
CONFIG_DIR="/etc/bap"
LOG_DIR="/var/log/bap"
LAUNCHD_PLIST="/Library/LaunchDaemons/com.bap.edge.plist"

mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"
chmod 755 "$CONFIG_DIR"
chmod 755 "$LOG_DIR"

# Ensure binary permissions
if [ -f "$INSTALL_BIN" ]; then
    chmod 755 "$INSTALL_BIN"
    chown root:wheel "$INSTALL_BIN"
fi

# Install LaunchDaemon
if [ -f "/tmp/com.bap.edge.plist" ]; then
    cp "/tmp/com.bap.edge.plist" "$LAUNCHD_PLIST"
    chmod 644 "$LAUNCHD_PLIST"
    chown root:wheel "$LAUNCHD_PLIST"
    
    # Reload daemon if running
    launchctl unload "$LAUNCHD_PLIST" 2>/dev/null || true
    launchctl load -w "$LAUNCHD_PLIST" 2>/dev/null || true
fi

exit 0
