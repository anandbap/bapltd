#!/bin/bash
# =============================================================================
# BAP Control Plane Background Supervisor for Linux / POSIX
# =============================================================================
# Manages bapcontrolplane as a high-availability background daemon.
# Automatically detects process death or termination and respawns it within 1s.
#
# Usage:
#   ./scripts/supervise_controlplane.sh start      # Run in background daemon mode
#   ./scripts/supervise_controlplane.sh stop       # Stop supervisor and server
#   ./scripts/supervise_controlplane.sh status     # Check process status
#   ./scripts/supervise_controlplane.sh restart    # Restart supervisor & server
#   ./scripts/supervise_controlplane.sh foreground # Run in current terminal
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PID_FILE="$REPO_ROOT/.bap-controlplane-supervisor.pid"
SERVER_PID_FILE="$REPO_ROOT/.bap-controlplane.pid"
LOG_FILE="$REPO_ROOT/bap-controlplane-supervisor.log"

# Locate bapcontrolplane binary
find_binary() {
    local candidates=(
        "$REPO_ROOT/dist/linux-amd64/controlplane/bapcontrolplane"
        "$REPO_ROOT/dist/linux-amd64/bapcontrolplane"
        "$REPO_ROOT/dist/linux-arm64/controlplane/bapcontrolplane"
        "$REPO_ROOT/dist/linux-arm64/bapcontrolplane"
        "$REPO_ROOT/bap-controlplane/bapcontrolplane"
        "$REPO_ROOT/bapcontrolplane"
    )
    for c in "${candidates[@]}"; do
        if [ -x "$c" ]; then
            echo "$c"
            return 0
        fi
    done
    return 1
}

# Resolve port and TLS from bap-config.json
resolve_args() {
    local port=8443
    local tls_flag="-https"
    local config_file="$REPO_ROOT/bap-config.json"

    if [ -f "$config_file" ]; then
        if grep -q '"controlplane_url"' "$config_file"; then
            if grep -q 'http://' "$config_file"; then
                tls_flag=""
                port=8080
            fi
            local parsed_port
            parsed_port=$(grep -oE ':[0-9]+' "$config_file" | tr -d ':' | head -n1)
            if [ -n "$parsed_port" ]; then
                port="$parsed_port"
            fi
        fi
    fi

    echo "-port $port -ttl 30 -trust-domain bap.internal $tls_flag"
}

run_supervisor_loop() {
    local bin="$1"
    local server_args="$2"

    echo "$$" > "$PID_FILE"
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [SUPERVISOR] Started supervisor loop (PID: $$)" >> "$LOG_FILE"

    cleanup() {
        echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [SUPERVISOR] Caught termination signal. Stopping bapcontrolplane..." >> "$LOG_FILE"
        if [ -f "$SERVER_PID_FILE" ]; then
            local spid
            spid=$(cat "$SERVER_PID_FILE" 2>/dev/null)
            if [ -n "$spid" ] && kill -0 "$spid" 2>/dev/null; then
                kill -TERM "$spid" 2>/dev/null || kill -9 "$spid" 2>/dev/null
            fi
            rm -f "$SERVER_PID_FILE"
        fi
        rm -f "$PID_FILE"
        exit 0
    }

    trap cleanup SIGTERM SIGINT SIGHUP

    local restart_count=0

    while true; do
        echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [SUPERVISOR] Spawning: $bin $server_args (Attempt #$((restart_count + 1)))" >> "$LOG_FILE"
        
        # Run server in child process
        "$bin" $server_args >> "$LOG_FILE" 2>&1 &
        local child_pid=$!
        echo "$child_pid" > "$SERVER_PID_FILE"

        echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [SUPERVISOR] bapcontrolplane is live (PID: $child_pid)" >> "$LOG_FILE"

        # Wait for child to exit
        wait "$child_pid" 2>/dev/null
        local exit_code=$?

        rm -f "$SERVER_PID_FILE"
        echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [SUPERVISOR] WARNING: bapcontrolplane (PID: $child_pid) died with code $exit_code. Respawning in 1s..." >> "$LOG_FILE"
        restart_count=$((restart_count + 1))
        sleep 1
    done
}

cmd_start() {
    if [ -f "$PID_FILE" ]; then
        local existing_pid
        existing_pid=$(cat "$PID_FILE" 2>/dev/null)
        if [ -n "$existing_pid" ] && kill -0 "$existing_pid" 2>/dev/null; then
            echo "[!] BAP Control Plane supervisor is already running (PID: $existing_pid)."
            return 0
        fi
    fi

    local bin
    bin=$(find_binary)
    if [ -z "$bin" ]; then
        echo "[-] Error: bapcontrolplane binary not found. Build binaries first."
        exit 1
    fi

    local args
    args=$(resolve_args)

    echo "[*] Launching BAP Control Plane background supervisor..."
    echo "[*] Binary: $bin"
    echo "[*] Args  : $args"
    echo "[*] Log   : $LOG_FILE"

    nohup bash -c "$(declare -f run_supervisor_loop); run_supervisor_loop '$bin' '$args'" >> "$LOG_FILE" 2>&1 &
    local sup_pid=$!
    echo "$sup_pid" > "$PID_FILE"
    sleep 2

    if kill -0 "$sup_pid" 2>/dev/null; then
        echo "[+] BAP Control Plane supervisor active in background (PID: $sup_pid)."
        if [ -f "$SERVER_PID_FILE" ]; then
            echo "[+] bapcontrolplane daemon running (PID: $(cat "$SERVER_PID_FILE"))."
        fi
    else
        echo "[-] Failed to start supervisor. Check $LOG_FILE for details."
        exit 1
    fi
}

cmd_stop() {
    local stopped=0
    if [ -f "$PID_FILE" ]; then
        local sup_pid
        sup_pid=$(cat "$PID_FILE" 2>/dev/null)
        if [ -n "$sup_pid" ] && kill -0 "$sup_pid" 2>/dev/null; then
            echo "[*] Stopping BAP Control Plane supervisor (PID: $sup_pid)..."
            kill -TERM "$sup_pid" 2>/dev/null
            stopped=1
        fi
        rm -f "$PID_FILE"
    fi

    if [ -f "$SERVER_PID_FILE" ]; then
        local s_pid
        s_pid=$(cat "$SERVER_PID_FILE" 2>/dev/null)
        if [ -n "$s_pid" ] && kill -0 "$s_pid" 2>/dev/null; then
            echo "[*] Stopping bapcontrolplane server (PID: $s_pid)..."
            kill -TERM "$s_pid" 2>/dev/null || kill -9 "$s_pid" 2>/dev/null
            stopped=1
        fi
        rm -f "$SERVER_PID_FILE"
    fi

    # Fallback check for any stray bapcontrolplane processes
    pkill -f "bapcontrolplane" 2>/dev/null

    if [ $stopped -eq 1 ]; then
        echo "[+] BAP Control Plane stopped successfully."
    else
        echo "[*] No active BAP Control Plane supervisor found."
    fi
}

cmd_status() {
    echo "==============================================================================="
    echo "           BAP CONTROL PLANE SUPERVISOR STATUS (LINUX)                        "
    echo "==============================================================================="
    if [ -f "$PID_FILE" ]; then
        local sup_pid
        sup_pid=$(cat "$PID_FILE" 2>/dev/null)
        if [ -n "$sup_pid" ] && kill -0 "$sup_pid" 2>/dev/null; then
            echo "  Supervisor Status : RUNNING (PID: $sup_pid)"
            if [ -f "$SERVER_PID_FILE" ]; then
                local s_pid
                s_pid=$(cat "$SERVER_PID_FILE" 2>/dev/null)
                if [ -n "$s_pid" ] && kill -0 "$s_pid" 2>/dev/null; then
                    echo "  Server Status     : ACTIVE (PID: $s_pid)"
                else
                    echo "  Server Status     : RESTARTING..."
                fi
            fi
            echo "  Log File          : $LOG_FILE"
            echo "==============================================================================="
            return 0
        fi
    fi
    echo "  Status : STOPPED (Not running)"
    echo "==============================================================================="
    return 1
}

ACTION="${1:-start}"
case "$ACTION" in
    start)
        cmd_start
        ;;
    stop)
        cmd_stop
        ;;
    status)
        cmd_status
        ;;
    restart)
        cmd_stop
        sleep 1
        cmd_start
        ;;
    foreground)
        bin=$(find_binary)
        if [ -z "$bin" ]; then
            echo "[-] Error: bapcontrolplane binary not found."
            exit 1
        fi
        args=$(resolve_args)
        run_supervisor_loop "$bin" "$args"
        ;;
    *)
        echo "Usage: $0 {start|stop|status|restart|foreground}"
        exit 1
        ;;
esac

