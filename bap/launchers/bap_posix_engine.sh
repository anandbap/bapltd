#!/usr/bin/env bash
# BAP POSIX launcher engine (macOS / Linux / WSL) - BAP-1101.
# This file is SOURCED by run_claude_bap.sh, run_codex_cli_bap.sh and run_antigravity_cli_bap.sh.
# It MUST keep LF line endings (see .gitattributes) and stay compatible with bash 3.2 (macOS).
#
# What it does for one governed session, mirroring the Windows bap_launcher_engine.ps1:
#   1. Takes a per-workspace lock.
#   2. STARTUP CLEANUP: if no live session owns the workspace, it restores files left by a crashed
#      or killed run (recovery manifest) and recovers any orphaned `<file>.bap-backup-<session>`
#      copies, so a new session never starts from injected leftovers.
#   3. Injects the generated per-session policy/hook/MCP files, after backing up each original and
#      recording it in a manifest BEFORE overwriting it.
#   4. Runs the agent as a child (not exec) so cleanup can run when it exits or is signalled.
#   5. LAST-SESSION CLEANUP: reference-counted across concurrent sessions in the same workspace;
#      only the last live session restores the originals, then sweeps for orphans once more.
# A launcher that is SIGKILLed cannot clean up; the next startup does (step 2).

BAP_ENGINE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Files a launcher may inject into, relative to the workspace.
BAP_MANAGED_RELPATHS="GEMINI.md AGENTS.md CLAUDE.md CODEX.md .antigravity/mcp_config.json .gemini/config/mcp_config.json .claude/settings.json .claude/mcp.json .codex/mcp.json .codex/hooks.json .cursor/mcp.json .cursorrules .vscode/settings.json .vscode/mcp.json .copilot/bap-session.json .copilot/mcp-config.json .opencode/opencode.json"

bap_log() { printf '%s\n' "$*" >&2; }

# ---------------------------------------------------------------------------
# State, locking, session liveness
# ---------------------------------------------------------------------------
bap_ws_hash() {
    if command -v shasum >/dev/null 2>&1; then
        printf '%s' "$1" | shasum -a 256 | cut -c1-16
    elif command -v sha256sum >/dev/null 2>&1; then
        printf '%s' "$1" | sha256sum | cut -c1-16
    else
        printf '%s' "$1" | cksum | tr ' ' '-'
    fi
}

bap_lock() {
    local tries=0 owner
    while ! mkdir "$BAP_LAUNCH_STATE/lock" 2>/dev/null; do
        owner="$(cat "$BAP_LAUNCH_STATE/lock/pid" 2>/dev/null || true)"
        if [ -n "$owner" ] && ! kill -0 "$owner" 2>/dev/null; then
            rm -rf "$BAP_LAUNCH_STATE/lock"   # owner died holding the lock
            continue
        fi
        tries=$((tries + 1))
        if [ "$tries" -gt 150 ]; then
            bap_log "[BAP] Could not acquire the workspace coordination lock."
            return 1
        fi
        sleep 0.1 2>/dev/null || sleep 1
    done
    printf '%s' "$$" > "$BAP_LAUNCH_STATE/lock/pid"
    return 0
}

bap_unlock() { rm -rf "$BAP_LAUNCH_STATE/lock"; }

bap_pid_start() { ps -p "$1" -o lstart= 2>/dev/null | sed -e 's/^ *//' -e 's/ *$//'; }

# A session file is named after the launcher PID; line 1 = session id, line 2 = process start time
# (guards against PID reuse).
bap_session_alive() {
    local pid stored cur
    pid="${1##*/}"
    kill -0 "$pid" 2>/dev/null || return 1
    stored="$(sed -n '2p' "$1" 2>/dev/null)"
    cur="$(bap_pid_start "$pid")"
    [ -z "$stored" ] || [ "$stored" = "$cur" ]
}

# Prints the number of live sessions and removes the records of dead ones.
bap_live_sessions() {
    local n=0 f
    for f in "$BAP_LAUNCH_STATE"/sessions/*; do
        [ -e "$f" ] || continue
        if bap_session_alive "$f"; then
            n=$((n + 1))
        else
            rm -f "$f"
        fi
    done
    printf '%s' "$n"
}

# ---------------------------------------------------------------------------
# File custody: staging, injection, restore, orphan recovery
# ---------------------------------------------------------------------------
bap_atomic_write() {
    local dest="$1" dir tmp
    dir="$(dirname "$dest")"
    mkdir -p "$dir" || return 1
    tmp="$dest.bap-tmp-$$"
    cat > "$tmp" || { rm -f "$tmp"; return 1; }
    mv -f "$tmp" "$dest"
}

# bap_add_file <relative-path>   (content on stdin)
bap_add_file() {
    BAP_STAGE_N=$((BAP_STAGE_N + 1))
    printf '%s' "$1" > "$BAP_STAGE_DIR/$BAP_STAGE_N.rel"
    cat > "$BAP_STAGE_DIR/$BAP_STAGE_N.content"
}

# Markers only BAP launchers write; a developer's own file will not carry them.
bap_is_injected() {
    if grep -Eq 'BAP Zero-Trust Policy & Enterprise Governance|"bap-zero-trust"|bapmcp|BAP_SESSION_ID' "$1" 2>/dev/null; then
        return 0
    fi
    if grep -q 'interceptor' "$1" 2>/dev/null && grep -q 'disableAllHooks' "$1" 2>/dev/null; then
        return 0
    fi
    return 1
}

bap_restore_manifest() {
    local m="$BAP_LAUNCH_STATE/manifest" failed=0 existed target backup tab
    [ -f "$m" ] || return 0
    tab="$(printf '\t')"
    while IFS="$tab" read -r existed target backup; do
        [ -n "$target" ] || continue
        if [ "$existed" = "1" ]; then
            if [ -f "$backup" ]; then
                if cp -p "$backup" "$target" 2>/dev/null; then
                    rm -f "$backup"
                else
                    bap_log "[BAP] WARNING: could not restore $target from $backup"
                    failed=1
                fi
            else
                bap_log "[BAP] WARNING: backup for $target is missing; leaving the file as is."
            fi
        else
            rm -f "$target" 2>/dev/null || true
            rmdir "$(dirname "$target")" 2>/dev/null || true
        fi
    done < "$m"
    if [ "$failed" -eq 0 ]; then
        rm -f "$m"
    fi
    return "$failed"
}

bap_inject_staged() {
    local i=1 rel target backup existed tab
    tab="$(printf '\t')"
    while [ "$i" -le "$BAP_STAGE_N" ]; do
        rel="$(cat "$BAP_STAGE_DIR/$i.rel")"
        target="$BAP_WORKSPACE/$rel"
        backup="$target.bap-backup-$BAP_SESSION_ID"
        mkdir -p "$(dirname "$target")" || { bap_restore_manifest || true; return 1; }
        if [ -f "$target" ]; then
            existed=1
            cp -p "$target" "$backup" || { bap_restore_manifest || true; return 1; }
        else
            existed=0
        fi
        # Record BEFORE overwriting so a crash at any point is recoverable.
        printf '%s%s%s%s%s\n' "$existed" "$tab" "$target" "$tab" "$backup" >> "$BAP_LAUNCH_STATE/manifest"
        if ! bap_atomic_write "$target" < "$BAP_STAGE_DIR/$i.content"; then
            bap_log "[BAP] Could not write $target"
            bap_restore_manifest || true
            return 1
        fi
        i=$((i + 1))
    done
    return 0
}

# Restores the developer's original file from orphaned `<file>.bap-backup-<session>` copies left by
# a crashed, killed or manifest-less run. A backup that already holds BAP-injected content is never
# restored; if no backup is provably the original they are archived, not deleted.
# Call only while holding the lock and when no live session or manifest remains.
bap_repair_orphans() {
    local rel target dir leaf b best found
    for rel in $BAP_MANAGED_RELPATHS; do
        target="$BAP_WORKSPACE/$rel"
        dir="$(dirname "$target")"
        leaf="$(basename "$target")"
        [ -d "$dir" ] || continue
        best=""
        found=0
        for b in "$dir/$leaf".bap-backup-*; do
            [ -f "$b" ] || continue
            found=1
            if bap_is_injected "$b"; then
                continue
            fi
            if [ -z "$best" ] || [ "$b" -nt "$best" ]; then
                best="$b"
            fi
        done
        [ "$found" -eq 1 ] || continue
        if [ -n "$best" ]; then
            if cp -p "$best" "$target" 2>/dev/null; then
                bap_log "[BAP] Recovered original $rel from orphaned backup."
                rm -f "$dir/$leaf".bap-backup-*
            else
                bap_log "[BAP] WARNING: could not recover $rel; orphaned backups kept."
            fi
        else
            mkdir -p "$dir/.bap-recovery-archive" 2>/dev/null &&
                mv -f "$dir/$leaf".bap-backup-* "$dir/.bap-recovery-archive/" 2>/dev/null || true
        fi
    done
}

# ---------------------------------------------------------------------------
# Generated content
# ---------------------------------------------------------------------------
bap_json_str() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

# bap_find_bin <name>...  -> first executable found next to the launcher, in standard BAP dirs, or on PATH
bap_find_bin() {
    local name dir
    for name in "$@"; do
        for dir in "$BAP_ENGINE_DIR" "$BAP_ENGINE_DIR/.." "$BAP_ENGINE_DIR/../cchook" "$BAP_ENGINE_DIR/cchook" "$HOME/.bap/bin" "$HOME/bin" "/usr/local/bin"; do
            if [ -x "$dir/$name" ] && [ ! -d "$dir/$name" ]; then
                (cd "$dir" && printf '%s/%s' "$(pwd)" "$name")
                return 0
            fi
        done
        if command -v "$name" >/dev/null 2>&1; then
            command -v "$name"
            return 0
        fi
    done
    return 1
}

bap_rule_text() {
    sed -e "s/@AGENT@/$1/g" -e "s/@NAME@/$2/g" <<'EOF'
# BAP Zero-Trust Policy & Enterprise Governance for @NAME@

This workspace is actively governed by the BAP Zero-Trust Local Trusted Daemon (bapedge).

## Enterprise Governance & Boundaries
1. **Multi-Project Workspace & Dependency Traversal**:
   - Reading, inspecting, and navigating cross-project dependencies, sibling repositories, shared schemas, and local dependency caches (e.g. `../sibling-project`, `~/.m2`, `~/.gradle`) is **PERMITTED** for build and code intelligence.
   - Modifying, deleting, or redirecting output to files outside the authorized workspace is strictly prohibited without explicit human authorization.
2. **Absolute Secret Protection**:
   - Access to credential files (`.env`, `~/.aws`, `~/.ssh`, private keys) is strictly forbidden across all directories, whether inside or outside the workspace.
3. **Software Supply Chain & Package Management**:
   - Package managers (Maven, Gradle, npm, pip) must use approved corporate mirrors (e.g. local Nexus / Artifactory). Bypassing internal repos to download directly from public internet registries is prohibited.
   - Installation of unapproved standalone software or setup binaries is strictly blocked.
4. **Network Egress & Execution Broker**:
   - All shell executions MUST run through the BAP Edge Execution Broker: `bapedge exec "<command>"`.
   - Raw network exfiltration utilities (`curl`, `wget`, `nc`, raw sockets) are strictly prohibited; external API access must route through the BAP Gateway PEP.
5. **Zero-Trust Policy Enforcement & JIT Task Grants**:
   - Commands are evaluated against Cedar invariants before execution.
   - **Zero Standing Privileges (ZSP)**: The agent operates with zero standing execution privileges.
   - **Read-Only Exemption**: Plain project inspection within the workspace (`git status`, `git log`, `git diff`, directory listing, file viewing) is permitted automatically.
   - Follow the BAP task authorization workflow below for grants, renewal and human approval.
## BAP task authorization workflow

Use the session ID supplied by BAP. Submit ordinary supported inspection and
workspace edits normally: hooks evaluate policy and obtain eligible JIT grants.
An installed client with automatic grants disabled must request a grant first.
Shell commands must execute through `bapedge exec "<command>"` (`bapedge.exe` on
Windows); native Read/Write/Edit tools remain governed by their BAP hooks.

If BAP asks for authorization, run the suggested standalone command yourself:
`bapedge zsp authorize --session-id "<active-session-id>" --mission TASK_EXECUTION --goal "<task intent>" --actions "<canonical:action>" --resources workspace://current`
Use the actual session ID from hook context or the environment: PowerShell
`$env:BAP_SESSION_ID`, CMD `%BAP_SESSION_ID%`, POSIX shells `$BAP_SESSION_ID`.
Do not chain authorization with execution or dispatch dependent tools before it finishes.
Alternatively use `bap_request_task_grant` when that MCP tool is available.

Generic grants default to one use. For several ordinary workspace file edits,
request only `fs:file:write` with `--max-uses 25 --ttl 600s`; the signed policy
can narrow those ceilings. Do not mix Python, builds, deletion or publishing
into an edit grant. Running the created script requires a separate execution grant.
Read the granted actions, resources, remaining uses and expiry before relying on it.
Authorization itself does not spend the new grant. Duplicate callbacks for one
stable native tool-use ID spend once; a new tool call spends another edit use.

An expired/exhausted grant requires fresh policy authorization. If a newly issued
grant is immediately reported burned, report the hook defect and stop the loop;
do not keep minting grants or switch to shell writes to bypass a native denial.
If BAP returns a pending approval request, tell the human the request ID and exact
`bapedge zsp approve <request-id>` command for their own terminal, then wait for
approval before retrying. Never approve your own request or enable developer override.
Auto-approve cannot satisfy rules requiring separate human approval. Credential
and protected-policy denials must never be retried through another tool or shell.

6. **Multi-Layer Defense-in-Depth & Policy Protection**:
   - Instruction and policy files (`GEMINI.md`, `CLAUDE.md`, `AGENTS.md`, `CODEX.md`, `policy.cedar`, `.bap/pins.json`) are tamper-proof and actively defended across 5 layers:
     - **Layer 1 (In-Harness Tool Hooks)**: Tool write/edit attempts targeting policy files are blocked before execution.
     - **Layer 2 (Execution Broker)**: `bapedge exec` evaluates commands against Cedar invariants, blocking file overwrites or redirects to policy files.
     - **Layer 3 (Cryptographic FIM & Pinning)**: `.bap/pins.json` verifies SHA-256 hashes in real time. Any unverified drift immediately halts execution fail-closed with `HashMismatchError`.
     - **Layer 4 (Anomaly Risk Engine)**: Tampering attempts trigger `DENIED_TAMPER` alerts and escalate the session threat score to CRITICAL.
     - **Layer 5 (Control Plane Attestation)**: The central control plane validates cryptographic attestation and revokes compromised sessions.
7. **Identity & Audit Logging**:
   - LTD_SOURCE=@AGENT@
   - BAP_SESSION_ID is provided in the environment of this session.
8. **Developer Override & Agent Immunity**:
   - Autonomous agents are **STRICTLY FORBIDDEN** from executing `bapedge dev-override on`. That command requires interactive human authorization.
EOF
}

bap_mcp_json() {
    local cmd args
    cmd="$(bap_find_bin bapmcp || true)"
    args='[]'
    if [ -z "$cmd" ]; then
        cmd="$(bap_find_bin bapedge || true)"
        args='["mcp"]'
    fi
    [ -n "$cmd" ] || cmd="bapmcp"
    printf '{\n  "mcpServers": {\n    "bap-zero-trust": {\n      "command": "%s",\n      "args": %s,\n      "env": {\n        "LTD_SOURCE": "%s",\n        "BAP_SESSION_ID": "%s",\n        "BAP_SERVER_URL": "%s",\n        "BAP_CONTROL_PLANE_URL": "%s"\n      }\n    }\n  }\n}\n' \
        "$(bap_json_str "$cmd")" "$args" "$(bap_json_str "$1")" "$(bap_json_str "$BAP_SESSION_ID")" \
        "$(bap_json_str "${BAP_SERVER_URL:-}")" "$(bap_json_str "${BAP_SERVER_URL:-}")"
}

bap_stage_claude() {
    bap_add_file "CLAUDE.md" < <(bap_rule_text claude-code "Claude Code")
    local icpt h
    icpt="$(bap_find_bin interceptor cchook-interceptor || true)"
    if [ -z "$icpt" ]; then
        bap_log "[BAP] WARNING: interceptor binary not found; hooks are NOT injected for this session (relying on globally installed hooks)."
        return 0
    fi
    h="{\"type\": \"command\", \"command\": \"$(bap_json_str "$icpt")\", \"args\": []}"
    bap_add_file ".claude/settings.json" <<EOF
{
  "disableAllHooks": false,
  "hooks": {
    "SessionStart": [ { "hooks": [ $h ] } ],
    "UserPromptSubmit": [ { "hooks": [ $h ] } ],
    "PreToolUse": [ { "matcher": "*", "hooks": [ $h ] } ],
    "PostToolUse": [ { "matcher": "*", "hooks": [ $h ] } ],
    "PostToolUseFailure": [ { "matcher": "*", "hooks": [ $h ] } ],
    "Stop": [ { "hooks": [ $h ] } ],
    "SessionEnd": [ { "hooks": [ $h ] } ]
  }
}
EOF
}

bap_stage_codex() {
    local icpt h
    # NOTE: never `cmd | bap_add_file` - a pipeline runs bap_add_file in a subshell and the
    # BAP_STAGE_N increment is lost, so every file lands in slot 1. Process substitution keeps
    # the function in this shell.
    bap_add_file "CODEX.md" < <(bap_rule_text codex "OpenAI Codex")
    bap_add_file "AGENTS.md" < <(bap_rule_text codex "OpenAI Codex")
    bap_add_file ".codex/mcp.json" < <(bap_mcp_json codex)
    icpt="$(bap_find_bin interceptor cchook-interceptor || true)"
    if [ -z "$icpt" ]; then
        bap_log "[BAP] WARNING: interceptor binary not found; Codex hooks are NOT injected for this session."
        return 0
    fi
    h="{\"type\": \"command\", \"command\": \"$(bap_json_str "$icpt")\", \"timeout\": 10}"
    bap_add_file ".codex/hooks.json" <<EOF
{
  "description": "BAP zero-trust lifecycle governance and prompt telemetry.",
  "hooks": {
    "SessionStart": [ { "hooks": [ $h ] } ],
    "UserPromptSubmit": [ { "hooks": [ $h ] } ],
    "PreToolUse": [ { "matcher": ".*", "hooks": [ $h ] } ],
    "Stop": [ { "hooks": [ $h ] } ],
    "SessionEnd": [ { "hooks": [ $h ] } ]
  }
}
EOF
}

bap_stage_antigravity() {
    bap_add_file "GEMINI.md" < <(bap_rule_text antigravity "Antigravity")
    bap_add_file ".antigravity/mcp_config.json" < <(bap_mcp_json antigravity)
}

# ---------------------------------------------------------------------------
# Session teardown
# ---------------------------------------------------------------------------
bap_cleanup() {
    [ "${BAP_CLEANED:-0}" = "1" ] && return 0
    BAP_CLEANED=1
    local bapedge live
    bapedge="$(bap_find_bin bapedge 2>/dev/null || true)"
    if [ -n "$bapedge" ] && [ -n "${BAP_SERVER_URL:-}" ]; then
        "$bapedge" session-end --server "$BAP_SERVER_URL" --session-id "$BAP_SESSION_ID" >/dev/null 2>&1 || true
    fi
    if bap_lock; then
        rm -f "$BAP_LAUNCH_STATE/sessions/$$"
        live="$(bap_live_sessions)"
        if [ "$live" -eq 0 ]; then
            # Last session: restore originals, then sweep once more - but only after a clean restore.
            if bap_restore_manifest; then
                bap_repair_orphans
            fi
        else
            bap_log "[BAP] Session ended. $live other session(s) remain active in this workspace."
        fi
        bap_unlock
    fi
    [ -n "${BAP_STAGE_DIR:-}" ] && rm -rf "$BAP_STAGE_DIR"
    return 0
}

# bap_governed_run <agent-id> <display-name> -- <command> [args...]
# agent-id: claude-code | codex | antigravity
bap_governed_run() {
    local live rc=0
    BAP_AGENT_ID="$1"
    BAP_DISPLAY="$2"
    shift 2
    [ "${1:-}" = "--" ] && shift

    # Resolve the control-plane URL like the Windows launcher: flag/env, then bap-config.json.
    if [ -z "${BAP_SERVER_URL:-}" ]; then
        BAP_SERVER_URL="${BAP_CONTROL_PLANE_URL:-}"
    fi
    if [ -z "${BAP_SERVER_URL:-}" ]; then
        local cfg
        for cfg in "./bap-config.json" "$BAP_ENGINE_DIR/bap-config.json" "$BAP_ENGINE_DIR/../bap-config.json"; do
            if [ -f "$cfg" ]; then
                BAP_SERVER_URL="$(grep -o '"controlplane_url": *"[^"]*"' "$cfg" 2>/dev/null | head -n 1 | cut -d'"' -f4)"
                [ -n "$BAP_SERVER_URL" ] && break
            fi
        done
    fi
    BAP_SERVER_URL="${BAP_SERVER_URL%/}"
    if [ -n "$BAP_SERVER_URL" ]; then
        export BAP_SERVER_URL BAP_CONTROL_PLANE_URL="$BAP_SERVER_URL"
    fi

    BAP_WORKSPACE="$(pwd -P)"
    BAP_SESSION_ID="${BAP_SESSION_ID:-sess-$BAP_AGENT_ID-$$-$(date +%s)}"
    export BAP_SESSION_ID
    BAP_LAUNCH_STATE="${BAP_STATE_DIR:-$HOME/.bapstate}/launchers/$(bap_ws_hash "$BAP_WORKSPACE")"
    BAP_CLEANED=0
    BAP_STAGE_N=0
    BAP_PRIMARY=0
    BAP_STAGE_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t bapstage)" || BAP_STAGE_DIR=""
    if [ -z "$BAP_STAGE_DIR" ] || ! mkdir -p "$BAP_LAUNCH_STATE/sessions"; then
        bap_log "[BAP] Cannot create launcher state; refusing to start $BAP_DISPLAY ungoverned."
        return 1
    fi

    bap_lock || return 1

    live="$(bap_live_sessions)"
    if [ "$live" -eq 0 ]; then
        # STARTUP CLEANUP: nothing alive owns this workspace, so anything injected is a leftover.
        if [ -f "$BAP_LAUNCH_STATE/manifest" ]; then
            bap_log "[BAP] Stale session detected from a prior crash. Restoring original files..."
            bap_restore_manifest || true
        fi
        if [ ! -f "$BAP_LAUNCH_STATE/manifest" ]; then
            bap_repair_orphans
        fi
        case "$BAP_AGENT_ID" in
            claude-code|claude) bap_stage_claude ;;
            codex) bap_stage_codex ;;
            antigravity|agy) bap_stage_antigravity ;;
        esac
        if ! bap_inject_staged; then
            bap_unlock
            bap_log "[BAP] Injection failed; originals restored. Not starting $BAP_DISPLAY."
            rm -rf "$BAP_STAGE_DIR"
            return 1
        fi
        BAP_PRIMARY=1
    else
        bap_log "[BAP] Joined an active BAP-governed workspace ($live active session(s))."
    fi
    printf '%s\n%s\n' "$BAP_SESSION_ID" "$(bap_pid_start "$$")" > "$BAP_LAUNCH_STATE/sessions/$$"
    bap_unlock

    trap 'bap_cleanup' EXIT
    trap 'bap_cleanup; exit 130' INT
    trap 'bap_cleanup; exit 143' TERM
    trap 'bap_cleanup; exit 129' HUP

    BAP_EDGE_BIN="$(bap_find_bin bapedge 2>/dev/null || true)"
    export LTD_SOURCE="$BAP_AGENT_ID"
    if [ -n "$BAP_EDGE_BIN" ]; then
        if [ "$BAP_PRIMARY" -eq 1 ]; then
            # Re-attest pinned instruction files so they match the governed content.
            "$BAP_EDGE_BIN" pin scan >/dev/null 2>&1 || true
        fi
        # Enroll the session (also starts the detached watcher), as the Windows launcher does.
        if [ -n "${BAP_SERVER_URL:-}" ]; then
            "$BAP_EDGE_BIN" session-start --server "$BAP_SERVER_URL" --session-id "$BAP_SESSION_ID" --app-id "$BAP_AGENT_ID" ||
                bap_log "[BAP] WARNING: session-start failed; continuing under local zero-trust policy."
        fi
    else
        bap_log "[BAP] WARNING: bapedge not found; session is not enrolled with the control plane."
    fi

    "$@" || rc=$?

    bap_cleanup
    trap - EXIT INT TERM HUP
    return "$rc"
}
