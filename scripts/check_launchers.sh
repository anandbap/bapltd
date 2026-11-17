#!/usr/bin/env bash
# BAP launcher self-check for POSIX shells: macOS (bash/zsh), Ubuntu/Linux, WSL, Git Bash.
#
#   bash scripts/check_launchers.sh
#
# It never starts a real agent and never contacts a control plane. Each launcher is copied
# into a temp dir and run against fake claude / agy / codex binaries that just print their
# arguments, which proves BAP's own flags are stripped and the server reaches the
# environment. This file MUST keep LF line endings (see .gitattributes).
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LAUNCHERS="$ROOT/bap/launchers"
TMP="$(mktemp -d 2>/dev/null || mktemp -d -t bapcheck)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
ok()   { PASS=$((PASS + 1)); printf '  [PASS] %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  [FAIL] %s\n' "$1"; }

echo "OS: $(uname -s) $(uname -m)   bash: ${BASH_VERSION:-unknown}"
echo

# 1. No CRLF in any shell launcher (the macOS/Linux "bash\r" failure).
echo "1. Line endings"
for f in "$LAUNCHERS"/*.sh "$ROOT"/bap/run_claude_bap.sh; do
    [ -f "$f" ] || continue
    if grep -q $'\r' "$f"; then fail "CRLF found in ${f#"$ROOT"/}"; else ok "LF  ${f#"$ROOT"/}"; fi
done

# 2. Syntax check.
echo "2. bash -n"
for f in "$LAUNCHERS"/*.sh "$ROOT"/bap/run_claude_bap.sh; do
    [ -f "$f" ] || continue
    if bash -n "$f" 2>"$TMP/err"; then ok "syntax ${f##*/}"; else fail "syntax ${f##*/}: $(cat "$TMP/err")"; fi
done

# 3. Behaviour with fake agents. PATH is restricted so a real bapedge/claude cannot interfere.
mkdir -p "$TMP/fakebin" "$TMP/work"
for agent in claude agy codex; do
    cat > "$TMP/fakebin/$agent" <<'EOF'
#!/bin/sh
echo "ARGS:$*"
echo "SERVER:${BAP_SERVER_URL:-}"
EOF
    chmod +x "$TMP/fakebin/$agent"
done
SAFE_PATH="$TMP/fakebin:/usr/bin:/bin"

run_case() {   # run_case <script> <expected-args> <expected-server> <launcher args...>
    local script="$1" want_args="$2" want_server="$3"
    shift 3
    mkdir -p "$TMP/run"
    cp "$LAUNCHERS/$script" "$TMP/run/$script"        # copy so no sibling .ps1 / bapedge is found
    local out
    out="$(cd "$TMP/work" && env -i HOME="$TMP/work" PATH="$SAFE_PATH" bash "$TMP/run/$script" "$@" 2>&1)"
    if printf '%s\n' "$out" | grep -qx "ARGS:$want_args" \
        && { [ -z "$want_server" ] || printf '%s\n' "$out" | grep -qx "SERVER:$want_server"; }; then
        ok "$script $*"
    else
        fail "$script $*"
        printf '%s\n' "$out" | sed 's/^/        /'
    fi
}

echo "3. Argument stripping / server hand-off"
run_case run_claude_cli_bap.sh       "--model sonnet" "http://x:1" --server=http://x:1 --model sonnet
run_case run_claude_cli_bap.sh       "--model sonnet" "http://x:1" --server http://x:1 --model sonnet
run_case run_claude_cli_bap.sh       ""               ""
run_case run_codex_cli_bap.sh        "exec hi"        "http://x:1" --server=http://x:1 exec hi
run_case run_antigravity_cli_bap.sh  "--foo"          "http://x:1" --server=http://x:1 --foo
run_case run_claude_bap.sh           "--model sonnet" "http://x:1" --server=http://x:1 --model sonnet
run_case run_claude_bap.sh           "-p hello"       "http://x:1" http://x:1 -p hello

echo
echo "Result: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
