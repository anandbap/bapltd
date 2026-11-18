#!/usr/bin/env bash
# End-to-end check of the POSIX launcher engine (BAP-1101) for macOS and Linux CI.
#
#   bash scripts/check_launchers_posix.sh
#
# Uses FAKE claude / codex / agy / interceptor binaries, so no real agent or control plane is needed.
# Verifies, for `bap claude`, `bap codex` and `bap agy` launchers:
#   - generated hooks/policy/MCP files are injected while the agent runs, originals are backed up
#   - the originals are restored (and generated files removed) when the agent exits
#   - startup cleanup after a crashed launcher (SIGKILL) restores the leftovers
#   - startup cleanup of orphaned backups with no manifest
#   - concurrent sessions in one workspace: only the last one restores
#   - a missing agent binary fails fast and injects nothing
# This file MUST keep LF line endings (see .gitattributes). Bash 3.2 compatible (macOS).
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LAUNCHERS="$ROOT/bap/launchers"
TMP="$(mktemp -d 2>/dev/null || mktemp -d -t bapposix)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
ok()   { PASS=$((PASS + 1)); printf '  [PASS] %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  [FAIL] %s\n' "$1"; }
check() { if eval "$2"; then ok "$1"; else fail "$1"; fi; }

echo "OS: $(uname -s) $(uname -m)   bash: ${BASH_VERSION:-unknown}"

# --- fixture: launchers + engine + fake binaries in one directory ---------------------------------
BIN="$TMP/bin"; FAKE="$TMP/fakebin"; HOME_DIR="$TMP/home"; STATE="$TMP/state"
mkdir -p "$BIN" "$FAKE" "$HOME_DIR" "$STATE"
for f in run_claude_bap.sh run_codex_cli_bap.sh run_antigravity_cli_bap.sh bap_posix_engine.sh; do
    cp "$LAUNCHERS/$f" "$BIN/$f"
done
printf '#!/bin/sh\nexit 0\n' > "$BIN/interceptor"; chmod +x "$BIN/interceptor"

for agent in claude codex agy; do
    cat > "$FAKE/$agent" <<'EOF'
#!/bin/sh
# Fake agent: records what it can see in the workspace, optionally crashes its launcher or waits.
{
  echo "ARGS:$*"
  for f in AGENTS.md CODEX.md GEMINI.md .codex/hooks.json .codex/mcp.json .antigravity/mcp_config.json .claude/settings.json; do
    if [ -f "$f" ]; then echo "HAS:$f:$(head -c 60 "$f" | tr '\n' ' ')"; fi
  done
  if [ -f .claude/settings.json ]; then
    grep -o 'interceptor' .claude/settings.json | head -n 1 | sed 's/^/INTERCEPTOR:/'
  fi
} > "${FAKE_OUT:-/dev/null}"
if [ -n "${FAKE_READY:-}" ]; then : > "$FAKE_READY"; fi
if [ -n "${FAKE_CRASH:-}" ]; then kill -9 "$PPID"; fi
if [ -n "${FAKE_SLEEP:-}" ]; then sleep "$FAKE_SLEEP"; fi
exit 0
EOF
    chmod +x "$FAKE/$agent"
done

# run_launcher <workspace> <launcher> [args...]   (extra env via the caller's environment)
run_launcher() {
    local ws="$1" launcher="$2"
    shift 2
    ( cd "$ws" && env HOME="$HOME_DIR" BAP_STATE_DIR="$STATE" PATH="$FAKE:/usr/bin:/bin" \
        bash "$BIN/$launcher" "$@" ) 2>&1
}

new_ws() { local d="$TMP/ws-$1"; rm -rf "$d"; mkdir -p "$d"; printf '%s' "$d"; }
no_backups() { [ -z "$(find "$1" -name '*.bap-backup-*' -not -path '*/.bap-recovery-archive/*' 2>/dev/null)" ]; }

# --- 1. codex ---------------------------------------------------------------------------------------
echo "1. codex: inject, run, restore"
WS="$(new_ws codex)"; printf 'ORIGINAL AGENTS\n' > "$WS/AGENTS.md"
OUT="$TMP/out-codex"
FAKE_OUT="$OUT" run_launcher "$WS" run_codex_cli_bap.sh --model x >"$TMP/log-codex" 2>&1
check "agent saw injected AGENTS.md"      "grep -q 'HAS:AGENTS.md:.*BAP Zero-Trust' '$OUT'"
check "agent saw injected CODEX.md"       "grep -q 'HAS:CODEX.md' '$OUT'"
check "agent saw injected .codex/hooks"   "grep -q 'HAS:.codex/hooks.json' '$OUT'"
check "agent args forwarded"              "grep -q 'ARGS:--model x' '$OUT'"
check "original AGENTS.md restored"       "[ \"\$(cat '$WS/AGENTS.md')\" = 'ORIGINAL AGENTS' ]"
check "generated CODEX.md removed"        "[ ! -e '$WS/CODEX.md' ]"
check ".codex directory removed"          "[ ! -e '$WS/.codex' ]"
check "no backup files left"              "no_backups '$WS'"

# --- 2. antigravity (agy) -------------------------------------------------------------------------
echo "2. agy: inject, run, restore"
WS="$(new_ws agy)"; printf 'ORIGINAL GEMINI\n' > "$WS/GEMINI.md"
OUT="$TMP/out-agy"
FAKE_OUT="$OUT" run_launcher "$WS" run_antigravity_cli_bap.sh >"$TMP/log-agy" 2>&1
check "agent saw injected GEMINI.md"      "grep -q 'HAS:GEMINI.md:.*BAP Zero-Trust' '$OUT'"
check "agent saw .antigravity/mcp_config" "grep -q 'HAS:.antigravity/mcp_config.json' '$OUT'"
check "original GEMINI.md restored"       "[ \"\$(cat '$WS/GEMINI.md')\" = 'ORIGINAL GEMINI' ]"
check ".antigravity directory removed"    "[ ! -e '$WS/.antigravity' ]"
check "no backup files left"              "no_backups '$WS'"

# --- 3. claude ------------------------------------------------------------------------------------
echo "3. claude: hooks injected, settings restored"
WS="$(new_ws claude)"; mkdir -p "$WS/.claude"; printf '{"mine": true}\n' > "$WS/.claude/settings.json"
OUT="$TMP/out-claude"
FAKE_OUT="$OUT" run_launcher "$WS" run_claude_bap.sh -p hello >"$TMP/log-claude" 2>&1
check "agent saw injected settings.json"  "grep -q 'HAS:.claude/settings.json:.*disableAllHooks' '$OUT'"
check "hooks point at the interceptor"    "grep -q 'INTERCEPTOR:interceptor' '$OUT'"
check "original settings.json restored"   "[ \"\$(cat '$WS/.claude/settings.json')\" = '{\"mine\": true}' ]"
check "no backup files left"              "no_backups '$WS'"

# --- 4. startup cleanup after a crashed (SIGKILLed) launcher ----------------------------------------
echo "4. startup cleanup after a crash"
WS="$(new_ws crash)"; printf 'ORIGINAL AGENTS\n' > "$WS/AGENTS.md"
FAKE_CRASH=1 run_launcher "$WS" run_codex_cli_bap.sh >"$TMP/log-crash1" 2>&1
check "crash left injected AGENTS.md (simulated SIGKILL)" "grep -q 'BAP Zero-Trust' '$WS/AGENTS.md'"
check "crash left a backup behind"        "! no_backups '$WS'"
FAKE_OUT="$TMP/out-crash2" run_launcher "$WS" run_codex_cli_bap.sh >"$TMP/log-crash2" 2>&1
check "next startup reported stale session" "grep -q 'Stale session' '$TMP/log-crash2'"
check "original AGENTS.md restored after relaunch" "[ \"\$(cat '$WS/AGENTS.md')\" = 'ORIGINAL AGENTS' ]"
check "no backups after relaunch"         "no_backups '$WS'"
check "no manifest left"                  "[ -z \"\$(find '$STATE' -name manifest 2>/dev/null)\" ]"

# --- 5. orphaned backup with no manifest ------------------------------------------------------------
echo "5. orphaned backup sweep at startup"
WS="$(new_ws orphan)"
printf '# BAP Zero-Trust Policy & Enterprise Governance for Antigravity\n' > "$WS/GEMINI.md"
printf 'ORIGINAL GEMINI\n' > "$WS/GEMINI.md.bap-backup-sess-old"
run_launcher "$WS" run_antigravity_cli_bap.sh >"$TMP/log-orphan" 2>&1
check "orphan recovered original GEMINI.md" "[ \"\$(cat '$WS/GEMINI.md')\" = 'ORIGINAL GEMINI' ]"
check "orphan backup removed"             "no_backups '$WS'"

# --- 6. concurrent sessions: only the last one restores ----------------------------------------------
echo "6. concurrent sessions in one workspace"
WS="$(new_ws concurrent)"; printf 'ORIGINAL AGENTS\n' > "$WS/AGENTS.md"
READY="$TMP/ready-a"; rm -f "$READY"
( FAKE_READY="$READY" FAKE_SLEEP=4 run_launcher "$WS" run_codex_cli_bap.sh >"$TMP/log-a" 2>&1 ) &
APID=$!
i=0; while [ ! -f "$READY" ] && [ "$i" -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
FAKE_OUT="$TMP/out-b" run_launcher "$WS" run_codex_cli_bap.sh >"$TMP/log-b" 2>&1
check "second session joined the first"   "grep -q 'Joined an active' '$TMP/log-b'"
check "files stay injected while first session runs" "grep -q 'BAP Zero-Trust' '$WS/AGENTS.md'"
wait "$APID"
check "original restored after the last session exits" "[ \"\$(cat '$WS/AGENTS.md')\" = 'ORIGINAL AGENTS' ]"
check "no backups after both sessions"    "no_backups '$WS'"

# --- 7. missing agent binary ----------------------------------------------------------------------------
echo "7. missing agent fails fast, injects nothing"
WS="$(new_ws missing)"; printf 'ORIGINAL AGENTS\n' > "$WS/AGENTS.md"
rm -f "$FAKE/codex"
if run_launcher "$WS" run_codex_cli_bap.sh >"$TMP/log-missing" 2>&1; then rc=0; else rc=$?; fi
check "non-zero exit when codex is missing" "[ '$rc' -ne 0 ]"
check "error names the missing CLI"       "grep -q 'not found' '$TMP/log-missing'"
check "workspace untouched"               "[ \"\$(cat '$WS/AGENTS.md')\" = 'ORIGINAL AGENTS' ] && [ ! -e '$WS/CODEX.md' ]"

echo
echo "Result: $PASS passed, $FAIL failed"
if [ "$FAIL" -ne 0 ]; then
    for l in "$TMP"/log-*; do [ -f "$l" ] && { echo "--- $(basename "$l")"; sed 's/^/    /' "$l"; }; done
fi
[ "$FAIL" -eq 0 ]
