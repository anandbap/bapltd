package main

import (
	"os"
	"testing"
)

// chain describes pid -> (parent, name) for pickAgentProcess.
type proc struct {
	parent int
	name   string
}

func pick(initial int, chain map[int]proc) int {
	return pickAgentProcess(initial,
		func(pid int) int { return chain[pid].parent },
		func(pid int) string { return chain[pid].name })
}

func TestPickAgentProcessSkipsShellsToClaudeCLI(t *testing.T) {
	// hook <- bash.exe <- bash.exe <- claude.exe (CLI) <- Claude.exe (desktop) <- explorer
	chain := map[int]proc{
		10: {20, "bash.exe"},
		20: {30, "bash.exe"},
		30: {40, "claude.exe"},
		40: {50, "Claude.exe"},
		50: {0, "explorer.exe"},
	}
	if got := pick(10, chain); got != 30 {
		t.Fatalf("got %d, want the per-session claude.exe (30), not the desktop app or a shell", got)
	}
}

func TestPickAgentProcessSkipsUnreadableNames(t *testing.T) {
	chain := map[int]proc{
		10: {20, "sh.exe"},
		20: {30, ""}, // access denied: name unavailable
		30: {40, "claude.exe"},
		40: {0, "explorer.exe"},
	}
	if got := pick(10, chain); got != 30 {
		t.Fatalf("got %d, want 30", got)
	}
}

func TestPickAgentProcessClimbsHelperWorkers(t *testing.T) {
	// No claude binary: node helpers climb to the topmost contiguous agent process.
	chain := map[int]proc{
		10: {20, "bash"},
		20: {30, "node.exe"},
		30: {40, "node.exe"},
		40: {50, "explorer.exe"},
		50: {0, "wininit.exe"},
	}
	if got := pick(10, chain); got != 30 {
		t.Fatalf("got %d, want topmost node (30)", got)
	}
}

func TestPickAgentProcessOnlyShellsReturnsInitial(t *testing.T) {
	chain := map[int]proc{10: {20, "bash.exe"}, 20: {0, "cmd.exe"}}
	if got := pick(10, chain); got != 10 {
		t.Fatalf("got %d, want initial pid so the caller can detect the shell", got)
	}
}

// Two sessions hosted by the same desktop app must resolve to their own claude.exe, so
// closing one session never ends, or is kept alive by, the other.
func TestPickAgentProcessSeparatesConcurrentSessions(t *testing.T) {
	chain := map[int]proc{
		// session A
		10: {20, "bash.exe"}, 20: {30, "claude.exe"},
		// session B
		11: {21, "bash.exe"}, 21: {31, "claude.exe"},
		// shared host
		30: {40, "Claude.exe"}, 31: {40, "Claude.exe"}, 40: {50, "explorer.exe"}, 50: {0, ""},
	}
	a, b := pick(10, chain), pick(11, chain)
	if a != 20 || b != 21 || a == b {
		t.Fatalf("sessions must map to their own claude.exe: got %d and %d, want 20 and 21", a, b)
	}
}

// TestLiveAncestry prints what the resolver finds for the real process tree. Opt in with
// BAP_LIVE_ANCESTRY=1; it is skipped otherwise because it depends on how tests were launched.
func TestLiveAncestry(t *testing.T) {
	if os.Getenv("BAP_LIVE_ANCESTRY") != "1" {
		t.Skip("set BAP_LIVE_ANCESTRY=1 to inspect the real process tree")
	}
	pid, info := resolveAgentProcess(os.Getppid())
	t.Logf("resolved pid=%d binary=%s app=%s", pid, info.BinaryPath, info.AppID)
}

func TestWatchPIDForNeverPinsShell(t *testing.T) {
	if got := watchPIDFor(10, CallerProcessInfo{BinaryName: "bash.exe"}); got != 0 {
		t.Fatalf("shell must not be watched, got %d", got)
	}
	if got := watchPIDFor(30, CallerProcessInfo{BinaryName: "claude.exe"}); got != 30 {
		t.Fatalf("got %d", got)
	}
}

func TestShellNamesNormalizeExe(t *testing.T) {
	for _, n := range []string{"bash.exe", "BASH.EXE", "sh.exe", "pwsh.exe", "cmd.exe", "zsh"} {
		if !isTransientShell(n) {
			t.Errorf("%q should be a transient shell", n)
		}
	}
	if isTransientShell("claude.exe") || !isClaudeBinary("Claude.exe") {
		t.Error("claude classification wrong")
	}
}
