package cmd

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClaudeSelectionReusesManagedAndPreservesUserHooks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "managed.json")
	original := []byte(`{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"bapedge plugin adapter"},{"type":"command","command":"user-audit"}]}]}}`)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	regs, only, err := inspectClaudeHooks([]string{path}, map[string]bool{path: true})
	if err != nil {
		t.Fatal(err)
	}
	overlay, err := selectClaudeHooks(regs, only, "C:/BAP/bapedge.exe")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := overlay.Hooks["PreToolUse"]; ok {
		t.Fatal("managed hook duplicated")
	}
	if len(overlay.Hooks) != len(claudeEvents)-1 {
		t.Fatal(overlay)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(original) {
		t.Fatal("source settings modified")
	}
	for _, group := range overlay.Hooks {
		if len(group) != 1 || len(group[0].Hooks) != 1 {
			t.Fatal("duplicate callback")
		}
	}
	// Repeating selection is idempotent and does not install into source files.
	next, err := selectClaudeHooks(regs, only, "C:/BAP/bapedge.exe")
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(overlay)
	b, _ := json.Marshal(next)
	if string(a) != string(b) {
		t.Fatal("non-deterministic selection")
	}
}

func TestClaudeStartupReapsDeadOwnersAndRetainsConcurrentLiveOwners(t *testing.T) {
	workspace := t.TempDir()
	root := filepath.Join(workspace, ".bap", "claude-launches")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	stale, owner := makeClaudeOwner(t, workspace, root)
	owner.PID = 2147483000
	owner.Birth = "terminated-process"
	if err := writeClaudeOwner(stale, owner); err != nil {
		t.Fatal(err)
	}
	live, liveOwner := makeClaudeOwner(t, workspace, root)
	liveOwner.PID = os.Getpid()
	liveOwner.Birth = processBirth(os.Getpid())
	if liveOwner.Birth == "" {
		t.Fatal("process birth identity unavailable")
	}
	if err := writeClaudeOwner(live, liveOwner); err != nil {
		t.Fatal(err)
	}
	if err := reconcileClaudeOwners(root, workspace); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("stale launch not reaped", err)
	}
	if _, err := os.Stat(live); err != nil {
		t.Fatal("live concurrent launch deleted", err)
	}
	// A killed launcher must not reap settings still in use by its live child.
	orphan, orphanOwner := makeClaudeOwner(t, workspace, root)
	orphanOwner.PID = 2147483000
	orphanOwner.Birth = "terminated-launcher"
	orphanOwner.ChildPID = os.Getpid()
	orphanOwner.ChildBirth = processBirth(os.Getpid())
	if err := writeClaudeOwner(orphan, orphanOwner); err != nil {
		t.Fatal(err)
	}
	if err := reconcileClaudeOwners(root, workspace); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(orphan); err != nil {
		t.Fatal("live child settings reaped", err)
	}
}

func TestClaudeLifecycleLockSerializesInstallationNotWholeSession(t *testing.T) {
	workspace := t.TempDir()
	if err := os.Mkdir(filepath.Join(workspace, ".bap"), 0700); err != nil {
		t.Fatal(err)
	}
	release, err := acquireClaudeLifecycleLock(workspace)
	if err != nil {
		t.Fatal(err)
	}
	other, err := acquireClaudeLifecycleLock(workspace)
	if err == nil {
		other()
		release()
		t.Fatal("concurrent installation lock granted")
	}
	release()
	other, err = acquireClaudeLifecycleLock(workspace)
	if err != nil {
		t.Fatal("lock not released", err)
	}
	other()
}

func TestClaudeInterruptProcessFixture(t *testing.T) {
	if os.Getenv("BAP_CLAUDE_SLEEPER_TEST") == "1" {
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	ctx, cancel := context.WithCancel(context.Background())
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestClaudeInterruptProcessFixture$")
	child.Env = append(os.Environ(), "BAP_CLAUDE_SLEEPER_TEST=1")
	if err := child.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	workspace := t.TempDir()
	dir, owner := makeClaudeOwner(t, workspace, workspace)
	owner.PID = os.Getpid()
	owner.Birth = processBirth(os.Getpid())
	owner.ChildPID = child.Process.Pid
	owner.ChildBirth = processBirth(child.Process.Pid)
	if err := writeClaudeOwner(dir, owner); err != nil {
		cancel()
		_ = child.Wait()
		t.Fatal(err)
	}
	cancel()
	if err := child.Wait(); err == nil {
		t.Fatal("canceled fixture process did not stop")
	}
	if err := cleanupClaudeOwner(dir, workspace, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("interruption cleanup left artifacts", err)
	}
}

func TestClaudeSelectionRejectsDuplicatesAndPartialCoverage(t *testing.T) {
	base := claudeRegistration{Source: "user.json", Event: "PreToolUse", Matcher: "*", Command: "bapedge plugin adapter"}
	if _, err := selectClaudeHooks([]claudeRegistration{base, base}, false, "bapedge"); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatal(err)
	}
	base.Matcher = "Bash"
	if _, err := selectClaudeHooks([]claudeRegistration{base}, false, "bapedge"); err == nil {
		t.Fatal("partial matcher accepted")
	}
	if _, err := selectClaudeHooks(nil, true, "bapedge"); err == nil {
		t.Fatal("managed-only policy bypassed")
	}
}

func makeClaudeOwner(t *testing.T, workspace, root string) (string, claudeOwner) {
	t.Helper()
	dir, err := os.MkdirTemp(root, "launch-")
	if err != nil {
		t.Fatal(err)
	}
	settings := []byte(`{"hooks":{}}`)
	owner := claudeOwner{Version: 1, Workspace: workspace, Session: "test", PID: 123, Birth: "birth", Fingerprint: claudeFingerprint(settings), State: "running"}
	if err := writeClaudeOwner(dir, owner); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), settings, 0600); err != nil {
		t.Fatal(err)
	}
	return dir, owner
}

func TestClaudeCleanupPreservesConcurrentSessionsAndUserEdits(t *testing.T) {
	root := t.TempDir()
	a, owner := makeClaudeOwner(t, root, root)
	b, _ := makeClaudeOwner(t, root, root)
	if err := cleanupClaudeOwner(a, root, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(b); err != nil {
		t.Fatal("other session removed", err)
	}
	a, owner = makeClaudeOwner(t, root, root)
	if err := os.WriteFile(filepath.Join(a, "settings.json"), []byte("edited"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := cleanupClaudeOwner(a, root, owner); err == nil {
		t.Fatal("user edit deleted")
	}
	if b, err := os.ReadFile(filepath.Join(a, "settings.json")); err != nil || string(b) != "edited" {
		t.Fatal("edit lost")
	}
	owner.Workspace = "other"
	if err := cleanupClaudeOwner(a, root, owner); err == nil {
		t.Fatal("foreign workspace accepted")
	}
}

func TestClaudeOwnerLivenessAndPIDReuse(t *testing.T) {
	procs := []agentProcess{{PID: 123}}
	for _, tc := range []struct {
		birth       string
		procs       []agentProcess
		current     string
		live, known bool
	}{
		{"old", procs, "old", true, true}, {"old", procs, "new", false, true}, {"old", nil, "", false, true}, {"", procs, "", false, false}, {"old", procs, "", false, false},
	} {
		live, known := claudeOwnerLive(123, tc.birth, tc.procs, func(int) string { return tc.current })
		if live != tc.live || known != tc.known {
			t.Fatalf("%+v: %v %v", tc, live, known)
		}
	}
}

func TestClaudeRecoveryRejectsUnknownArtifacts(t *testing.T) {
	root := t.TempDir()
	dir, owner := makeClaudeOwner(t, root, root)
	if err := os.WriteFile(filepath.Join(dir, "user.txt"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := cleanupClaudeOwner(dir, root, owner); err == nil {
		t.Fatal("unknown artifact removed")
	}
	if _, err := os.Stat(filepath.Join(dir, "settings.json")); err != nil {
		t.Fatal("partial cleanup before validation", err)
	}
}
