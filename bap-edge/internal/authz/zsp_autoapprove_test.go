package authz

import (
	"errors"
	"os"
	"testing"
	"time"
)

func TestAutoApproveDefaultsOffAndHonorsWindow(t *testing.T) {
	dir := t.TempDir()
	if on, _, _ := AutoApproveStatus(dir); on {
		t.Fatal("auto-approve must be OFF by default")
	}
	until, err := SetAutoApprove(dir, true, 2*time.Hour, "tester")
	if err != nil {
		t.Fatal(err)
	}
	if on, got, by := AutoApproveStatus(dir); !on || by != "tester" || !got.Equal(until) {
		t.Fatalf("status after on = (%v, %v, %q)", on, got, by)
	}
	if _, err := SetAutoApprove(dir, false, 0, ""); err != nil {
		t.Fatal(err)
	}
	if on, _, _ := AutoApproveStatus(dir); on {
		t.Fatal("auto-approve still on after off")
	}
}

func TestAutoApproveWindowIsCapped(t *testing.T) {
	dir := t.TempDir()
	until, err := SetAutoApprove(dir, true, 72*time.Hour, "tester")
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(until) > MaxAutoApproveWindow+time.Minute {
		t.Fatalf("window %v exceeds the %v cap", time.Until(until), MaxAutoApproveWindow)
	}
}

func TestAutoApproveTamperedOrExpiredRecordIsOff(t *testing.T) {
	dir := t.TempDir()
	if _, err := SetAutoApprove(dir, true, time.Hour, "tester"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(autoApprovePath(dir))
	// Editing any signed field of the file invalidates the signature.
	edited := replaceFirst(string(data), `"enabled_by": "tester"`, `"enabled_by": "attacker"`)
	if err := os.WriteFile(autoApprovePath(dir), []byte(edited), 0600); err != nil {
		t.Fatal(err)
	}
	if on, _, _ := AutoApproveStatus(dir); on {
		t.Fatal("tampered auto-approve record was accepted")
	}
}

func replaceFirst(s, old, repl string) string {
	for i := 0; i+len(old) <= len(s); i++ {
		if s[i:i+len(old)] == old {
			return s[:i] + repl + s[i+len(old):]
		}
	}
	return s
}

func TestAutoApproveSatisfiesApproveTierButNotGovernance(t *testing.T) {
	prev := AutoApproveActive
	t.Cleanup(func() { AutoApproveActive = prev })
	zspDir := t.TempDir()
	const sess = "sess-autoapprove"
	ask := func(delegation string, actions ...string) error {
		_, _, err := SubmitTaskEnvelopeWithDelegation(zspDir, sess, "claude-code", "TASK_EXECUTION", "build", "build",
			actions, []string{"workspace://current"}, "", delegation, 1, 0)
		return err
	}

	// Baseline: an approve-tier action is refused for a plain prompt delegation.
	AutoApproveActive = nil
	if err := ask("human_interactive_prompt", "dev:go:-C"); !errors.Is(err, ErrHighRiskApprovalRequired) {
		t.Skipf("default policy does not put dev:go:-C in the approve tier here (%v); adjust the action", err)
	}

	// Auto-approve delegation without an open window is still refused (stale envelope).
	AutoApproveActive = func() bool { return false }
	if err := ask(DelegationAutoApprove, "dev:go:-C"); !errors.Is(err, ErrHighRiskApprovalRequired) {
		t.Fatalf("auto_approve with the window closed must be refused, got %v", err)
	}

	// With the window open the approve-tier request is granted.
	AutoApproveActive = func() bool { return true }
	if err := ask(DelegationAutoApprove, "dev:go:-C"); err != nil {
		t.Fatalf("auto_approve with the window open should grant an approve-tier action: %v", err)
	}

	// Governance escalations are never auto-approved.
	if err := ask(DelegationAutoApprove, "policy:edit"); !errors.Is(err, ErrHighRiskApprovalRequired) {
		t.Fatalf("policy:edit must still need a real out-of-band human approval, got %v", err)
	}
}
