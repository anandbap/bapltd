package authz

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func batchFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("USERPROFILE", root)
	t.Setenv("BAP_STATE_DIR", filepath.Join(root, "state"))
	t.Setenv("BAP_ZSP_AUTO_GRANTS", "1")
	return filepath.Join(root, "zsp"), root
}

func commandChecks(command, ws string) []ZSPActionCheck {
	return ResolveZSPCommandChecks(command, "git", "", "", "", ws)
}

func TestAutomaticBatchGrantReuseAndAtomicBurn(t *testing.T) {
	dir, ws := batchFixture(t)
	command := "git status --short --branch; git log --oneline -n 10; git status"
	checks := commandChecks(command, ws)
	if len(checks) != 3 {
		t.Fatalf("lost batch operations: %+v", checks)
	}
	_, grant, _, err := AuthorizeSessionCommandBatch(dir, "batch-session", "test", command, ws, checks, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if grant.CommandHash == "" || grant.PolicyHash == "" || grant.WorkspaceRoot != canonicalBatchWorkspace(ws) || grant.MaxUses != 1 || time.Until(grant.ExpiresAt) > 30*time.Second {
		t.Fatalf("unbounded automatic grant: %+v", grant)
	}
	_, again, _, err := AuthorizeSessionCommandBatch(dir, "batch-session", "test", command, ws, checks, false, nil)
	if err != nil || again.GrantID != grant.GrantID {
		t.Fatalf("check did not reuse grant: %v", err)
	}
	var successes atomic.Int32
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			_, _, _, err := VerifyOrConsumeSessionZSPChecks(dir, "batch-session", "test", checks, command, ws, true, nil)
			if err == nil {
				successes.Add(1)
			}
		}()
	}
	workers.Wait()
	if successes.Load() != 1 {
		t.Fatalf("single-use grant consumed %d times", successes.Load())
	}
}

func TestStatusGrantCannotAuthorizePushOrMixedBatch(t *testing.T) {
	dir, ws := batchFixture(t)
	grant, _, err := SubmitTaskEnvelope(dir, "scope-session", "test", "CODE_INSPECTION", "status only", "status", []string{"git:status"}, []string{"workspace://current"}, "", 1, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"git push origin main", "git status --short --branch; git push origin main"} {
		_, _, _, err := AuthorizeSessionCommandBatch(dir, "scope-session", "test", command, ws, commandChecks(command, ws), true, nil)
		if !errors.Is(err, ErrActionNotGranted) {
			t.Fatalf("%s escaped status scope: %v", command, err)
		}
	}
	_, remaining, _, err := VerifyOrConsumeSessionZSPChecks(dir, "scope-session", "test", commandChecks("git status", ws), "git status", ws, false, nil)
	if err != nil || remaining.GrantID != grant.GrantID || remaining.RemainingUses != 1 {
		t.Fatalf("rejected batch consumed authority: %v %+v", err, remaining)
	}
}

func TestAutomaticBatchBindingRejectsCommandWorkspaceAndTampering(t *testing.T) {
	dir, ws := batchFixture(t)
	command := "git status; git log --oneline -n 10"
	_, grant, _, err := AuthorizeSessionCommandBatch(dir, "binding-session", "test", command, ws, commandChecks(command, ws), false, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, attempt := range []struct{ command, ws string }{{"git status; git log --oneline -n 20", ws}, {command, t.TempDir()}} {
		_, _, _, err := VerifyOrConsumeSessionZSPChecks(dir, "binding-session", "test", commandChecks(attempt.command, attempt.ws), attempt.command, attempt.ws, true, nil)
		if err == nil {
			t.Fatal("batch binding was bypassed")
		}
	}
	_, _, minter, secret, err := EnsureSessionPrincipal(dir, "binding-session", "test")
	if err != nil {
		t.Fatal(err)
	}
	engine := NewZSPEngine(minter, secret)
	tampered := *grant
	tampered.CommandHash = batchCommandHash("git push origin main")
	if engine.LoadGrant(&tampered) == nil {
		t.Fatal("binding tampering was not detected")
	}
	if err := engine.LoadGrant(grant); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.ConsumeTaskGrant(grant.GrantID, "git:status", "workspace://current", "git push origin main", nil); err == nil {
		t.Fatal("direct consumption ignored command binding")
	}
}

func TestAutomaticBatchRejectsUnknownAndEffectChangingSyntax(t *testing.T) {
	_, ws := batchFixture(t)
	for _, command := range []string{
		"git status; git push origin main", "git status > report.txt", "git status & git log",
		"git log --output=report.txt", "git log --ext-diff", "git tag release", "git branch -D feature",
		"git -c core.pager=helper log", "git status $(helper)", "git status; unknown-tool", "git log 'unterminated",
		"git status\ngit push origin main", "git status; sed -e anything file",
	} {
		if _, ok := automaticBatchChecks(command, ws); ok {
			t.Errorf("unsafe automatic candidate: %s", command)
		}
	}
	for _, command := range []string{"git status; git log --oneline -n 10", "git status && git log --max-count=10", "git status; git status; git log --oneline"} {
		if _, ok := automaticBatchChecks(command, ws); !ok {
			t.Errorf("safe batch rejected: %s", command)
		}
	}
}

func TestAutomaticBatchReevaluatesSignedPolicy(t *testing.T) {
	dir, ws := batchFixture(t)
	command := "git status; git log --oneline -n 10"
	_, _, _, err := AuthorizeSessionCommandBatch(dir, "policy-session", "test", command, ws, commandChecks(command, ws), false, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, secret, err := EnsureSessionPrincipal(dir, "policy-session", "test")
	if err != nil {
		t.Fatal(err)
	}
	policy, _ := ParsePermissionPolicy(defaultPermissionPolicyJSON)
	policy.Rules = append(policy.Rules, PermissionRule{ID: "deny-log", Tier: TierDeny, Scope: "any", Match: []string{"git:log"}})
	raw, _ := json.Marshal(policy)
	path := filepath.Join(ws, "policy-fixture.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := SignPermissionPolicyFile(dir, secret, path); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := AuthorizeSessionCommandBatch(dir, "policy-session", "test", command, ws, commandChecks(command, ws), true, nil); err == nil {
		t.Fatal("stale grant bypassed policy change")
	}
}

func TestAutomaticBatchCanBeRestrictedWithoutDisablingZSP(t *testing.T) {
	dir, ws := batchFixture(t)
	t.Setenv("BAP_ZSP_AUTO_GRANTS", "0")
	command := "git status; git log --oneline -n 10"
	if _, _, _, err := AuthorizeSessionCommandBatch(dir, "explicit-session", "test", command, ws, commandChecks(command, ws), false, nil); err == nil {
		t.Fatal("explicit-only mode minted a grant")
	}
}

func TestAutomaticBatchHonorsApprovalTierAndMintCeiling(t *testing.T) {
	for _, tier := range []PermissionTier{TierApprove, TierDeny} {
		t.Run(string(tier), func(t *testing.T) {
			dir, ws := batchFixture(t)
			_, _, _, secret, err := EnsureSessionPrincipal(dir, "tier-session", "test")
			if err != nil {
				t.Fatal(err)
			}
			policy, _ := ParsePermissionPolicy(defaultPermissionPolicyJSON)
			policy.Rules = append(policy.Rules, PermissionRule{ID: "restrict-log", Tier: tier, Scope: "any", Match: []string{"git:log"}})
			raw, _ := json.Marshal(policy)
			path := filepath.Join(ws, "policy-fixture.json")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if err := SignPermissionPolicyFile(dir, secret, path); err != nil {
				t.Fatal(err)
			}
			command := "git status; git log --oneline -n 10"
			if _, _, _, err := AuthorizeSessionCommandBatch(dir, "tier-session", "test", command, ws, commandChecks(command, ws), false, nil); err == nil {
				t.Fatal("restricted batch received authority")
			}
			if countSessionGrants(dir, "tier-session") != 0 {
				t.Fatal("part of a rejected batch was granted")
			}
		})
	}
	dir, ws := batchFixture(t)
	_, _, _, secret, err := EnsureSessionPrincipal(dir, "cap-session", "test")
	if err != nil {
		t.Fatal(err)
	}
	policy, _ := ParsePermissionPolicy(defaultPermissionPolicyJSON)
	policy.Ceiling.MaxMintsPerSession = 1
	raw, _ := json.Marshal(policy)
	path := filepath.Join(ws, "policy-fixture.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := SignPermissionPolicyFile(dir, secret, path); err != nil {
		t.Fatal(err)
	}
	command := "git status; git log --oneline -n 10"
	if _, _, _, err := AuthorizeSessionCommandBatch(dir, "cap-session", "test", command, ws, commandChecks(command, ws), true, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := AuthorizeSessionCommandBatch(dir, "cap-session", "test", command, ws, commandChecks(command, ws), true, nil); !errors.Is(err, ErrMintCapExceeded) {
		t.Fatalf("automatic path bypassed mint ceiling: %v", err)
	}
}

func BenchmarkAutomaticBatchPrecheck(b *testing.B) {
	root := b.TempDir()
	b.Setenv("HOME", root)
	b.Setenv("USERPROFILE", root)
	b.Setenv("BAP_STATE_DIR", filepath.Join(root, "state"))
	b.Setenv("BAP_ZSP_AUTO_GRANTS", "1")
	dir := filepath.Join(root, "zsp")
	command := "git status --short --branch; git log --oneline -n 10; git status"
	checks := commandChecks(command, root)
	if _, _, _, err := AuthorizeSessionCommandBatch(dir, "bench-session", "test", command, root, checks, false, nil); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, _, err := AuthorizeSessionCommandBatch(dir, "bench-session", "test", command, root, checks, false, nil); err != nil {
			b.Fatal(err)
		}
	}
}
