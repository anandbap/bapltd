package authz

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func nativeCall(id, content string) NativeToolInvocation {
	digest, _ := NativeToolInputDigest(map[string]any{"file_path": "pilot_check.py", "content": content})
	return NativeToolInvocation{ID: id, InputDigest: digest}
}

func TestNativeSingleUseDuplicateCallbacksConsumeOnce(t *testing.T) {
	dir, ws := batchFixture(t)
	t.Setenv("BAP_ZSP_AUTO_GRANTS", "0")
	grant, _, err := SubmitTaskEnvelope(dir, "native", "test", "TASK_EXECUTION", "write pilot", "write pilot", []string{"fs:file:write"}, []string{"workspace://current"}, "", 1, time.Minute)
	if err != nil { t.Fatal(err) }
	var wg sync.WaitGroup
	proofs := make(chan string, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, g, proof, err := AuthorizeNativeToolInvocation(dir, "native", "test", "Write", "pilot_check.py", ws, nativeCall("one", "print(1)"))
			if err != nil { t.Error(err); return }
			if g.GrantID != grant.GrantID || g.RemainingUses != 0 { t.Errorf("wrong consumption: %+v", g) }
			proofs <- proof.ProofID
		}()
	}
	wg.Wait(); close(proofs)
	first := ""
	for proof := range proofs { if first == "" { first = proof }; if proof != first { t.Fatal("duplicate callback created a second proof") } }
	if first == "" { t.Fatal("no callback authorized") }
	if _, err := os.Stat(filepath.Join(ws, "pilot_check.py")); !os.IsNotExist(err) { t.Fatal("precheck executed a write") }
	if _, _, _, err := AuthorizeNativeToolInvocation(dir, "native", "test", "Write", "pilot_check.py", ws, nativeCall("two", "print(1)")); err == nil { t.Fatal("second invocation reused one-use grant") }
}

func TestNativeBindingAndCompletionFailClosed(t *testing.T) {
	for _, change := range []string{"content", "target", "tool", "completed", "expired", "revoked", "tampered", "pending", "policy"} {
		t.Run(change, func(t *testing.T) {
			dir, ws := batchFixture(t)
			call := nativeCall("id", "print(1)")
			_, g, _, err := AuthorizeNativeToolInvocation(dir, "native", "test", "Write", "pilot_check.py", ws, call)
			if err != nil { t.Fatal(err) }
			_, _, _, secret, _ := EnsureSessionPrincipal(dir, "native", "test")
			path := nativeInvocationPath(dir, "native", "id")
			tool, target := "Write", "pilot_check.py"
			switch change {
			case "content": call = nativeCall("id", "print(2)")
			case "target": target = "another.py"
			case "tool": tool = "Edit"
			case "completed":
				if err := CompleteNativeToolInvocation(dir, "native", "test", "id"); err != nil { t.Fatal(err) }
				if err := CompleteNativeToolInvocation(dir, "native", "test", "id"); err != nil { t.Fatal(err) }
			case "expired", "pending":
				d, _ := loadNativeDecision(path, secret)
				if change == "expired" { d.Until = time.Now().Add(-time.Second) } else { d.State = "pending" }
				if err := saveNativeDecision(path, d, secret); err != nil { t.Fatal(err) }
			case "revoked": if _, err := RevokeSessionZSPGrants(dir, "native", g.GrantID); err != nil { t.Fatal(err) }
			case "tampered": if err := os.WriteFile(path, []byte(`{"state":"accepted"}`), 0600); err != nil { t.Fatal(err) }
			case "policy":
				p, _ := ParsePermissionPolicy(defaultPermissionPolicyJSON)
				p.Rules = append(p.Rules, PermissionRule{ID: "new-rule", Tier: TierDeny, Scope: "any", Match: []string{"fs:file:write"}})
				raw, _ := json.Marshal(p)
				file := filepath.Join(ws, "policy-fixture.json")
				if err := os.WriteFile(file, raw, 0600); err != nil { t.Fatal(err) }
				if err := SignPermissionPolicyFile(dir, secret, file); err != nil { t.Fatal(err) }
			}
			if _, _, _, err := AuthorizeNativeToolInvocation(dir, "native", "test", tool, target, ws, call); err == nil { t.Fatal("changed or closed invocation authorized") }
		})
	}
}

func TestNativeWorkspaceBudgetCountsLogicalCalls(t *testing.T) {
	dir, ws := batchFixture(t)
	var grantID string
	for i := 0; i < 26; i++ {
		call := nativeCall(fmt.Sprint(i), "print(1)")
		for duplicate := 0; duplicate < 2; duplicate++ {
			_, grant, _, err := AuthorizeNativeToolInvocation(dir, "native", "test", "Write", "pilot_check.py", ws, call)
			if err != nil { t.Fatal(err) }
			if grant.MaxUses != 25 { t.Fatalf("workspace class ceiling changed: %+v", grant) }
			if i == 0 { grantID = grant.GrantID }
			if i < 25 && (grant.GrantID != grantID || grant.RemainingUses != 24-i) { t.Fatalf("callback burned extra use: %d %+v", i, grant) }
			if i == 25 && (grant.GrantID == grantID || grant.RemainingUses != 24) { t.Fatal("exhausted edit budget was not renewed") }
		}
		if err := CompleteNativeToolInvocation(dir, "native", "test", call.ID); err != nil { t.Fatal(err) }
	}
}

func TestNativeAutomaticGrantNeverWidensTargetsOrActions(t *testing.T) {
	for _, target := range []string{"../outside.py", ".env", "AGENTS.md", "CODEX.md", ".bap/pins.json"} {
		t.Run(target, func(t *testing.T) {
			dir, ws := batchFixture(t)
			if _, _, _, err := AuthorizeNativeToolInvocation(dir, "native", "test", "Write", target, ws, nativeCall("id", "x")); err == nil { t.Fatal("forbidden target auto-granted") }
		})
	}
	dir, ws := batchFixture(t)
	for _, tool := range []string{"Bash", "Delete", "unknown"} {
		if _, _, _, err := AuthorizeNativeToolInvocation(dir, "native", "test", tool, "pilot_check.py", ws, nativeCall(tool, "x")); err == nil { t.Fatalf("%s auto-granted", tool) }
	}
	if _, _, _, err := AuthorizeNativeToolInvocation(dir, "legacy", "test", "Write", "pilot_check.py", ws, NativeToolInvocation{}); err == nil { t.Fatal("missing ID auto-granted") }
}
