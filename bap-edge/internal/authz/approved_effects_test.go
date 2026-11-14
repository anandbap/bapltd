package authz

import (
	"os"
	"path/filepath"
	"testing"
)

func withApproved(t *testing.T, effects ...string) {
	t.Helper()
	old := ApprovedEffectsProvider
	ApprovedEffectsProvider = func() []string { return effects }
	t.Cleanup(func() { ApprovedEffectsProvider = old })
	t.Setenv("BAP_ZSP_STRICT_READS", "")
}

func TestApprovableEffectMatchesTheControlPlaneRule(t *testing.T) {
	yes := []string{"dev:go:test", "dev:go:build", "dev:test:exec", "fs:file:write", "fs:file:edit", "git:commit:write", "git:branch:write"}
	no := []string{"", "net:egress", "http:get", "http:post", "fs:file:delete", "git:push:write", "git:clean:delete", "dev:package:install",
		"db:query:read", "cli:python:exec", "secret:read", "credential:read", "../etc", "dev:go:test;rm -rf /", "DEV GO TEST", "fs:file:read", "git:status"}
	for _, a := range yes {
		if !ApprovableEffect(a) {
			t.Errorf("%q should be approvable", a)
		}
	}
	for _, a := range no {
		if ApprovableEffect(a) {
			t.Errorf("%q must never be approvable", a)
		}
	}
}

func TestApprovedCommandSkipsTheGrantOnlyForApprovedEffects(t *testing.T) {
	ws := t.TempDir()
	withApproved(t, "dev:go:test")

	exe, args := splitFirst("go test ./...")
	if !IsApprovedLocalCommand("go test ./...", exe, args, ws) {
		checks := ResolveZSPCommandChecks("go test ./...", exe, args, "", "", ws)
		t.Fatalf("an approved effect must run without a grant; checks=%+v", checks)
	}
	// A different effect on the same machine is still gated.
	for _, cmd := range []string{"go build ./...", "git commit -m x", "rm -rf build", "curl https://example.invalid", "go test ./... > out.txt"} {
		e, a := splitFirst(cmd)
		if IsApprovedLocalCommand(cmd, e, a, ws) {
			t.Errorf("%q is not approved and must still need a grant", cmd)
		}
	}
	// Approved effect combined with an unapproved one needs a grant for the whole command.
	if IsApprovedLocalCommand("go test ./... && rm -rf build", "go", "test ./... && rm -rf build", ws) {
		t.Error("a mixed command must need a grant covering every effect")
	}
}

func TestApprovalNeverCoversCredentialsRootsOrOutsideTheWorkspace(t *testing.T) {
	ws := t.TempDir()
	withApproved(t, "dev:go:test", "fs:file:write", "fs:file:edit")
	outside := t.TempDir()

	for _, tc := range []struct{ tool, target string }{
		{"Write", filepath.Join(ws, ".env")},
		{"Write", filepath.Join(ws, ".ssh", "id_rsa")},
		{"Edit", filepath.Join(ws, ".aws", "credentials")},
		{"Write", filepath.Join(outside, "x.txt")},
		{"Write", string(os.PathSeparator)},
	} {
		if IsApprovedToolCall(tc.tool, tc.target, ws) {
			t.Errorf("%s %s must never be covered by an approval", tc.tool, tc.target)
		}
	}
	if !IsApprovedToolCall("Write", filepath.Join(ws, "main.go"), ws) {
		t.Error("an approved write inside the workspace should not need a grant")
	}
	if IsApprovedToolCall("Read", filepath.Join(ws, "main.go"), ws) {
		t.Error("an unapproved tool class must not be covered")
	}
}

func TestApprovalsAreIgnoredWhenNotApprovableOrNotProvided(t *testing.T) {
	ws := t.TempDir()
	// A forged list that names a dangerous effect must be ignored by the edge itself.
	withApproved(t, "net:egress", "fs:file:delete", "dev:package:install")
	for _, cmd := range []string{"curl https://example.invalid", "rm -rf build", "npm install left-pad"} {
		e, a := splitFirst(cmd)
		if IsApprovedLocalCommand(cmd, e, a, ws) {
			t.Errorf("%q: the edge must refuse to honor a non-approvable effect", cmd)
		}
	}
	ApprovedEffectsProvider = nil
	if IsApprovedLocalCommand("go test ./...", "go", "test ./...", ws) || IsApprovedToolCall("Write", filepath.Join(ws, "a.go"), ws) {
		t.Error("with no signed approvals nothing is exempt")
	}
}

func TestStrictModeOverridesApprovals(t *testing.T) {
	ws := t.TempDir()
	withApproved(t, "dev:go:test")
	t.Setenv("BAP_ZSP_STRICT_READS", "1")
	if IsApprovedLocalCommand("go test ./...", "go", "test ./...", ws) {
		t.Fatal("BAP_ZSP_STRICT_READS=1 must require grants even for approved effects")
	}
}
