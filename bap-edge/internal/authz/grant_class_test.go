package authz

import (
	"strings"
	"testing"
	"time"
)

// BAP-1102: single-use by default, bounded multi-use for specific classes of action.

func defaultPolicyForTest(t *testing.T) *PermissionPolicy {
	t.Helper()
	p, err := DefaultPermissionPolicy()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaultCeilingIsSingleUse(t *testing.T) {
	p := defaultPolicyForTest(t)
	uses, ttl, clamped, class := p.ClampCeilingFor([]string{"dev:go:test"}, []string{"workspace://current"}, 40, time.Hour)
	if uses != 1 || ttl != 300*time.Second || !clamped || class != DefaultGrantClass {
		t.Fatalf("default class = (%d, %v, clamped=%v, %q), want (1, 5m0s, true, %q)", uses, ttl, clamped, class, DefaultGrantClass)
	}
}

func TestWorkspaceEditClassAllowsBoundedMultiUse(t *testing.T) {
	p := defaultPolicyForTest(t)
	uses, ttl, clamped, class := p.ClampCeilingFor([]string{"fs:file:write"}, []string{"workspace://current"}, 40, 2*time.Hour)
	if uses != 25 || ttl != 600*time.Second || !clamped || class != "workspace_edit" {
		t.Fatalf("edit class = (%d, %v, clamped=%v, %q), want (25, 10m0s, true, workspace_edit)", uses, ttl, clamped, class)
	}
	if uses, _, clamped, _ := p.ClampCeilingFor([]string{"fs:file:edit"}, []string{"workspace://current"}, 10, 5*time.Minute); uses != 10 || clamped {
		t.Fatalf("an in-limit edit request must not be clamped, got uses=%d clamped=%v", uses, clamped)
	}
}

func TestEditClassNeverAppliesOutsideTheWorkspaceResource(t *testing.T) {
	p := defaultPolicyForTest(t)
	uses, _, _, class := p.ClampCeilingFor([]string{"fs:file:write"}, []string{"file://C:/Windows/system32/x"}, 25, 5*time.Minute)
	if uses != 1 || class == "workspace_edit" {
		t.Fatalf("an edit outside workspace://current must stay single-use, got uses=%d class=%q", uses, class)
	}
}

func TestMixedGrantTakesTheStrictestClass(t *testing.T) {
	p := defaultPolicyForTest(t)
	uses, ttl, _, class := p.ClampCeilingFor([]string{"fs:file:write", "git:push"}, []string{"workspace://current"}, 25, 10*time.Minute)
	if uses != 1 || ttl != 300*time.Second || class != DefaultGrantClass {
		t.Fatalf("edit+push = (%d, %v, %q), want single-use default", uses, ttl, class)
	}
	uses, _, _, class = p.ClampCeilingFor([]string{"fs:file:write", "git:status"}, []string{"workspace://current"}, 25, 5*time.Minute)
	if uses != 10 || class != "inspection" {
		t.Fatalf("edit+inspection = (%d, %q), want the stricter inspection limit (10)", uses, class)
	}
}

func TestLegacyPolicyWithoutClassesIsLabelledMultiUse(t *testing.T) {
	p, err := ParsePermissionPolicy([]byte(`{"version":1,"default_tier":"approve","boundary_prefixes":["workspace://current"],
		"ceiling":{"max_uses_per_grant":1000,"max_ttl_seconds":3600,"max_mints_per_session":100},
		"rules":[{"id":"r","tier":"allow","match":["fs:file:write"],"reason":"x"}]}`))
	if err != nil {
		t.Fatalf("an override without classes must still load: %v", err)
	}
	uses, _, _, class := p.ClampCeilingFor([]string{"fs:file:write"}, []string{"workspace://current"}, 500, time.Minute)
	if uses != 500 || class != "multi_use" {
		t.Fatalf("legacy policy = (%d, %q), want (500, multi_use)", uses, class)
	}
}

func TestInvalidCeilingClassIsRejected(t *testing.T) {
	_, err := ParsePermissionPolicy([]byte(`{"version":1,"default_tier":"approve","boundary_prefixes":["workspace://current"],
		"ceiling":{"max_uses_per_grant":1,"max_ttl_seconds":300,"max_mints_per_session":10,
		"classes":[{"id":"","match":["fs:file:write"],"max_uses_per_grant":5,"max_ttl_seconds":60}]},
		"rules":[{"id":"r","tier":"allow","match":["fs:file:write"],"reason":"x"}]}`))
	if err == nil {
		t.Fatal("a ceiling class without an id must be rejected")
	}
}

func TestMintedGrantCarriesClassAndRunsOutAtItsLimit(t *testing.T) {
	zspDir := t.TempDir()
	ws := t.TempDir()
	grant, _, err := SubmitTaskEnvelope(zspDir, "sess-class", "claude-code", "TASK_EXECUTION", "edit files", "edit files",
		[]string{"fs:file:write"}, []string{"workspace://current"}, "", 100, time.Hour)
	if err != nil || grant == nil {
		t.Fatalf("mint: %v", err)
	}
	if grant.GrantClass != "workspace_edit" || grant.MaxUses != 25 || !grant.NarrowingApplied {
		t.Fatalf("grant = class %q, max uses %d, narrowed=%v; want workspace_edit, 25, true", grant.GrantClass, grant.MaxUses, grant.NarrowingApplied)
	}
	if !strings.Contains(grant.NarrowingReason, "workspace_edit") {
		t.Fatalf("narrowing reason should name the class, got %q", grant.NarrowingReason)
	}
	if time.Until(grant.ExpiresAt) > 11*time.Minute {
		t.Fatalf("edit grant lives %v, want at most 10 minutes", time.Until(grant.ExpiresAt))
	}

	checks := []ZSPActionCheck{{Action: "fs:file:write", CanonicalResource: "workspace://current"}}
	for i := 0; i < 25; i++ {
		if _, _, _, err := VerifyOrConsumeSessionZSPChecks(zspDir, "sess-class", "claude-code", checks, "edit", ws, true, nil); err != nil {
			t.Fatalf("use %d of 25 failed: %v", i+1, err)
		}
	}
	if _, _, _, err := VerifyOrConsumeSessionZSPChecks(zspDir, "sess-class", "claude-code", checks, "edit", ws, true, nil); err == nil {
		t.Fatal("the 26th use must be refused")
	}
}

func TestNonEditGrantIsSingleUse(t *testing.T) {
	zspDir := t.TempDir()
	grant, _, err := SubmitTaskEnvelope(zspDir, "sess-single", "claude-code", "TASK_EXECUTION", "build", "build",
		[]string{"dev:go:build"}, []string{"workspace://current"}, "", 40, time.Hour)
	if err != nil || grant == nil {
		t.Fatalf("mint: %v", err)
	}
	if grant.MaxUses != 1 || grant.GrantClass != DefaultGrantClass {
		t.Fatalf("build grant = %d uses, class %q; want 1, %q", grant.MaxUses, grant.GrantClass, DefaultGrantClass)
	}
}
