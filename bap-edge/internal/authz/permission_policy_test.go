package authz

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustDefault(t *testing.T) *PermissionPolicy {
	t.Helper()
	p, err := DefaultPermissionPolicy()
	if err != nil {
		t.Fatalf("default policy must parse: %v", err)
	}
	return p
}

func TestPermissionPolicy_DefaultParsesAndNeverAllowsByDefault(t *testing.T) {
	p := mustDefault(t)
	if p.DefaultTier == TierAllow {
		t.Fatal("default tier must never be allow")
	}
	d := p.decide("some:unknown:action", "workspace://current")
	if d.Tier != TierApprove || d.RuleID != "default" {
		t.Fatalf("unknown action must hit default approve tier, got %+v", d)
	}
}

func TestPermissionPolicy_ParseRejectsUnsafeDocuments(t *testing.T) {
	good := string(defaultPermissionPolicyJSON)
	cases := map[string]string{
		"allow default":   strings.Replace(good, `"default_tier": "approve"`, `"default_tier": "allow"`, 1),
		"bad version":     strings.Replace(good, `"version": 1`, `"version": 2`, 1),
		"unknown field":   strings.Replace(good, `"version": 1,`, `"version": 1, "backdoor": true,`, 1),
		"bad tier":        strings.Replace(good, `"tier": "deny"`, `"tier": "maybe"`, 1),
		"bad pattern":     strings.Replace(good, `"credential:*"`, `"credential:[*"`, 1),
		"zero ceiling":    strings.Replace(good, `"max_mints_per_session": 100`, `"max_mints_per_session": 0`, 1),
		"wildcard output": strings.Replace(good, `"repo:*": ["repo:read"]`, `"repo:*": ["repo:*"]`, 1),
		"garbage":         "{not json",
	}
	for name, doc := range cases {
		if _, err := ParsePermissionPolicy([]byte(doc)); !errors.Is(err, ErrPermissionPolicyInvalid) {
			t.Errorf("%s: expected ErrPermissionPolicyInvalid, got %v", name, err)
		}
	}
}

func TestPermissionPolicy_BoundaryIsPrefixSafe(t *testing.T) {
	p := mustDefault(t)
	for res, want := range map[string]bool{
		"workspace://current":        true,
		"workspace://current/src":    true,
		"workspace://current/**":     true,
		"repo:local":                 true,
		"workspace://currentevil":    false,
		"system://local":             false,
		"file://C:/Users/x":          false,
		"":                           false,
		"WORKSPACE://CURRENT":        true,
		"workspace://current/../../": false, // traversal is never provably in-boundary
	} {
		if got := p.InBoundary(res); got != want {
			t.Errorf("InBoundary(%q)=%v want %v", res, got, want)
		}
	}
}

func TestPermissionPolicy_DenyBeatsAllowAndApprove(t *testing.T) {
	p, err := ParsePermissionPolicy([]byte(`{
	  "version":1,"default_tier":"approve","boundary_prefixes":["workspace://current"],
	  "ceiling":{"max_uses_per_grant":10,"max_ttl_seconds":60,"max_mints_per_session":5},
	  "rules":[
	    {"id":"a","tier":"allow","match":["x:*"]},
	    {"id":"b","tier":"approve","match":["x:y"]},
	    {"id":"c","tier":"deny","match":["x:y"]}
	  ]}`))
	if err != nil {
		t.Fatal(err)
	}
	if d := p.decide("x:y", "workspace://current"); d.Tier != TierDeny || d.RuleID != "c" {
		t.Fatalf("most restrictive rule must win, got %+v", d)
	}
	if d := p.decide("x:z", "workspace://current"); d.Tier != TierAllow {
		t.Fatalf("expected allow for x:z, got %+v", d)
	}
}

// The motivating case: a harmless GET to an allow-listed reference host must not stop the agent,
// while POST, uploads and unknown hosts still require a human.
func TestPermissionPolicy_DestinationAwareNetworkRule(t *testing.T) {
	doc := `{
	  "version":1,"default_tier":"approve","boundary_prefixes":["workspace://current"],
	  "ceiling":{"max_uses_per_grant":10,"max_ttl_seconds":60,"max_mints_per_session":5},
	  "rules":[
	    {"id":"net-default","tier":"approve","scope":"any","match":["http:*"]},
	    {"id":"net-reference-get","tier":"allow","match":["http:get"],"resource_match":["https://www.cnn.com/*","https://cnn.com*"]}
	  ]}`
	p, err := ParsePermissionPolicy([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	// Both rules match a GET to cnn.com; the more restrictive net-default would win, so a
	// destination allow rule must be expressed as a narrower deny-by-exception policy.
	if d := p.decide("http:get", "https://www.cnn.com/world"); d.Tier != TierApprove {
		t.Fatalf("restrictive-wins semantics expected approve here, got %+v", d)
	}

	// Correct shape: the broad network rule only covers non-allow-listed destinations.
	doc2 := `{
	  "version":1,"default_tier":"approve","boundary_prefixes":["workspace://current"],
	  "ceiling":{"max_uses_per_grant":10,"max_ttl_seconds":60,"max_mints_per_session":5},
	  "rules":[
	    {"id":"net-reference-get","tier":"allow","match":["http:get"],"resource_match":["https://www.cnn.com/*","https://cnn.com*"]},
	    {"id":"net-writes","tier":"approve","scope":"any","match":["http:post","http:put","http:patch","http:delete"]}
	  ]}`
	p2, err := ParsePermissionPolicy([]byte(doc2))
	if err != nil {
		t.Fatal(err)
	}
	if d := p2.decide("http:get", "https://www.cnn.com/world"); d.Tier != TierAllow {
		t.Errorf("GET to allow-listed host must be allowed, got %+v", d)
	}
	if d := p2.decide("http:get", "https://evil.example/x"); d.Tier != TierApprove {
		t.Errorf("GET to unknown host must need approval (default), got %+v", d)
	}
	if d := p2.decide("http:post", "https://www.cnn.com/x"); d.Tier != TierApprove {
		t.Errorf("POST must need approval even to an allow-listed host, got %+v", d)
	}
}

func TestPermissionPolicy_SignedOverrideLifecycle(t *testing.T) {
	dir := t.TempDir()
	secret := "test-pepper-0123456789-0123456789-abcdef"

	// No override -> embedded default.
	if p, err := LoadPermissionPolicy(dir, secret); err != nil || p == nil {
		t.Fatalf("expected default policy, got %v", err)
	}

	src := filepath.Join(t.TempDir(), "p.json")
	custom := strings.Replace(string(defaultPermissionPolicyJSON), `"max_mints_per_session": 100`, `"max_mints_per_session": 3`, 1)
	if err := os.WriteFile(src, []byte(custom), 0600); err != nil {
		t.Fatal(err)
	}
	if err := SignPermissionPolicyFile(dir, secret, src); err != nil {
		t.Fatalf("sign: %v", err)
	}
	p, err := LoadPermissionPolicy(dir, secret)
	if err != nil || p.Ceiling.MaxMintsPerSession != 3 {
		t.Fatalf("signed override must load, got %v %+v", err, p)
	}

	// Tampering with the file after signing is a hard error, not a silent fallback to default.
	target := filepath.Join(dir, permissionPolicyOverrideName)
	if err := os.WriteFile(target, []byte(strings.Replace(custom, `"max_mints_per_session": 3`, `"max_mints_per_session": 9999`, 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPermissionPolicy(dir, secret); !errors.Is(err, ErrPolicySignature) {
		t.Fatalf("tampered override must fail signature check, got %v", err)
	}

	// A wrong secret must not verify either; an unsigned override must be refused.
	_ = os.Remove(target + ".sig")
	if _, err := LoadPermissionPolicy(dir, secret); !errors.Is(err, ErrPolicySignature) {
		t.Fatalf("unsigned override must be refused, got %v", err)
	}
	if err := SignPermissionPolicyFile(dir, "", src); !errors.Is(err, ErrSigningSecretMissing) {
		t.Fatalf("signing without a secret must fail closed, got %v", err)
	}
}

func TestPermissionPolicy_OverrideDrivesMintCapEndToEnd(t *testing.T) {
	dir := t.TempDir()
	_, _, _, secret, err := EnsureSessionPrincipal(dir, "sess-ovr", "claude-code")
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "p.json")
	custom := strings.Replace(string(defaultPermissionPolicyJSON), `"max_mints_per_session": 100`, `"max_mints_per_session": 2`, 1)
	if err := os.WriteFile(src, []byte(custom), 0600); err != nil {
		t.Fatal(err)
	}
	if err := SignPermissionPolicyFile(dir, secret, src); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := mintAs(t, dir, "sess-ovr", []string{"git:status"}, []string{escalationWorkspace}); err != nil {
			t.Fatalf("mint %d should succeed: %v", i, err)
		}
	}
	if err := mintAs(t, dir, "sess-ovr", []string{"git:status"}, []string{escalationWorkspace}); !errors.Is(err, ErrMintCapExceeded) {
		t.Fatalf("third mint must hit the cap, got %v", err)
	}
	// A different session has its own budget.
	if err := mintAs(t, dir, "sess-other", []string{"git:status"}, []string{escalationWorkspace}); err != nil {
		t.Fatalf("other session must be unaffected: %v", err)
	}
}

func TestPermissionPolicy_ClampCeiling(t *testing.T) {
	p := mustDefault(t)
	u, ttl, clamped := p.ClampCeiling(5_000, 48*time.Hour)
	if !clamped || u != p.Ceiling.MaxUsesPerGrant || ttl != time.Duration(p.Ceiling.MaxTTLSeconds)*time.Second {
		t.Fatalf("unexpected clamp result: %d %s %v", u, ttl, clamped)
	}
	if _, _, clamped := p.ClampCeiling(1, time.Minute); clamped {
		t.Fatal("in-range request must not be clamped")
	}
}
