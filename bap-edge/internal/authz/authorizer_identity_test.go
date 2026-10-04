package authz

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAuthorizer_IdentityClaims(t *testing.T) {
	// Policy permits actions when principal.department == "Finance",
	// but forbids billing-export when principal.department != "Finance".
	testPolicy := `
permit (
    principal == Agent::"Local",
    action == Action::"Execute",
    resource == Command::"CLI"
) when {
    principal.department == "Finance" && ["billing-tool", "git", "ls"].contains(context.executable)
};

forbid (
    principal == Agent::"Local",
    action == Action::"Execute",
    resource == Command::"CLI"
) when {
    principal.department != "Finance"
};
`
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policy.cedar")
	if err := os.WriteFile(policyPath, []byte(testPolicy), 0644); err != nil {
		t.Fatalf("failed to write test policy: %v", err)
	}

	authz, err := NewAuthorizer(policyPath)
	if err != nil {
		t.Fatalf("failed to initialize authorizer: %v", err)
	}

	// 1. Finance User: Allowed
	authz.SetIdentity(PrincipalIdentity{
		UserEmail:  "alice@corp.internal",
		Department: "Finance",
		Groups:     []string{"finance-team"},
		AgentID:    "agent-alice-01",
		AuthMode:   "oidc",
	})

	allowed, reason, err := authz.Evaluate("billing-tool", "billing-tool --report", "")
	if err != nil {
		t.Fatalf("evaluation error: %v", err)
	}
	if !allowed {
		t.Errorf("expected Finance user to be allowed, got denied: %s", reason)
	}

	// 2. Engineering User: Denied by department forbid rule
	authz.SetIdentity(PrincipalIdentity{
		UserEmail:  "bob@corp.internal",
		Department: "Engineering",
		Groups:     []string{"dev-team"},
		AgentID:    "agent-bob-01",
		AuthMode:   "oidc",
	})

	allowed, reason, err = authz.Evaluate("billing-tool", "billing-tool --report", "")
	if err != nil {
		t.Fatalf("evaluation error: %v", err)
	}
	if allowed {
		t.Errorf("expected Engineering user to be denied for billing-tool, but was allowed")
	}
	if reason == "" {
		t.Errorf("expected denial reason for Engineering user")
	}
}
