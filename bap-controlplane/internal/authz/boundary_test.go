package authz

import (
	"testing"
)

func TestDecisionPlaneBoundary_CheckTargetActionExecution(t *testing.T) {
	b := NewDecisionPlaneBoundary()

	// Direct execution by central policy service must be rejected
	err := b.CheckTargetActionExecution("git:push:write")
	if err == nil {
		t.Fatalf("Expected error when central policy service attempts target execution, got nil")
	}

	// Secret retrieval by central policy service must be rejected
	err = b.CheckSecretRetrieval("github_api_token")
	if err == nil {
		t.Fatalf("Expected error when central policy service attempts secret retrieval, got nil")
	}
}
