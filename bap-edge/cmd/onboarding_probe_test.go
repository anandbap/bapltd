package cmd

import (
	"strings"
	"testing"
	"time"
)

func TestProbeRequiresCorrelatedFreshOrderedCallbacksAndOwnedPolicy(t *testing.T) {
	now := time.Now().UTC()
	probe := onboardingProbe{ID: strings.Repeat("a", 32), StartedAt: now.Add(-time.Minute), ExpiresAt: now.Add(14 * time.Minute)}
	reference := strings.Repeat("b", 64)
	fixture := func() (map[string]any, map[string]any) {
		phases := map[string]any{}
		for i, event := range []string{"SessionStart", "UserPromptSubmit", "PreToolUse", "Stop"} {
			phases[event] = map[string]any{"status": "observed", "last_observed_at": probe.StartedAt.Add(time.Duration(i+1) * time.Second), "session_reference": reference, "probe_id": probe.ID}
		}
		return map[string]any{"claude_callbacks": phases}, map[string]any{"probe_id": probe.ID, "session_reference": reference, "prompt_record_observed": true, "policy_record_observed": true, "policy_decision": "allow", "restricted": false}
	}
	local, central := fixture()
	if got := evaluateProbe(probe, now, local, central); got["status"] != "reporting_probe_observed" || got["execution_success_verified"] != false {
		t.Fatal(got)
	}
	for _, change := range []func(map[string]any, map[string]any){
		func(l, c map[string]any) { c["prompt_record_observed"] = false }, func(l, c map[string]any) { c["policy_decision"] = "deny" }, func(l, c map[string]any) { c["restricted"] = true }, func(l, c map[string]any) { c["probe_id"] = strings.Repeat("c", 32) },
		func(l, c map[string]any) {
			l["claude_callbacks"].(map[string]any)["PreToolUse"].(map[string]any)["session_reference"] = "other"
		},
		func(l, c map[string]any) {
			l["claude_callbacks"].(map[string]any)["Stop"].(map[string]any)["last_observed_at"] = probe.StartedAt
		},
		func(l, c map[string]any) {
			l["claude_callbacks"].(map[string]any)["UserPromptSubmit"].(map[string]any)["probe_id"] = "other"
		},
	} {
		local, central = fixture()
		change(local, central)
		if result := evaluateProbe(probe, now, local, central); result["status"] == "reporting_probe_observed" {
			t.Fatal("unqualified evidence accepted", result)
		}
	}
	local, central = fixture()
	if result := evaluateProbe(probe, now.Add(time.Hour), local, central); result["status"] != "expired" {
		t.Fatal(result)
	}
}
