package main

import (
	"reflect"
	"testing"
)

func TestClassifyIntentMixedBugAndDatabaseChange(t *testing.T) {
	got := classifyIntent("Fix the login bug and update the database schema")
	if got.Primary != "BUG_FIX" {
		t.Fatalf("primary = %q, want BUG_FIX: %#v", got.Primary, got)
	}
	if !reflect.DeepEqual(got.Secondary, []string{"DATABASE_CHANGE"}) {
		t.Fatalf("secondary = %#v, want DATABASE_CHANGE", got.Secondary)
	}
	if !reflect.DeepEqual(got.Tags, []string{"DATABASE"}) {
		t.Fatalf("tags = %#v, want DATABASE", got.Tags)
	}
	if got.ClassifierVersion != intentClassifierVersion || got.Confidence <= 0 {
		t.Fatalf("classification metadata incomplete: %#v", got)
	}
}

func TestClassifyIntentUsesUnknownInsteadOfGuessing(t *testing.T) {
	got := classifyIntent("Please handle BAP-412")
	if got.Primary != "UNKNOWN" || got.Confidence != 0 {
		t.Fatalf("ambiguous prompt was guessed: %#v", got)
	}
}

func TestClassifyIntentCommonCIOWorkCategories(t *testing.T) {
	for _, tc := range []struct {
		prompt string
		want   string
	}{
		{"Enhance the portfolio UI", "FEATURE_ENHANCEMENT"},
		{"Write documentation for the new API", "DOCUMENTATION"},
		{"Upgrade the framework dependency", "MIGRATION"},
		{"Deploy the service to production", "DEPLOYMENT_RELEASE"},
		{"Investigate the payment timeout", "INVESTIGATION"},
	} {
		if got := classifyIntent(tc.prompt); got.Primary != tc.want {
			t.Errorf("classifyIntent(%q) = %s, want %s (%#v)", tc.prompt, got.Primary, tc.want, got)
		}
	}
}

func TestClassifyIntentDeterministic(t *testing.T) {
	prompt := "Enhance the UI and add tests for the dashboard"
	want := classifyIntent(prompt)
	for i := 0; i < 100; i++ {
		if got := classifyIntent(prompt); !reflect.DeepEqual(got, want) {
			t.Fatalf("classification changed between identical inputs: want %#v, got %#v", want, got)
		}
	}
}

// The local override only applies when the administrator delegated the choice to users.
func TestPromptCaptureEnvironmentOverride(t *testing.T) {
	setAdminPromptMode(t, promptCaptureUserControlled)
	t.Setenv("BAP_CAPTURE_USER_PROMPT", "false")
	if shouldCaptureUserPrompt() {
		t.Fatal("prompt capture remained enabled after explicit endpoint override")
	}
}

func BenchmarkClassifyIntent(b *testing.B) {
	prompt := "Fix the login bug, update the database schema, and add regression tests to the customer UI"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = classifyIntent(prompt)
	}
}
