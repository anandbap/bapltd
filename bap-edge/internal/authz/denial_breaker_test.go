package authz

import (
	"strings"
	"testing"
)

func TestBAP936_DenialBreakerCountsPerSessionAndKey(t *testing.T) {
	dir := t.TempDir()
	k := AuthorizeDenialKey([]string{"dev:python:exec"}, nil)
	for i := 1; i <= DenialHaltAfter; i++ {
		if got := RecordDenial(dir, "s1", k); got != i {
			t.Fatalf("count %d, want %d", got, i)
		}
	}
	if DenialCount(dir, "s1", k) != DenialHaltAfter {
		t.Fatal("DenialCount must read without incrementing")
	}
	// Other sessions and other asks are independent.
	if RecordDenial(dir, "s2", k) != 1 {
		t.Fatal("a different session has its own counter")
	}
	if RecordDenial(dir, "s1", AuthorizeDenialKey([]string{"git:push:write"}, nil)) != 1 {
		t.Fatal("a different request has its own counter")
	}
	// Key is order-insensitive and defaults the resource.
	if AuthorizeDenialKey([]string{"b", "a"}, []string{"workspace://current"}) != AuthorizeDenialKey([]string{"a", "b"}, nil) {
		t.Fatal("equivalent asks must share a key")
	}
	ClearDenial(dir, "s1", k)
	if DenialCount(dir, "s1", k) != 0 {
		t.Fatal("ClearDenial must reset the counter")
	}
}

func TestBAP936_RepeatedDenialMessagesAreUnmistakable(t *testing.T) {
	if n := RepeatedDenialNotice(3); !strings.Contains(n, "STOP") || !strings.Contains(n, "3 times") || !strings.Contains(n, "Do not retry") {
		t.Fatalf("notice: %s", n)
	}
	if h := HaltReason(5, "x"); !strings.Contains(h, "halted") || !strings.Contains(h, "bapedge zsp approvals") {
		t.Fatalf("halt: %s", h)
	}
	if !(DenialWarnAfter < DenialHaltAfter) {
		t.Fatal("the warning must come before the halt")
	}
}
