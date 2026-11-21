package bapsh

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestBapsh_ParseAndExtractCallCommands(t *testing.T) {
	script := `git status && python a11.py "arg with space" | grep test`
	f, err := Parse(script)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	calls := ExtractCallCommands(f)
	if len(calls) != 3 {
		t.Fatalf("expected 3 command calls, got %d: %+v", len(calls), calls)
	}

	if calls[0][0] != "git" || calls[0][1] != "status" {
		t.Errorf("call 0: expected [git status], got %v", calls[0])
	}
	if calls[1][0] != "python" || calls[1][1] != "a11.py" || calls[1][2] != "arg with space" {
		t.Errorf("call 1: expected [python a11.py 'arg with space'], got %v", calls[1])
	}
	if calls[2][0] != "grep" || calls[2][1] != "test" {
		t.Errorf("call 2: expected [grep test], got %v", calls[2])
	}
}

func TestBapsh_BlocksCredentialAccess(t *testing.T) {
	ctx := context.Background()
	var stdout, stderr bytes.Buffer

	opts := Options{
		SessionID:     "sess-test-bapsh",
		ClientType:    "claude-code",
		WorkspaceRoot: t.TempDir(),
		Stdout:        &stdout,
		Stderr:        &stderr,
	}

	err := Run(ctx, "cat .env", opts)
	if err == nil {
		t.Fatal("expected credential access to be blocked, got nil")
	}

	if !strings.Contains(err.Error(), "Access to credential file") {
		t.Fatalf("expected credential denial, got: %v", err)
	}
}

func TestBapsh_BlocksBAPAuthorityState(t *testing.T) {
	ctx := context.Background()
	var stdout, stderr bytes.Buffer

	opts := Options{
		SessionID:     "sess-test-bapsh",
		ClientType:    "claude-code",
		WorkspaceRoot: t.TempDir(),
		Stdout:        &stdout,
		Stderr:        &stderr,
	}

	err := Run(ctx, "cat .bapstate/zsp/pepper.key", opts)
	if err == nil {
		t.Fatal("expected authority state access to be blocked, got nil")
	}

	if !strings.Contains(err.Error(), "BAP authority/state path") {
		t.Fatalf("expected authority path violation, got: %v", err)
	}
}

func TestBapsh_ExecutesReadOnlyEcho(t *testing.T) {
	ctx := context.Background()
	var stdout, stderr bytes.Buffer

	opts := Options{
		SessionID:     "sess-test-bapsh",
		ClientType:    "claude-code",
		WorkspaceRoot: t.TempDir(),
		Stdout:        &stdout,
		Stderr:        &stderr,
	}

	err := Run(ctx, "echo 'hello from bapsh'", opts)
	if err != nil {
		t.Fatalf("echo should succeed, got: %v", err)
	}

	if !strings.Contains(stdout.String(), "hello from bapsh") {
		t.Fatalf("expected output 'hello from bapsh', got: %q", stdout.String())
	}
}

func TestBapsh_RequiresApprovalForHighRiskToolchain(t *testing.T) {
	ctx := context.Background()
	var stdout, stderr bytes.Buffer

	opts := Options{
		SessionID:     "sess-test-bapsh",
		ClientType:    "claude-code",
		WorkspaceRoot: t.TempDir(),
		Stdout:        &stdout,
		Stderr:        &stderr,
	}

	err := Run(ctx, "go version", opts)
	if err == nil {
		t.Fatal("expected high-risk toolchain without grant to require approval or grant, got nil")
	}

	if !strings.Contains(err.Error(), "HUMAN APPROVAL REQUIRED") && !strings.Contains(err.Error(), "ZeroStandingPrivilegeViolation") {
		t.Fatalf("expected approval requirement or ZSP violation, got: %v", err)
	}
}
