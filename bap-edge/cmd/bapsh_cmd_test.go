package cmd

import (
	"strings"
	"testing"
)

func TestRunBapsh_Echo(t *testing.T) {
	err := RunBapsh([]string{"-c", "echo 'hello from bapsh command'"})
	if err != nil {
		t.Fatalf("expected RunBapsh to succeed, got: %v", err)
	}
}

func TestRunBapsh_NoCommandError(t *testing.T) {
	err := RunBapsh([]string{})
	if err == nil {
		t.Fatal("expected error when no command is provided, got nil")
	}
	if !strings.Contains(err.Error(), "no command provided to bapsh") {
		t.Fatalf("unexpected error message: %v", err)
	}
}
