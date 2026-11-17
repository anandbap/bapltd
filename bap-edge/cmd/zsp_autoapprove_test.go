package cmd

import "testing"

func TestAutoApproveOnIsHumanOnlyButOffAndStatusAreNot(t *testing.T) {
	for _, c := range []string{
		`bapedge zsp autoapprove on`,
		`bapedge.exe zsp autoapprove on --duration 2h`,
		`C:\Users\x\bin\bapedge.exe zsp autoapprove on`,
	} {
		if verb, ok := humanOnlyBAPCommand(c); !ok || verb != "zsp autoapprove on" {
			t.Fatalf("%q must be a human-only command, got (%q, %v)", c, verb, ok)
		}
	}
	for _, c := range []string{`bapedge zsp autoapprove off`, `bapedge zsp autoapprove status`, `bapedge zsp authorize --actions git:status`} {
		if verb, ok := humanOnlyBAPCommand(c); ok {
			t.Fatalf("%q should not be human-only, got %q", c, verb)
		}
	}
}
