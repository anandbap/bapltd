package cmd

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"os"
	"strings"
)

// approvalCodeAlphabet avoids look-alike characters so a human can retype the code reliably.
const approvalCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func newApprovalCode() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	out := make([]byte, len(b))
	for i, v := range b {
		out[i] = approvalCodeAlphabet[int(v)%len(approvalCodeAlphabet)]
	}
	return string(out)
}

// humanApprovalChallenge is the BAP-926 replacement for the old "--oob-approve flag / y/N" gate.
//
// A flag or a piped "y" proves nothing, so approval now requires a real interactive terminal on
// stdin AND stderr plus a freshly generated one-time code that the human must read from the
// terminal and retype. Piped input, redirected input and scripts cannot answer it without reading
// the terminal. It never runs inside an agent broker (callers enforce BAP_IN_BROKER).
//
// Limit: an agent able to allocate its own pseudo-terminal and read it back could still answer.
// The planned hardening (BAP-926 follow-up) moves approval to a separate channel with a
// human-held signing key; this challenge removes the trivially scriptable paths today.
func humanApprovalChallenge(sessionID string, actions, resources []string, goal string) bool {
	if !isTerminal(os.Stdin) || !isTerminal(os.Stderr) {
		return false
	}
	code := newApprovalCode()
	fmt.Fprintf(os.Stderr, "\n[BAP HUMAN APPROVAL REQUIRED] Session %s is requesting elevated permissions.\n", sessionID)
	fmt.Fprintf(os.Stderr, "  Actions:   %v\n  Resources: %v\n  Goal:      %s\n", actions, resources, goal)
	fmt.Fprintf(os.Stderr, "To approve, type this one-time code exactly (anything else denies): %s\n> ", code)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	got := strings.ToUpper(strings.TrimSpace(line))
	return subtle.ConstantTimeCompare([]byte(got), []byte(code)) == 1
}
