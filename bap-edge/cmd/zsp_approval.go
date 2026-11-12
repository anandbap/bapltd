package cmd

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"strings"

	"bap-edge/internal/authz"
)

// humanOnlyBAPCommand reports whether command invokes a BAP command that only a human operator may run:
// trust, untrust, dev-override, and zsp policy-sign. This is the explicit agent gate (BAP-934); the
// commands themselves only check BAP_IN_BROKER so a developer is never locked out.
func humanOnlyBAPCommand(command string) (string, bool) {
	toks := strings.Fields(strings.ToLower(strings.ReplaceAll(command, "\"", " ")))
	isBAP := func(t string) bool {
		t = strings.ReplaceAll(t, "\\", "/")
		base := t[strings.LastIndex(t, "/")+1:]
		return base == "bap" || base == "bapedge" || base == "bap.exe" || base == "bapedge.exe"
	}
	for i := 0; i+1 < len(toks); i++ {
		if !isBAP(toks[i]) {
			continue
		}
		switch toks[i+1] {
		case "trust", "untrust", "dev-override":
			return toks[i+1], true
		case "zsp":
			if i+2 < len(toks) && toks[i+2] == "policy-sign" {
				return "zsp policy-sign", true
			}
		}
	}
	return "", false
}

// zspDenialConcept maps an authorize refusal to the ZSP concept recorded in the audit ledger.
func zspDenialConcept(err error) string {
	switch {
	case errors.Is(err, authz.ErrHighRiskApprovalRequired):
		return "HIGH_RISK_OOB_GATE"
	case errors.Is(err, authz.ErrActionDenied):
		return "ZSP_HARD_DENY"
	case errors.Is(err, authz.ErrWildcardNotPermitted):
		return "ZSP_WILDCARD_REJECTED"
	case errors.Is(err, authz.ErrMintCapExceeded):
		return "ZSP_MINT_CAP"
	case errors.Is(err, authz.ErrPolicySignature), errors.Is(err, authz.ErrPermissionPolicyInvalid), errors.Is(err, authz.ErrSigningSecretMissing):
		return "ZSP_POLICY_ERROR"
	}
	return ""
}

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
