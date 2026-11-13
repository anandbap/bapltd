package cmd

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"bap-edge/internal/authz"
	"bap-edge/pkg/types"
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
			if i+2 < len(toks) && (toks[i+2] == "policy-sign" || toks[i+2] == "approve" || toks[i+2] == "deny") {
				return "zsp " + toks[i+2], true
			}
		}
	}
	return "", false
}

const approvalPromptTimeout = 120 * time.Second

var (
	authorizeActionsFlagRe   = regexp.MustCompile(`--actions[ =]+"?([^"\s]+)`)
	authorizeResourcesFlagRe = regexp.MustCompile(`--resources[ =]+"?([^"\s]+)`)
)

// denialBreaker is the per-refusal anti-spin state (BAP-936).
type denialBreaker struct {
	count int
	halt  bool
	stop  string
}

func newDenialBreaker(sessionID, key, what string) denialBreaker {
	n := authz.RecordDenial(authz.ResolveZSPDir(), sessionID, key)
	b := denialBreaker{count: n}
	if n >= authz.DenialHaltAfter {
		b.halt = true
		b.stop = authz.HaltReason(n, what)
	}
	return b
}

// wrap prepends the unmistakable STOP notice once the same refusal keeps repeating.
func (b denialBreaker) wrap(guidance string) string {
	if b.count >= authz.DenialWarnAfter {
		return authz.RepeatedDenialNotice(b.count) + guidance
	}
	return guidance
}

// repeatedAuthorizeResponse halts an agent that keeps re-submitting an authorize ask BAP has already refused
// repeatedly, instead of letting it spin. Reads the counter the CLI maintains; never increments it.
func repeatedAuthorizeResponse(sessionID, command string) (types.ExecResponse, bool) {
	if !strings.Contains(strings.ToLower(command), "zsp authorize") {
		return types.ExecResponse{}, false
	}
	am := authorizeActionsFlagRe.FindStringSubmatch(command)
	if am == nil {
		return types.ExecResponse{}, false
	}
	actions := strings.Split(am[1], ",")
	var resources []string
	if rm := authorizeResourcesFlagRe.FindStringSubmatch(command); rm != nil {
		resources = strings.Split(rm[1], ",")
	}
	n := authz.DenialCount(authz.ResolveZSPDir(), sessionID, authz.AuthorizeDenialKey(actions, resources))
	if n < authz.DenialHaltAfter {
		return types.ExecResponse{}, false
	}
	return types.ExecResponse{
		Allowed:    false,
		ExitCode:   1,
		Reason:     fmt.Sprintf("ZeroStandingPrivilegeViolation: this authorize request for %v was refused %d times; not submitting it again", actions, n),
		Suggestion: authz.RepeatedDenialNotice(n) + "A human must act: see `bapedge zsp approvals`.",
		Halt:       true,
		StopReason: authz.HaltReason(n, "authorize "+am[1]),
	}, true
}

// printHITLNextStep tells the agent (stderr of the refused authorize) and the developer exactly what happens next.
func printHITLNextStep(p *authz.PendingApproval, sessionID, actions, resources string) {
	if p == nil {
		fmt.Fprintf(os.Stderr, "  Human Operator:    Run out-of-band in your own terminal: bapedge zsp authorize --oob-approve --session-id %q --actions %q --resources %q\n", sessionID, actions, resources)
		return
	}
	fmt.Fprintf(os.Stderr, "  HITL REQUEST RAISED: %s (valid until %s)\n", p.ID, p.ExpiresAt.Local().Format("15:04:05"))
	fmt.Fprintf(os.Stderr, "  DEVELOPER, in your own terminal:\n")
	fmt.Fprintf(os.Stderr, "      bapedge zsp approvals            # review pending requests\n")
	fmt.Fprintf(os.Stderr, "      bapedge zsp approve %s   # approve (you will type a one-time code)\n", p.ID)
	fmt.Fprintf(os.Stderr, "      bapedge zsp deny %s      # or deny\n", p.ID)
	fmt.Fprintf(os.Stderr, "  AGENT: stop and tell the developer the request id above, then retry your command once they approve. Do not run these commands yourself (they are blocked for agents).\n")
}

// raiseHITLRequest records a pending approval for an approve-tier refusal.
func raiseHITLRequest(sessionID, clientType, mission, goal string, actions, resources []string, maxUses int, ttl time.Duration, err error) *authz.PendingApproval {
	p, rErr := authz.RaisePendingApproval(authz.ResolveZSPDir(), authz.PendingApproval{
		SessionID: sessionID, ClientType: clientType, Mission: mission, Goal: goal,
		Actions: actions, Resources: resources, MaxUses: maxUses, TTLSeconds: int(ttl.Seconds()), Reason: err.Error(),
	})
	if rErr != nil {
		return nil
	}
	return p
}

// runZSPApprovals lists requests (human or agent may look; nothing is decided here).
func runZSPApprovals() error {
	list, err := authz.ListPendingApprovals(authz.ResolveZSPDir())
	if err != nil {
		return err
	}
	pending := 0
	for _, p := range list {
		if p.Status == "pending" && time.Now().Before(p.ExpiresAt) {
			pending++
			fmt.Printf("%s  session=%s  actions=%v  resources=%v\n    goal: %s\n    why:  %s\n    expires %s\n",
				p.ID, p.SessionID, p.Actions, p.Resources, p.Goal, p.Reason, p.ExpiresAt.Local().Format("15:04:05"))
		}
	}
	if pending == 0 {
		fmt.Println("No pending approval requests.")
	}
	return nil
}

// runZSPDecide approves or denies a request. Human-only: refused inside the broker, and approval also
// needs a real terminal and a freshly generated one-time code.
func runZSPDecide(approve bool, args []string) error {
	if strings.TrimSpace(os.Getenv("BAP_IN_BROKER")) != "" {
		return fmt.Errorf("%w: approving or denying requests is a human-operator action and cannot run inside an agent session", authz.ErrHighRiskApprovalRequired)
	}
	if len(args) == 0 {
		return fmt.Errorf("usage: bapedge zsp %s <request-id>", map[bool]string{true: "approve", false: "deny"}[approve])
	}
	id := strings.TrimSpace(args[0])
	p, err := authz.GetPendingApproval(authz.ResolveZSPDir(), id)
	if err != nil {
		return err
	}
	if approve && !humanApprovalChallenge(p.SessionID, p.Actions, p.Resources, p.Goal) {
		return fmt.Errorf("%w: interactive human approval challenge failed or no terminal is attached", authz.ErrHighRiskApprovalRequired)
	}
	req, grant, err := authz.DecidePendingApproval(authz.ResolveZSPDir(), id, approve)
	if err != nil {
		return err
	}
	if approve {
		fmt.Printf("[BAP ZERO-TRUST] Request %s APPROVED. Grant %s minted for session %s (%d uses, expires %s). Tell the agent to retry.\n",
			req.ID, grant.GrantID, req.SessionID, grant.MaxUses, grant.ExpiresAt.Local().Format("15:04:05"))
	} else {
		fmt.Printf("[BAP ZERO-TRUST] Request %s DENIED.\n", req.ID)
	}
	return nil
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
	// The prompt can never spin forever: if nobody answers, it gives up and leaves the request pending.
	type readResult struct {
		line string
		err  error
	}
	ch := make(chan readResult, 1)
	go func() {
		l, e := bufio.NewReader(os.Stdin).ReadString('\n')
		ch <- readResult{l, e}
	}()
	var line string
	var err error
	select {
	case r := <-ch:
		line, err = r.line, r.err
	case <-time.After(approvalPromptTimeout):
		fmt.Fprintln(os.Stderr, "\n[BAP] Approval prompt timed out; nothing was approved and the request stays pending.")
		return false
	}
	if err != nil && line == "" {
		return false
	}
	got := strings.ToUpper(strings.TrimSpace(line))
	return subtle.ConstantTimeCompare([]byte(got), []byte(code)) == 1
}
