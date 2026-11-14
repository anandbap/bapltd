package cmd

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"bap-edge/internal/audit"
	"bap-edge/internal/authz"
	"bap-edge/internal/config"
)

// emitApprovalLifecycle reports a human-approval request state change to the audit trail so the
// control plane can show it. It is visibility only: the decision stays local, out of band, and gated
// by a terminal one-time code. Events use decision "observed" so they never inflate allow/deny counts.
// state is one of: approval_pending, approval_approved, approval_denied.
func emitApprovalLifecycle(p *authz.PendingApproval, state string) {
	if p == nil || os.Getenv("BAP_OFFLINE") == "1" || os.Getenv("BAP_TEST_MODE") == "1" {
		return
	}
	// Never write to the real state directory or reach the network from `go test`.
	if flag.Lookup("test.v") != nil {
		return
	}
	serverURL := strings.TrimRight(config.ResolveEndpoints().ControlPlaneURL, "/")
	if serverURL == "" {
		serverURL = strings.TrimRight(config.DefaultControlPlaneURL, "/")
	}
	entry := audit.AuditEntry{
		EventID:        "approval-" + p.ID + "-" + state,
		ReportingLayer: "broker",
		SessionID:      p.SessionID,
		Timestamp:      time.Now().UTC(),
		Source:         "zsp-approval",
		ClientPID:      os.Getpid(),
		Executable:     "zsp_approval",
		FullCommand: fmt.Sprintf("%s actions=%s resources=%s goal=%s", p.ID,
			strings.Join(p.Actions, ","), strings.Join(p.Resources, ","), p.Goal),
		Decision: "observed",
		Reason:   state,
	}
	logPath := audit.DefaultLogPath()
	_ = audit.Log(&entry, logPath)
	_, _, _ = audit.Transmit(entry, serverURL, logPath)
}
