package cmd

import (
	"flag"
	"fmt"
	"os/user"
	"strings"
	"time"

	"bap-edge/internal/authz"
)

func init() {
	authz.AutoApproveActive = func() bool {
		on, _, _ := authz.AutoApproveStatus(authz.ResolveZSPDir())
		return on
	}
}

// runZSPAutoApprove implements `bapedge zsp autoapprove on|off|status` (BAP-1100).
//
//	on [--duration 1h]   open a bounded window (max 8h) in which approve-tier ZSP requests are
//	                     granted without a per-request approval. Human only: refused inside an
//	                     agent broker and requires a terminal one-time-code challenge.
//	off                  close the window immediately.
//	status               show whether the window is open.
//
// It is off by default. It never covers policy/grant/admin escalations or hard denies.
func runZSPAutoApprove(args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	sub := strings.ToLower(args[0])
	rest := args[1:]
	dir := authz.ResolveZSPDir()

	switch sub {
	case "status":
		on, until, by := authz.AutoApproveStatus(dir)
		if on {
			fmt.Printf("ZSP step-up auto-approve: ON until %s (enabled by %s)\n", until.Format(time.RFC3339), by)
		} else {
			fmt.Println("ZSP step-up auto-approve: OFF (approve-tier requests need a human decision)")
		}
		return nil

	case "off", "disable":
		if _, err := authz.SetAutoApprove(dir, false, 0, ""); err != nil {
			return err
		}
		fmt.Println("ZSP step-up auto-approve: OFF")
		return nil

	case "on", "enable":
		if err := refuseAgentContext("turning on auto-approve is a human-operator action and cannot run inside an agent session"); err != nil {
			return err
		}
		fs := flag.NewFlagSet("zsp autoapprove on", flag.ContinueOnError)
		dur := fs.Duration("duration", authz.DefaultAutoApproveWindow, "Window length (maximum 8h)")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if !humanApprovalChallenge("auto-approve", []string{"ZSP step-up auto-approve ON for " + dur.String()}, []string{"workstation"}, "Approve-tier requests will be granted without a prompt until the window ends") {
			return fmt.Errorf("%w: interactive human approval challenge failed or no terminal is attached", authz.ErrHighRiskApprovalRequired)
		}
		by := "developer"
		if u, err := user.Current(); err == nil && u.Username != "" {
			by = u.Username
		}
		until, err := authz.SetAutoApprove(dir, true, *dur, by)
		if err != nil {
			return err
		}
		fmt.Printf("ZSP step-up auto-approve: ON until %s. Turn off with: bapedge zsp autoapprove off\n", until.Format(time.RFC3339))
		return nil
	}
	return fmt.Errorf("usage: bapedge zsp autoapprove on [--duration 1h] | off | status")
}
