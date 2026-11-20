package cmd

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"bap-edge/internal/authz"
)

func runZSPInbox(args []string) error {
	if strings.TrimSpace(os.Getenv("BAP_IN_BROKER")) != "" || !isTerminal(os.Stdin) || !isTerminal(os.Stderr) {
		return fmt.Errorf("%w: open the approval inbox in your own interactive terminal", authz.ErrHighRiskApprovalRequired)
	}
	fs := flag.NewFlagSet("zsp inbox", flag.ContinueOnError)
	watch := fs.Bool("watch", false, "Wait for newly raised requests after reviewing the current inbox")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: bapedge zsp inbox [--watch]")
	}
	// Keep the platform's normal Ctrl+C termination while a terminal read or
	// challenge is waiting. Pending requests are durable; no cleanup is needed.
	ctx := context.Background()
	fmt.Fprintln(os.Stderr, "BAP approval inbox: each approval requires its own one-time challenge. No bulk or automatic approval. Ctrl+C exits.")
	fmt.Fprintln(os.Stderr, "Terminal checks do not establish cryptographic human identity; do not expose this terminal to an agent.")
	return reviewZSPInbox(ctx, *watch, bufio.NewReader(os.Stdin), os.Stderr,
		func() ([]authz.PendingApproval, error) { return authz.ListPendingApprovals(authz.ResolveZSPDir()) },
		func(approve bool, p authz.PendingApproval, reader *bufio.Reader) error {
			return runZSPDecideReviewed(approve, []string{p.ID}, reader, &p)
		})
}

// The review loop has no grant-minting authority; decisions always return to the
// guarded CLI path, which rechecks terminal presence and the reviewed snapshot.
func reviewZSPInbox(ctx context.Context, watch bool, reader *bufio.Reader, output io.Writer,
	list func() ([]authz.PendingApproval, error), decide func(bool, authz.PendingApproval, *bufio.Reader) error) error {
	seen := map[string]bool{}
	for {
		requests, err := list()
		if err != nil {
			return err
		}
		for i := len(requests) - 1; i >= 0; i-- {
			p := requests[i]
			if seen[p.ID] || p.CheckDecidable() != nil {
				continue
			}
			if err := ctx.Err(); err != nil {
				return nil
			}
			fmt.Fprintf(output, "\nRequest %q\n  Client: %q\n  Session: %q\n  Linked session: %q\n  Mission: %q\n  Goal: %q\n  Actions: %q\n  Resources: %q\n  Uses: %d; grant TTL: %ds; request expires: %s\n  Reason: %q\n",
				p.ID, p.ClientType, p.SessionID, p.RequestingSessionID, p.Mission, p.Goal, p.Actions, p.Resources, p.MaxUses, p.TTLSeconds, p.ExpiresAt.Local().Format(time.RFC3339), p.Reason)
			fmt.Fprint(output, "[a] approve, [d] deny, [s/Enter] skip, [q] quit > ")
			line, err := reader.ReadString('\n')
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return err
			}
			switch strings.ToLower(strings.TrimSpace(line)) {
			case "q", "quit":
				return nil
			case "a", "approve", "d", "deny":
				approve := strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "a")
				if err := decide(approve, p, reader); err != nil {
					return err
				}
			case "", "s", "skip":
			default:
				fmt.Fprintln(output, "Unrecognized choice; nothing decided. Restart the inbox to review this request again.")
			}
			seen[p.ID] = true
		}
		if !watch {
			fmt.Fprintln(output, "No more pending requests to review.")
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(2 * time.Second):
		}
	}
}
