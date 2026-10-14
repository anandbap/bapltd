package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"bap-edge/internal/snapshot"
)

// RunRollback handles the 'bapedge rollback' command.
func RunRollback(args []string) error {
	fs := flag.NewFlagSet("rollback", flag.ContinueOnError)
	sessionID := fs.String("session-id", "", "Target session ID (defaults to active session or default)")
	checkpointID := fs.String("checkpoint-id", "", "Specific checkpoint ID to restore")
	filterFile := fs.String("file", "", "Specific file path to restore from checkpoint")
	listOnly := fs.Bool("list", false, "List available checkpoints for session")
	jsonOutput := fs.Bool("json", false, "Output results in JSON format")

	if err := fs.Parse(args); err != nil {
		return err
	}

	targetSession := *sessionID
	if targetSession == "" {
		targetSession = os.Getenv("BAP_SESSION_ID")
		if targetSession == "" {
			targetSession = "default"
		}
	}

	if *listOnly {
		checkpoints, err := snapshot.ListCheckpoints(targetSession)
		if err != nil {
			return fmt.Errorf("failed listing checkpoints: %v", err)
		}

		if *jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(checkpoints)
		}

		if len(checkpoints) == 0 {
			fmt.Printf("No checkpoints found for session %q.\n", targetSession)
			return nil
		}

		fmt.Printf("Found %d checkpoint(s) for session %q:\n\n", len(checkpoints), targetSession)
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "CHECKPOINT ID\tTIMESTAMP\tFILES\tCOMMAND")
		for _, ck := range checkpoints {
			var fileBases []string
			for _, f := range ck.Files {
				fileBases = append(fileBases, filepath.Base(f.OriginalPath))
			}
			fileSummary := fmt.Sprintf("%d file(s) (%s)", len(ck.Files), fileBases)
			if len(fileSummary) > 40 {
				fileSummary = fileSummary[:37] + "..."
			}
			cmdSummary := ck.Command
			if len(cmdSummary) > 45 {
				cmdSummary = cmdSummary[:42] + "..."
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", ck.CheckpointID, ck.Timestamp.Format(time.RFC3339), fileSummary, cmdSummary)
		}
		w.Flush()
		return nil
	}

	// Perform rollback
	res, err := snapshot.Rollback(targetSession, *checkpointID, *filterFile)
	if err != nil {
		return fmt.Errorf("rollback failed: %v", err)
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}

	fmt.Printf("[+] Successfully rolled back to checkpoint %q (Session: %s)\n", res.CheckpointID, res.SessionID)
	for _, f := range res.RestoredFiles {
		fmt.Printf("  • Restored: %s\n", f)
	}
	for _, f := range res.RemovedFiles {
		fmt.Printf("  • Removed (was created by mutating action): %s\n", f)
	}
	for _, h := range res.VerifiedHashes {
		fmt.Printf("  ✓ Cryptographically verified: %s\n", h)
	}

	return nil
}
