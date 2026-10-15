package cmd

import (
	"flag"
	"fmt"
	"os"
	"time"

	"bap-edge/internal/audit"
	"bap-edge/internal/config"
	"bap-edge/internal/policystore"
)

// RunSync implements the 'bapedge sync' command to synchronize or inspect local policy cache
// and flush locally spooled offline telemetry/audit events to the central control plane.
func RunSync(args []string) error {
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	epCfg := config.ResolveEndpoints()
	serverURL := fs.String("server", epCfg.ControlPlaneURL, "bapcontrolplane URL (e.g. http://localhost:8080)")
	policyDir := fs.String("policy-dir", policystore.DefaultPolicyDir(), "Path to local edge policy cache directory")
	agentID := fs.String("agent-id", os.Getenv("BAP_AGENT_ID"), "Registered Agent ID (optional)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	store := policystore.New(*policyDir)

	fmt.Printf("[bapedge sync] Checking policy & telemetry synchronization against %s...\n", *serverURL)
	bundle, isFallback, err := store.SyncWithServer(*serverURL, *agentID, 3*time.Second)
	if err != nil {
		if err == policystore.ErrKillSwitchActive {
			fmt.Println("==================================================")
			fmt.Println("  [EMERGENCY WARNING] POLICY KILL-SWITCH IS ACTIVE!")
			fmt.Println("  All local agent executions are strictly blocked.")
			fmt.Println("==================================================")
			return err
		}
		return fmt.Errorf("sync failed: %w", err)
	}

	// 2. Synchronize and flush offline audit telemetry spool to central control plane
	flushedCount := 0
	auditLogPath := audit.DefaultLogPath()
	if !isFallback && *serverURL != "" {
		if flushed, flushErr := audit.FlushOfflineAudit(*serverURL, auditLogPath); flushErr == nil {
			flushedCount = flushed
		}
	}

	// Inspect remaining offline spool backlog
	remainingEntries, _ := audit.ReadEntries(auditLogPath)
	pendingSpoolCount := len(remainingEntries)

	fmt.Println("==================================================")
	if isFallback {
		fmt.Println("  [OFFLINE RESILIENCE ACTIVE] Control plane is DOWN.")
		fmt.Println("  bapedge is operating safely with local cached policy.")
		fmt.Printf("  Offline telemetry is recorded locally in %s.\n", auditLogPath)
	} else {
		fmt.Println("  Synchronization successful (Online).")
	}
	fmt.Println("==================================================")
	fmt.Printf("Policy Version:   %d\n", bundle.Version)
	fmt.Printf("Rules Digest:     %s\n", bundle.Digest)
	fmt.Printf("Cache Location:   %s\n", *policyDir)
	fmt.Printf("Kill Switch:      %v\n", bundle.KillSwitch)
	if isFallback {
		fmt.Printf("Telemetry Spool:  Offline (%d event(s) buffered in %s)\n", pendingSpoolCount, auditLogPath)
	} else {
		fmt.Printf("Telemetry Spool:  Synchronized (%d flushed, %d remaining)\n", flushedCount, pendingSpoolCount)
	}
	fmt.Println("==================================================")

	return nil
}
