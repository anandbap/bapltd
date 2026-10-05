package cmd

import (
	"flag"
	"fmt"

	"bap-edge/internal/audit"
)

// RunVerifyLog checks the cryptographic integrity of the local JSON Lines audit log.
func RunVerifyLog(args []string) error {
	fs := flag.NewFlagSet("verify-log", flag.ContinueOnError)
	fileFlag := fs.String("file", "", "Path to audit log file (defaults to .bapstate/audit.jsonl or LTD_AUDIT_LOG)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	logPath := *fileFlag
	if logPath == "" {
		logPath = audit.DefaultLogPath()
	}

	fmt.Printf("[*] Verifying cryptographic integrity of audit log: %s\n", logPath)
	valid, count, err := audit.VerifyLocalLog(logPath)
	if err != nil {
		fmt.Printf("[-] TAMPER DETECTED: %v\n", err)
		return err
	}

	if !valid {
		fmt.Println("[-] INTEGRITY FAILURE: Log file has been altered.")
		return fmt.Errorf("audit log verification failed")
	}

	fmt.Printf("[+] SUCCESS: Audit log is cryptographically valid! (%d entries verified, 0 tampering detected)\n", count)
	return nil
}
