package cmd

import (
	"encoding/json"
	"fmt"

	"bap-edge/internal/shield"
)

// RunShield handles the 'bapedge shield' command
func RunShield(args []string) error {
	if len(args) == 0 {
		printShieldUsage()
		return nil
	}

	sub := args[0]
	rest := args[1:]
	vault := shield.NewShieldVault()

	switch sub {
	case "scan":
		dir := "."
		if len(rest) > 0 {
			dir = rest[0]
		}
		found, err := vault.ScanWorkspaceCredentials(dir)
		if err != nil {
			return err
		}
		out, _ := json.Marshal(map[string]interface{}{
			"scanned_dir":       dir,
			"credentials_found": found,
			"count":             len(found),
		})
		fmt.Println(string(out))
		return nil

	case "plant-canary":
		dir := "."
		if len(rest) > 0 {
			dir = rest[0]
		}
		token, path, err := vault.PlantCanary(dir)
		if err != nil {
			return err
		}
		out, _ := json.Marshal(map[string]interface{}{
			"status":       "planted",
			"canary_path":  path,
			"canary_token": token,
		})
		fmt.Println(string(out))
		return nil

	case "check-canary":
		if len(rest) == 0 {
			return fmt.Errorf("usage: bapedge shield check-canary <input>")
		}
		tripped, reason := vault.InspectForCanaryTrigger(rest[0])
		out, _ := json.Marshal(map[string]interface{}{
			"tripped": tripped,
			"reason":  reason,
		})
		fmt.Println(string(out))
		if tripped {
			return fmt.Errorf("honeytoken tripped: %s", reason)
		}
		return nil

	default:
		printShieldUsage()
		return fmt.Errorf("unknown shield subcommand: %s", sub)
	}
}

func printShieldUsage() {
	fmt.Println("BAP Credential Shielding & Honeytoken Vault (BAP-562)")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  bapedge shield scan [<dir>]                Discover standing credentials on disk")
	fmt.Println("  bapedge shield plant-canary [<dir>]        Plant a tripwire honeytoken in directory")
	fmt.Println("  bapedge shield check-canary <payload>      Inspect text for tripped canary tokens")
	fmt.Println("")
}
