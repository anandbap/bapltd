package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"bap-edge/internal/antibypass"
)

// RunAntiBypass handles the 'bapedge antibypass' command
func RunAntiBypass(args []string) error {
	if len(args) == 0 {
		printAntiBypassUsage()
		return nil
	}

	sub := args[0]
	rest := args[1:]

	engine := antibypass.NewAntiBypassEngine()

	switch sub {
	case "check":
		if len(rest) == 0 {
			return fmt.Errorf("usage: bapedge antibypass check <command>")
		}
		cmdToTest := rest[0]
		sessID := os.Getenv("BAP_SESSION_ID")
		if sessID == "" {
			sessID = "sess-antibypass-cli"
		}
		viol, err := engine.CheckCommand(sessID, cmdToTest, nil)
		if err != nil {
			out, _ := json.Marshal(map[string]interface{}{
				"allowed": false,
				"error":   err.Error(),
				"vector":  viol.Vector,
				"reason":  viol.Reason,
			})
			fmt.Println(string(out))
			return err
		}
		out, _ := json.Marshal(map[string]interface{}{
			"allowed": true,
			"status":  "clean",
			"command": cmdToTest,
		})
		fmt.Println(string(out))
		return nil

	case "status":
		fmt.Println("BAP Anti-Bypass Enforcement Engine: ACTIVE (Zero Unmediated Egress)")
		fmt.Printf("Protected Env Vars: %v\n", engine.ProtectedEnvVars)
		fmt.Printf("Monitored Evasion Regex Patterns: %d active\n", len(engine.EvasionPatterns))
		return nil

	default:
		printAntiBypassUsage()
		return fmt.Errorf("unknown antibypass subcommand: %s", sub)
	}
}

func printAntiBypassUsage() {
	fmt.Println("BAP Anti-Bypass Enforcement Subsystem (BAP-560)")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  bapedge antibypass check <command>   Evaluate command for bypass vectors")
	fmt.Println("  bapedge antibypass status            Show active anti-bypass rules")
	fmt.Println("")
}
