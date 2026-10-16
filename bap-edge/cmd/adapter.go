package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"bap-edge/internal/adapters"
)

// RunAdapter handles the "bapedge adapter" CLI command
func RunAdapter(args []string) error {
	if len(args) == 0 {
		printAdapterUsage()
		return nil
	}

	sub := args[0]
	rest := args[1:]

	switch sub {
	case "cursor":
		return runCursorAdapter(rest)
	case "gemini":
		return runGeminiAdapter(rest)
	case "browser":
		return runBrowserAdapter(rest)
	case "emit":
		return runEmitAdapter(rest)
	default:
		printAdapterUsage()
		return fmt.Errorf("unknown adapter command: %s", sub)
	}
}

func printAdapterUsage() {
	fmt.Println("BAP Multi-Harness Governance Adapter (BAP-539)")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  bapedge adapter cursor configure [--dir <path>]")
	fmt.Println("  bapedge adapter gemini configure [--dir <path>]")
	fmt.Println("  bapedge adapter browser check-url <url>")
	fmt.Println("  bapedge adapter browser check-upload <file-path>")
	fmt.Println("  bapedge adapter emit --harness <name> --action <act> --target <tgt> [--decision <ALLOW|DENY>]")
	fmt.Println("")
}

func runCursorAdapter(args []string) error {
	dir := "."
	for i := 0; i < len(args); i++ {
		if args[i] == "--dir" && i+1 < len(args) {
			dir = args[i+1]
			i++
		}
	}
	adapter := adapters.NewCursorAdapter(dir, "", "", "")
	if err := adapter.ConfigureWorkspace(); err != nil {
		return err
	}
	fmt.Printf("[BAP-ADAPTER] Cursor workspace configured successfully in %s\n", dir)
	return nil
}

func runGeminiAdapter(args []string) error {
	dir := "."
	for i := 0; i < len(args); i++ {
		if args[i] == "--dir" && i+1 < len(args) {
			dir = args[i+1]
			i++
		}
	}
	adapter := adapters.NewGeminiCLIAdapter(dir, "", "", "")
	if err := adapter.ConfigureWorkspace(); err != nil {
		return err
	}
	fmt.Printf("[BAP-ADAPTER] Gemini CLI workspace rules configured successfully in %s\n", dir)
	return nil
}

func runBrowserAdapter(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: bapedge adapter browser <check-url|check-upload> <target>")
	}
	action := args[0]
	target := args[1]
	guard := adapters.NewBrowserGuard("", "", "")

	switch action {
	case "check-url":
		allowed, reason, evt := guard.EvaluateNavigation(target)
		out, _ := json.Marshal(map[string]interface{}{
			"allowed":  allowed,
			"reason":   reason,
			"event_id": evt.EventID,
			"decision": evt.Decision,
		})
		fmt.Println(string(out))
		if !allowed {
			return fmt.Errorf("blocked: %s", reason)
		}
		return nil
	case "check-upload":
		content, _ := os.ReadFile(target)
		allowed, reason, evt := guard.EvaluateUpload(target, content)
		out, _ := json.Marshal(map[string]interface{}{
			"allowed":  allowed,
			"reason":   reason,
			"event_id": evt.EventID,
			"decision": evt.Decision,
		})
		fmt.Println(string(out))
		if !allowed {
			return fmt.Errorf("blocked: %s", reason)
		}
		return nil
	default:
		return fmt.Errorf("unknown browser action: %s", action)
	}
}

func runEmitAdapter(args []string) error {
	harness := "custom"
	action := "tool_call"
	target := ""
	decision := "ALLOW"
	reason := "Adapter activity emitted"

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--harness":
			if i+1 < len(args) {
				harness = args[i+1]
				i++
			}
		case "--action":
			if i+1 < len(args) {
				action = args[i+1]
				i++
			}
		case "--target":
			if i+1 < len(args) {
				target = args[i+1]
				i++
			}
		case "--decision":
			if i+1 < len(args) {
				decision = strings.ToUpper(args[i+1])
				i++
			}
		case "--reason":
			if i+1 < len(args) {
				reason = args[i+1]
				i++
			}
		}
	}

	evt := adapters.NewActivityEvent(harness, "sess-cli-emit", "agent-cli", action, target, decision, reason)
	_ = adapters.ReportActivity("", evt)

	out, _ := json.Marshal(evt)
	fmt.Println(string(out))
	return nil
}
