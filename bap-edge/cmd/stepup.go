package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"bap-edge/internal/httptransport"
)

// RunStepUp handles the 'bapedge stepup' command (BAP-565)
func RunStepUp(args []string) error {
	if len(args) == 0 {
		printStepUpUsage()
		return nil
	}

	sub := args[0]
	rest := args[1:]

	serverURL := os.Getenv("BAP_SERVER_URL")
	if serverURL == "" {
		serverURL = os.Getenv("BAP_CONTROL_PLANE_URL")
	}
	if serverURL == "" {
		serverURL = "http://localhost:8443"
	}
	serverURL = strings.TrimRight(serverURL, "/")

	client := httptransport.New(5 * time.Second)

	switch sub {
	case "request":
		if len(rest) < 3 {
			return fmt.Errorf("usage: bapedge stepup request <task_id> <action> <resource> [reason]")
		}
		taskID := rest[0]
		action := rest[1]
		resource := rest[2]
		reason := "Agent requested out-of-scope task escalation"
		if len(rest) > 3 {
			reason = strings.Join(rest[3:], " ")
		}

		sessID := os.Getenv("BAP_SESSION_ID")
		agentID := os.Getenv("BAP_AGENT_ID")
		if agentID == "" {
			agentID = "cli-agent"
		}

		payload := map[string]string{
			"task_id":    taskID,
			"session_id": sessID,
			"agent_id":   agentID,
			"resource":   resource,
			"action":     action,
			"reason":     reason,
		}

		data, _ := json.Marshal(payload)
		resp, err := client.Post(serverURL+"/api/v1/escalation/request", "application/json", bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("failed to submit escalation request: %w", err)
		}
		defer resp.Body.Close()

		var out map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		outBytes, _ := json.Marshal(out)
		fmt.Println(string(outBytes))

		if resp.StatusCode == http.StatusTooManyRequests {
			return fmt.Errorf("escalation throttled: %v", out["message"])
		}
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
			return fmt.Errorf("escalation rejected (status %d): %v", resp.StatusCode, out["message"])
		}
		return nil

	case "status":
		if len(rest) == 0 {
			return fmt.Errorf("usage: bapedge stepup status <escalation_id>")
		}
		escID := rest[0]
		resp, err := client.Get(serverURL + "/api/v1/escalation/" + escID)
		if err != nil {
			return fmt.Errorf("failed to query escalation status: %w", err)
		}
		defer resp.Body.Close()

		var out map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		outBytes, _ := json.Marshal(out)
		fmt.Println(string(outBytes))
		return nil

	case "list":
		resp, err := client.Get(serverURL + "/api/v1/escalation/requests")
		if err != nil {
			return fmt.Errorf("failed to list escalations: %w", err)
		}
		defer resp.Body.Close()

		var out map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		outBytes, _ := json.Marshal(out)
		fmt.Println(string(outBytes))
		return nil

	default:
		printStepUpUsage()
		return fmt.Errorf("unknown stepup subcommand: %s", sub)
	}
}

func printStepUpUsage() {
	fmt.Println("BAP Task-Scoped HITL Step-Up Escalation (BAP-565)")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  bapedge stepup request <task_id> <action> <resource> [reason]")
	fmt.Println("  bapedge stepup status <escalation_id>")
	fmt.Println("  bapedge stepup list")
	fmt.Println("")
}
