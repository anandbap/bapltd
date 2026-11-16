package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"bap-edge/internal/config"
	"bap-edge/internal/httptransport"
	"bap-edge/internal/state"
)

func resolveStepUpServerURL() string {
	serverURL := os.Getenv("BAP_SERVER_URL")
	if serverURL == "" {
		serverURL = os.Getenv("BAP_CONTROL_PLANE_URL")
	}
	if serverURL == "" {
		ep := config.ResolveEndpoints()
		serverURL = ep.ControlPlaneURL
	}
	if serverURL == "" {
		serverURL = config.DefaultControlPlaneURL
	}
	if serverURL == "" {
		serverURL = "http://localhost:8443"
	}
	return strings.TrimRight(serverURL, "/")
}

func sendStepUpRequest(client *http.Client, method, url string, body []byte) (*http.Response, error) {
	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	// Attach enrolled session token if present
	if credsData, err := os.ReadFile(state.CredentialsPath()); err == nil && len(credsData) > 0 {
		var creds struct {
			SessionToken string `json:"session_token"`
		}
		if json.Unmarshal(credsData, &creds) == nil && creds.SessionToken != "" {
			req.Header.Set("Authorization", "Bearer "+creds.SessionToken)
		}
	}

	return client.Do(req)
}

// RunStepUp handles the 'bapedge stepup' command (BAP-565, BAP-1093)
func RunStepUp(args []string) error {
	if len(args) == 0 {
		printStepUpUsage()
		return nil
	}

	sub := args[0]
	rest := args[1:]

	serverURL := resolveStepUpServerURL()
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
		resp, err := sendStepUpRequest(client, http.MethodPost, serverURL+"/api/v1/escalation/request", data)
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
		resp, err := sendStepUpRequest(client, http.MethodGet, serverURL+"/api/v1/escalation/"+escID, nil)
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
		resp, err := sendStepUpRequest(client, http.MethodGet, serverURL+"/api/v1/escalation/requests", nil)
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
