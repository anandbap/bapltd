package adapters

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CanonicalActivityEvent represents a normalized cross-harness security & audit event
// compliant with BAP-539 multi-harness governance standards.
type CanonicalActivityEvent struct {
	EventID      string                 `json:"event_id"`
	HarnessType  string                 `json:"harness_type"` // "cursor", "gemini-cli", "browser-playwright", "saas-agent"
	SessionID    string                 `json:"session_id"`
	AgentID      string                 `json:"agent_id"`
	UserEmail    string                 `json:"user_email,omitempty"`
	ActivityType string                 `json:"activity_type"` // "tool_call", "prompt", "terminal_command", "navigation", "upload", "saas_invocation"
	Target       string                 `json:"target"`
	Decision     string                 `json:"decision"` // "ALLOW", "DENY"
	Reason       string                 `json:"reason,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	Timestamp    time.Time              `json:"timestamp"`
}

// GenerateEventID produces a unique event ID
func GenerateEventID(harness string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("act-%s-%s", strings.ToLower(harness), hex.EncodeToString(b))
}

// NewActivityEvent creates an initialized CanonicalActivityEvent
func NewActivityEvent(harness, sessionID, agentID, activityType, target, decision, reason string) *CanonicalActivityEvent {
	return &CanonicalActivityEvent{
		EventID:      GenerateEventID(harness),
		HarnessType:  harness,
		SessionID:    sessionID,
		AgentID:      agentID,
		ActivityType: activityType,
		Target:       target,
		Decision:     decision,
		Reason:       reason,
		Metadata:     make(map[string]interface{}),
		Timestamp:    time.Now().UTC(),
	}
}

// ReportActivity logs the event locally and asynchronously transmits it to the Control Plane
func ReportActivity(controlPlaneURL string, event *CanonicalActivityEvent) error {
	if event.EventID == "" {
		event.EventID = GenerateEventID(event.HarnessType)
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	// Always persist to local activity spool
	_ = persistLocalActivity(event)

	// Send to control plane if endpoint configured
	if controlPlaneURL != "" {
		payload, err := json.Marshal(map[string]interface{}{
			"events": []map[string]interface{}{
				{
					"event_id":     event.EventID,
					"source":       "harness-" + event.HarnessType,
					"session_id":   event.SessionID,
					"agent_id":     event.AgentID,
					"executable":   event.ActivityType,
					"full_command": event.Target,
					"decision":     event.Decision,
					"reason":       event.Reason,
					"timestamp":    event.Timestamp.Format(time.RFC3339),
				},
			},
		})
		if err == nil {
			client := &http.Client{Timeout: 3 * time.Second}
			url := strings.TrimRight(controlPlaneURL, "/") + "/api/v1/audit/ingest"
			req, rerr := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
			if rerr == nil {
				req.Header.Set("Content-Type", "application/json")
				resp, postErr := client.Do(req)
				if postErr == nil {
					_ = resp.Body.Close()
				}
			}
		}
	}
	return nil
}

func persistLocalActivity(event *CanonicalActivityEvent) error {
	bapStateDir := ".bapstate"
	if err := os.MkdirAll(bapStateDir, 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(bapStateDir, "harness_activity.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	line, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = f.Write(append(line, '\n'))
	return err
}
