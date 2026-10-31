package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"bap-edge/internal/authz"
)

type recoveryRetry struct {
	mu       sync.Mutex
	next     time.Time
	failures int
	inFlight bool
}

var sessionRecoveries sync.Map

var recoveryRestrictions = localRecoveryRestrictions

var recoveryCredential = func(url string) (StoredCredentials, error) {
	var creds StoredCredentials
	raw, err := os.ReadFile(DefaultCredentialsPath())
	if err != nil || json.Unmarshal(raw, &creds) != nil || creds.SessionToken == "" || creds.InstanceID == "" || strings.TrimRight(creds.ServerURL, "/") != strings.TrimRight(url, "/") {
		return creds, fmt.Errorf("enrolled workstation identity unavailable for recovery")
	}
	return creds, nil
}

type sessionResumePayload struct {
	SessionID    string `json:"session_id"`
	AppID        string `json:"app_id"`
	InstanceID   string `json:"instance_id"`
	Hostname     string `json:"hostname"`
	ClientPID    int    `json:"client_pid"`
	LocalBlocked bool   `json:"local_blocked"`
	LocalFrozen  bool   `json:"local_frozen"`
}

func localRecoveryRestrictions(sessionID string) (blocked, frozen bool) {
	paths := []string{filepath.Join(".bap", "policy-state.json"), "policy-state.json"}
	if policy, err := authz.FindFile("", "policy.cedar"); err == nil {
		paths = append(paths, filepath.Join(filepath.Dir(policy), "policy-state.json"), filepath.Join(filepath.Dir(policy), ".bap", "policy-state.json"))
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var cache struct {
			KillSwitch bool     `json:"kill_switch"`
			Frozen     bool     `json:"frozen"`
			Sessions   []string `json:"revoked_sessions"`
		}
		if json.Unmarshal(raw, &cache) != nil {
			blocked = true
			continue
		}
		frozen = frozen || cache.Frozen
		blocked = blocked || cache.KillSwitch || hasTarget(cache.Sessions, []string{sessionID})
	}
	return
}

// This request only re-announces a live workload; it does not request a grant.
func postSessionResume(ctx context.Context, client *http.Client, url string, payload sessionResumePayload, proof string) (string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(url, "/")+"/api/v1/sessions/resume", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+proof)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer closeHeartbeatResponse(resp)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("resume refused (HTTP %d)", resp.StatusCode)
	}
	var result struct {
		Status string `json:"status"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if result.Status == "active" || result.Status == "alive" {
		return "ok", nil
	}
	if result.Status == "revoked" {
		return "revoked", nil
	}
	return "", fmt.Errorf("unexpected recovery status")
}

func recoverMissingSession(ctx context.Context, client *http.Client, url, id, app string, pid int) (string, string) {
	if pid <= 0 || !isProcessAlive(pid) {
		return "missing", ""
	}
	key := strings.TrimRight(url, "/") + "|" + id
	value, _ := sessionRecoveries.LoadOrStore(key, &recoveryRetry{})
	retry := value.(*recoveryRetry)
	retry.mu.Lock()
	if retry.inFlight || time.Now().Before(retry.next) {
		retry.mu.Unlock()
		return "missing", ""
	}
	retry.inFlight = true
	defer func() { retry.mu.Lock(); retry.inFlight = false; retry.mu.Unlock() }()
	delay := time.Second * time.Duration(1<<min(retry.failures, 5))
	retry.failures++
	retry.next = time.Now().Add(delay + time.Duration(rand.Int64N(int64(delay/4))))
	retry.mu.Unlock()
	// The application's existing enrolled identity is used only on this cold path.
	creds, err := recoveryCredential(url)
	if err != nil {
		return "missing", "Enrolled workstation identity unavailable for recovery"
	}
	host, _ := os.Hostname()
	blocked, frozen := recoveryRestrictions(id)
	status, err := postSessionResume(ctx, client, url, sessionResumePayload{SessionID: id, AppID: app, InstanceID: creds.InstanceID, Hostname: host, ClientPID: pid, LocalBlocked: blocked, LocalFrozen: frozen}, creds.SessionToken)
	if err != nil {
		return "missing", err.Error()
	}
	sessionRecoveries.Delete(key)
	return status, "Session reporting recovered"
}
