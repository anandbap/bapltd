package cmd

import (
	"bap-edge/internal/config"
	"bap-edge/internal/httptransport"
	"bap-edge/internal/state"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

type onboardingProbe struct {
	ID        string    `json:"probe_id"`
	StartedAt time.Time `json:"started_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

var onboardingProbeID = regexp.MustCompile(`^[a-f0-9]{32}$`)

func probeStatePath() string { return filepath.Join(state.Dir(), "onboarding-probe.json") }

func evaluateProbe(probe onboardingProbe, now time.Time, local map[string]any, central map[string]any) map[string]any {
	checks := map[string]any{}
	result := map[string]any{"status": "partial", "probe_id": probe.ID, "checks": checks, "execution_success_verified": false, "scope": "correlated reporting observations; not native approval, attestation, business completion or full pilot readiness"}
	if !onboardingProbeID.MatchString(probe.ID) || probe.StartedAt.IsZero() || probe.StartedAt.After(now.Add(5*time.Second)) || probe.ExpiresAt.Sub(probe.StartedAt) != 15*time.Minute || !probe.ExpiresAt.After(now) {
		result["status"] = "expired"
		return result
	}
	reference, _ := central["session_reference"].(string)
	valid := len(reference) == 64 && central["probe_id"] == probe.ID && central["prompt_record_observed"] == true && central["policy_record_observed"] == true && central["policy_decision"] == "allow" && central["restricted"] == false
	checks["central_owned_prompt_and_policy_record"] = valid
	if decision := central["policy_decision"]; decision == "allow" || decision == "deny" {
		result["central_policy_decision"] = decision
	}
	if restricted, ok := central["restricted"].(bool); ok {
		result["central_restricted"] = restricted
	}
	phases, _ := local["claude_callbacks"].(map[string]any)
	previous := probe.StartedAt
	for _, event := range []string{"SessionStart", "UserPromptSubmit", "PreToolUse", "Stop"} {
		phase, _ := phases[event].(map[string]any)
		stamp, _ := phase["last_observed_at"].(time.Time)
		matched := phase["status"] == "observed" && !stamp.Before(previous) && !stamp.After(now.Add(5*time.Second)) && phase["session_reference"] == reference && reference != ""
		previous = stamp
		if event == "UserPromptSubmit" {
			matched = matched && phase["probe_id"] == probe.ID
		}
		checks[event] = matched
		valid = valid && matched
	}
	if valid {
		result["status"] = "reporting_probe_observed"
	}
	if reason, ok := central["reason"]; ok {
		result["central_reason"] = reason
	}
	return result
}

func RunOnboarding(args []string) error {
	if len(args) == 0 {
		return errors.New("use onboarding begin or onboarding check [--require]")
	}
	switch args[0] {
	case "begin":
		if len(args) > 1 {
			return errors.New("onboarding begin takes no arguments")
		}
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return err
		}
		now := time.Now().UTC()
		probe := onboardingProbe{ID: hex.EncodeToString(random[:]), StartedAt: now, ExpiresAt: now.Add(15 * time.Minute)}
		if err := writeRuntimeState(probeStatePath(), probe); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"probe": probe, "prompt": "BAP-ONBOARDING-" + probe.ID + " Please run git status in this fixture repository, then describe the result.", "instructions": "Start a new supported Claude session after this command; paste the prompt yourself and allow the harmless tool only through the native client's normal approval flow. Then run onboarding check --require. No hook approvals are automated."})
	case "check":
		flags := flag.NewFlagSet("onboarding check", flag.ContinueOnError)
		require := flags.Bool("require", false, "Fail unless correlated reporting evidence is observed")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected onboarding check arguments")
		}
		info, err := os.Lstat(probeStatePath())
		if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
			return errors.New("no valid bounded local probe; run onboarding begin")
		}
		body, err := os.ReadFile(probeStatePath())
		if err != nil {
			return errors.New("no local probe; run onboarding begin")
		}
		var probe onboardingProbe
		if len(body) > 4096 || json.Unmarshal(body, &probe) != nil || !onboardingProbeID.MatchString(probe.ID) {
			return errors.New("invalid local onboarding probe")
		}
		now := time.Now().UTC()
		local := localOnboardingHealth(now)
		central := map[string]any{}
		if probe.ExpiresAt.After(now) {
			endpoint := config.ReportingEndpoint(config.ResolveEndpoints().ControlPlaneURL)
			query := url.Values{"probe_id": {probe.ID}, "started_at": {probe.StartedAt.Format(time.RFC3339Nano)}}
			client := httptransport.New(3 * time.Second)
			response, err := client.Get(endpoint + "/api/v1/onboarding/probe?" + query.Encode())
			if err != nil {
				central["reason"] = "control_plane_unreachable"
			} else {
				if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
					central["reason"] = "identity_rejected"
				} else if response.StatusCode != 200 {
					central["reason"] = "probe_service_unavailable"
				} else if json.NewDecoder(io.LimitReader(response.Body, 16384)).Decode(&central) != nil {
					central = map[string]any{"reason": "invalid_probe_response"}
				}
				response.Body.Close()
			}
		}
		result := evaluateProbe(probe, now, local, central)
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			return err
		}
		if *require && result["status"] != "reporting_probe_observed" {
			return fmt.Errorf("onboarding reporting probe incomplete: %s", result["status"])
		}
		return nil
	default:
		return errors.New("unknown onboarding command")
	}
}
