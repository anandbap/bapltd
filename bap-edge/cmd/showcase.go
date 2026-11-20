package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"bap-edge/internal/pinning"
	"bap-edge/pkg/types"
)

// Diagnostic evidence is deliberately separate from production audit ingestion.
// Imported reports are local, untrusted artifacts, never execution authority.
type showcaseEvidence struct {
	RunID       string    `json:"demo_run_id"`
	SessionID   string    `json:"session_id"`
	ScenarioID  string    `json:"scenario_id"`
	ActionID    string    `json:"action_id"`
	EventID     string    `json:"event_id"`
	Layer       int       `json:"layer"`
	Producer    string    `json:"producer"`
	Timestamp   time.Time `json:"timestamp"`
	Status      string    `json:"status"`
	Decision    string    `json:"decision"`
	Explanation string    `json:"explanation"`
	Diagnostic  bool      `json:"diagnostic"`
	Details     any       `json:"details,omitempty"`
}
type showcaseReport struct {
	Client         string             `json:"client"`
	Schema         string             `json:"schema"`
	RunID          string             `json:"demo_run_id"`
	SessionID      string             `json:"session_id"`
	Diagnostic     bool               `json:"diagnostic"`
	OverrideActive bool               `json:"developer_override_active"`
	Validation     string             `json:"validation"`
	Evidence       []showcaseEvidence `json:"evidence"`
}

var showcaseRunPattern = regexp.MustCompile(`^demo-[a-f0-9]{32}$`)

func isShowcaseDiagnosticContext() bool {
	run := os.Getenv("BAP_DEMO_RUN_ID")
	return os.Getenv("BAP_DIAGNOSTIC_SHOWCASE") == "1" && showcaseRunPattern.MatchString(run) && os.Getenv("BAP_SESSION_ID") == "diagnostic-"+strings.TrimPrefix(run, "demo-")
}

type showcaseHookReceipt struct {
	Diagnostic bool                    `json:"diagnostic"`
	RunID      string                  `json:"demo_run_id"`
	SessionID  string                  `json:"session_id"`
	Client     string                  `json:"client"`
	Decision   string                  `json:"decision"`
	Receipt    *types.ExecutionReceipt `json:"receipt"`
}

// A private breadcrumb keeps diagnostic fields OUT of native vendor responses.
// Some clients reject every unknown JSON/protobuf field.
func recordShowcaseHookReceipt(client, decision string, receipt *types.ExecutionReceipt) {
	run := os.Getenv("BAP_DEMO_RUN_ID")
	if !isShowcaseDiagnosticContext() {
		return
	}
	session := "diagnostic-" + strings.TrimPrefix(run, "demo-")
	if os.Getenv("BAP_SESSION_ID") != session {
		return
	}
	cwd, err := os.Getwd()
	if err != nil {
		return
	}
	path := filepath.Join(cwd, ".bap", "showcase", run+"-hook-receipt.json")
	if claudeWorkspacePath(cwd, path) != nil {
		return
	}
	data, err := json.Marshal(showcaseHookReceipt{true, run, session, normalizeClientAppID(client), decision, receipt})
	if err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	_, _ = f.Write(data)
	_ = f.Close()
}

func showcaseHook(r *showcaseReport, exe string) {
	payload, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": r.SessionID, "tool_use_id": r.RunID + "-hook-status", "tool_name": "Bash", "tool_input": map[string]any{"command": "git status --short"}})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, exe, "plugin", "adapter", "--client", r.Client, "--event", "PreToolUse")
	c.Stdin = bytes.NewReader(payload)
	c.Env = append(os.Environ(), "BAP_DIAGNOSTIC_SHOWCASE=1", "BAP_DEMO_RUN_ID="+r.RunID, "BAP_SESSION_ID="+r.SessionID, "LTD_SOURCE="+r.Client)
	_, runErr := c.Output()
	cwd, _ := os.Getwd()
	path := filepath.Join(cwd, ".bap", "showcase", r.RunID+"-hook-receipt.json")
	data, err := os.ReadFile(path)
	var response showcaseHookReceipt
	producer := "edge/" + r.Client + "-adapter"
	owned := err == nil && json.Unmarshal(data, &response) == nil && response.Diagnostic && response.RunID == r.RunID && response.SessionID == r.SessionID && response.Client == normalizeClientAppID(r.Client)
	if owned {
		_ = os.Remove(path)
	}
	if !owned || response.Receipt == nil || response.Receipt.SessionID != r.SessionID || (response.Decision != "allow" && response.Decision != "deny") {
		r.add(1, "hook", "fixture-callback", producer, "unavailable", "no_verified_receipt", fmt.Sprintf("Supported callback handler returned no attributable receipt (%v; %v). No native-host delivery claimed.", err, runErr), response)
		// Leave unknown/mismatching ownership untouched.
	} else {
		status := "participated"
		if response.Decision == "deny" {
			status = "blocked"
		}
		r.add(1, "hook", "fixture-callback", producer, status, response.Decision, "Diagnostic fixture exercised this client's actual callback handler with harmless git inspection. Adapter behavior does not prove native-host invocation or live endpoint acceptance.", response.Receipt)
	}
	for layer := 2; layer <= 5; layer++ {
		r.add(layer, "hook", "fixture-callback", "diagnostic-runner", "not_reached", "not_exercised", "This callback scenario does not establish independent participation of this layer.", nil)
	}
}

func (r *showcaseReport) add(layer int, scenario, action, producer, status, decision, reason string, details any) {
	r.Evidence = append(r.Evidence, showcaseEvidence{RunID: r.RunID, SessionID: r.SessionID, ScenarioID: scenario, ActionID: action,
		EventID: fmt.Sprintf("%s:%s:layer-%d:%s", scenario, action, layer, producer), Layer: layer, Producer: producer, Timestamp: time.Now().UTC(), Status: status,
		Decision: decision, Explanation: reason, Diagnostic: true, Details: details})
}

func runShowcaseIntegrity(r *showcaseReport, dir string) error {
	path := filepath.Join(dir, "integrity-fixture.txt")
	if err := os.WriteFile(path, []byte("BAP diagnostic fixture v1\n"), 0600); err != nil {
		return err
	}
	manifest := pinning.NewManifest() // Never load/save production pins.
	if _, err := manifest.PinFile("diagnostic:fixture", "diagnostic", path, "diagnostic-runner", nil); err != nil {
		return err
	}
	for _, mismatch := range []bool{false, true} {
		action, expected := "matching", "match"
		if mismatch {
			action, expected = "mismatching", "mismatch"
			if err := os.WriteFile(path, []byte("BAP diagnostic fixture v2\n"), 0600); err != nil {
				return err
			}
		}
		result := manifest.VerifyAsset("diagnostic:fixture")
		decision, status := "match", "participated"
		if !result.Matches {
			decision = "mismatch"
		}
		if decision != expected {
			status = "failed"
		}
		r.add(3, "integrity", action, "edge/pinning.VerifyAsset", status, decision, "Disposable fixture verified by the production pinning verifier; production manifests untouched.", result)
	}
	return nil
}

func runShowcaseRisk(r *showcaseReport) {
	state := &sessionRiskState{SessionID: r.SessionID}
	for i := 1; i <= 4; i++ {
		advanceSessionRisk(state, "DIAGNOSTIC: simulated denial", time.Now().UTC())
		snapshot := *state
		snapshot.AttemptHistory = append([]string(nil), state.AttemptHistory...)
		r.add(4, "risk", fmt.Sprintf("denial-%d", i), "edge/advanceSessionRisk", "participated", state.ThreatLevel,
			"Diagnostic denial input evaluated by the enforcement risk transition; state exists only in this run's memory.", snapshot)
	}
}

func showcaseBroker(r *showcaseReport, exe string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, exe, "exec", "--json", "git status --short")
	c.Env = append(os.Environ(), "BAP_SESSION_ID="+r.SessionID, "BAP_DEMO_RUN_ID="+r.RunID, "BAP_SCENARIO_ID=broker", "BAP_ACTION_ID=git-status", "LTD_SOURCE="+r.Client)
	out, err := c.Output()
	var response types.ExecResponse
	if json.Unmarshal(bytes.TrimSpace(out), &response) != nil || response.Receipt == nil || response.Receipt.SessionID != r.SessionID {
		r.add(2, "broker", "git-status", "edge/exec", "unavailable", "no_verified_receipt", fmt.Sprintf("Broker returned no attributable JSON receipt (%v). No execution claimed.", err), nil)
		return
	}
	status := "participated"
	if !response.Allowed {
		status = "blocked"
	}
	reason := "Broker decision receipt received."
	if response.Receipt.Result == "ALLOWED_EXECUTED" && response.ExitCode == 0 {
		reason = "Approved git inspection executed; broker execution receipt received."
	}
	r.add(2, "broker", "git-status", "edge/exec", status, response.Receipt.Result, reason, response.Receipt)
}

func RunShowcase(args []string) error {
	fs := flag.NewFlagSet("showcase", flag.ContinueOnError)
	output := fs.String("output", "", "Workspace JSON report path")
	client := fs.String("client", "claude-code", "Client: claude-code, codex, antigravity, copilot, opencode")
	withoutHooks := fs.Bool("without-hooks", false, "Omit callback fixture; independently exercise downstream boundaries without disabling any defense")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: bapedge showcase [--output workspace-path]")
	}
	app := normalizeClientAppID(*client)
	switch app {
	case "claude-code", "codex", "antigravity", "copilot", "opencode":
	default:
		return fmt.Errorf("unsupported diagnostic client %q", *client)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	id := hex.EncodeToString(nonce)
	r := showcaseReport{Schema: "bap-defense-showcase/v1", RunID: "demo-" + id, SessionID: "diagnostic-" + id, Diagnostic: true, Validation: "Isolated component diagnostics; not live endpoint acceptance."}
	r.Client = app
	defer func() { _ = EnsureSessionEnded(r.SessionID, "diagnostic run finished") }()
	r.OverrideActive, _ = configuredDevOverride()
	if r.OverrideActive {
		r.Validation = "DEVELOPER OVERRIDE ACTIVE: unsuitable for normal enforcement validation."
	}
	root := filepath.Join(cwd, ".bap", "showcase")
	if err := claudeWorkspacePath(cwd, root); err != nil {
		return err
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(root, "fixture-")
	if err != nil {
		return err
	}
	// Only this known fixture is removed; no recursive cleanup of arbitrary paths.
	defer func() { _ = os.Remove(filepath.Join(dir, "integrity-fixture.txt")); _ = os.Remove(dir) }()
	if err := runShowcaseIntegrity(&r, dir); err != nil {
		r.add(3, "integrity", "fixture-verification", "edge/pinning.VerifyAsset", "unavailable", "fixture_error", err.Error(), nil)
	}
	runShowcaseRisk(&r)
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if *withoutHooks {
		r.add(1, "hook", "not-invoked", "diagnostic-runner", "unavailable", "no_callback_evidence", "The callback fixture was not invoked. This is not evidence that a host disabled hooks; independent downstream diagnostics still run.", nil)
	} else {
		showcaseHook(&r, exe)
	}
	showcaseBroker(&r, exe)
	r.add(5, "attestation", "server-verification", "control-plane", "unavailable", "not_requested", "Run the authenticated control-plane diagnostic from the showcase UI. An edge process cannot claim a server verdict.", nil)
	path := *output
	if path == "" {
		path = filepath.Join(root, r.RunID+".json")
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return err
	}
	if err := claudeWorkspacePath(cwd, path); err != nil {
		return err
	}
	rel, err := filepath.Rel(cwd, path)
	if err != nil || rel == ".." || (len(rel) > 3 && rel[:3] == ".."+string(os.PathSeparator)) {
		return fmt.Errorf("report output must stay inside workspace")
	}
	// Create exclusively: never overwrite arbitrary workspace files.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	err = enc.Encode(r)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	fmt.Println(path)
	return nil
}
