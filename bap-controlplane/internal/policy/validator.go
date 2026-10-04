package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
)

// ValidationError contains specific line and diagnostic message for Cedar syntax issues.
type ValidationError struct {
	Line    int    `json:"line"`
	Column  int    `json:"column,omitempty"`
	Message string `json:"message"`
}

// ValidationResult represents the output of a Cedar policy syntax check.
type ValidationResult struct {
	Valid       bool              `json:"valid"`
	PolicyCount int               `json:"policy_count"`
	Digest      string            `json:"digest"`
	Errors      []ValidationError `json:"errors"`
}

// Scenario represents a sample tool execution to test in the simulator.
type Scenario struct {
	ID               string `json:"id"`
	Executable       string `json:"executable"`
	FullCommand      string `json:"full_command"`
	Args             string `json:"args,omitempty"`
	EscapesWorkspace bool   `json:"escapes_workspace"`
}

// SimulationDiffItem tracks the evaluation delta between current and draft policies.
type SimulationDiffItem struct {
	ScenarioID      string `json:"scenario_id"`
	Command         string `json:"command"`
	CurrentDecision string `json:"current_decision"` // "ALLOW" or "DENY"
	DraftDecision   string `json:"draft_decision"`   // "ALLOW" or "DENY"
	CurrentReason   string `json:"current_reason,omitempty"`
	DraftReason     string `json:"draft_reason,omitempty"`
	DiffType        string `json:"diff_type"` // "ALLOWED_TO_DENIED", "DENIED_TO_ALLOWED", "UNCHANGED"
}

// SimulationReport summarizes the "What-If" sandbox execution.
type SimulationReport struct {
	TotalEvaluated   int                  `json:"total_evaluated"`
	CurrentAllowed   int                  `json:"current_allowed"`
	CurrentDenied    int                  `json:"current_denied"`
	DraftAllowed     int                  `json:"draft_allowed"`
	DraftDenied      int                  `json:"draft_denied"`
	ImpactDiffCount  int                  `json:"impact_diff_count"`
	AllowedToDenied  int                  `json:"allowed_to_denied"`
	DeniedToAllowed  int                  `json:"denied_to_allowed"`
	DiffItems        []SimulationDiffItem `json:"diff_items"`
	DraftPolicyValid bool                 `json:"draft_policy_valid"`
	DraftDigest      string               `json:"draft_digest"`
}

var lineRegex = regexp.MustCompile(`(?i)(?:line|at line)\s*(\d+)(?:,?\s*(?:col|column)\s*(\d+))?`)

// ValidateCedar checks Cedar policy code and schema for syntax correctness and schema compatibility.
func ValidateCedar(cedarCode, schemaJSON string) ValidationResult {
	trimmed := strings.TrimSpace(cedarCode)
	if trimmed == "" {
		return ValidationResult{
			Valid:  false,
			Errors: []ValidationError{{Line: 1, Message: "Policy cannot be empty"}},
		}
	}

	ps, err := cedar.NewPolicySetFromBytes("policy.cedar", []byte(cedarCode))
	if err != nil {
		errStr := err.Error()
		line := 1
		col := 0
		if m := lineRegex.FindStringSubmatch(errStr); len(m) > 1 {
			if l, e := strconv.Atoi(m[1]); e == nil {
				line = l
			}
			if len(m) > 2 && m[2] != "" {
				if c, e := strconv.Atoi(m[2]); e == nil {
					col = c
				}
			}
		}
		return ValidationResult{
			Valid:  false,
			Errors: []ValidationError{{Line: line, Column: col, Message: errStr}},
		}
	}

	// If schema provided, validate against it
	if strings.TrimSpace(schemaJSON) != "" {
		var s schema.Schema
		if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
			return ValidationResult{
				Valid:  false,
				Errors: []ValidationError{{Line: 1, Message: fmt.Sprintf("Schema JSON parse error: %v", err)}},
			}
		}
		if _, err := s.Resolve(); err != nil {
			return ValidationResult{
				Valid:  false,
				Errors: []ValidationError{{Line: 1, Message: fmt.Sprintf("Schema resolution error: %v", err)}},
			}
		}
	}

	hasher := sha256.New()
	hasher.Write([]byte(cedarCode))
	digest := hex.EncodeToString(hasher.Sum(nil))

	return ValidationResult{
		Valid:       true,
		PolicyCount: len(ps.Map()),
		Digest:      digest,
		Errors:      []ValidationError{},
	}
}

// EvaluateCommand evaluates a single command request against a Cedar PolicySet.
func EvaluateCommand(ps *cedar.PolicySet, executable, fullCommand, args string, escapesWorkspace bool) (bool, string) {
	normExec := strings.ToLower(strings.TrimSpace(executable))
	normFull := strings.ToLower(strings.TrimSpace(fullCommand))
	normArgs := strings.ToLower(strings.TrimSpace(args))

	req := cedar.Request{
		Principal: cedar.NewEntityUID("Agent", "Local"),
		Action:    cedar.NewEntityUID("Action", "Execute"),
		Resource:  cedar.NewEntityUID("Command", "CLI"),
		Context: cedar.NewRecord(cedar.RecordMap{
			cedar.String("executable"):        cedar.String(normExec),
			cedar.String("full_command"):      cedar.String(normFull),
			cedar.String("args"):              cedar.String(normArgs),
			cedar.String("escapes_workspace"): cedar.Boolean(escapesWorkspace),
		}),
	}

	entities := types.EntityMap{}
	decision, diag := cedar.Authorize(ps, entities, req)
	if decision == cedar.Allow {
		return true, "Allowed by Cedar policy"
	}

	var reason string
	if len(diag.Reasons) > 0 {
		var reasonList []string
		for _, r := range diag.Reasons {
			reasonList = append(reasonList, fmt.Sprintf("policy %s", r.PolicyID))
		}
		reason = fmt.Sprintf("Denial triggered by: %s", strings.Join(reasonList, ", "))
	} else if len(diag.Errors) > 0 {
		var errList []string
		for _, e := range diag.Errors {
			errList = append(errList, e.Message)
		}
		reason = fmt.Sprintf("Policy error: %s", strings.Join(errList, "; "))
	} else {
		reason = "Default deny (no permit policy matched)"
	}

	return false, reason
}

// SimulatePolicySandbox evaluates scenarios against both the active policy and a draft policy to produce a diff report.
func SimulatePolicySandbox(currentCedar, draftCedar string, scenarios []Scenario) (*SimulationReport, error) {
	// Parse current policy
	currentPS, err := cedar.NewPolicySetFromBytes("current.cedar", []byte(currentCedar))
	if err != nil {
		// Fallback to empty policy set if current is unparseable
		currentPS = cedar.NewPolicySet()
	}

	// Validate & parse draft policy
	draftValidation := ValidateCedar(draftCedar, "")
	if !draftValidation.Valid {
		return &SimulationReport{
			DraftPolicyValid: false,
			DiffItems:        []SimulationDiffItem{},
		}, fmt.Errorf("draft policy invalid: %s", draftValidation.Errors[0].Message)
	}

	draftPS, err := cedar.NewPolicySetFromBytes("draft.cedar", []byte(draftCedar))
	if err != nil {
		return nil, fmt.Errorf("failed to parse draft policy: %w", err)
	}

	report := &SimulationReport{
		TotalEvaluated:   len(scenarios),
		DraftPolicyValid: true,
		DraftDigest:      draftValidation.Digest,
		DiffItems:        make([]SimulationDiffItem, 0, len(scenarios)),
	}

	for _, sc := range scenarios {
		currAllowed, currReason := EvaluateCommand(currentPS, sc.Executable, sc.FullCommand, sc.Args, sc.EscapesWorkspace)
		draftAllowed, draftReason := EvaluateCommand(draftPS, sc.Executable, sc.FullCommand, sc.Args, sc.EscapesWorkspace)

		currDec := "DENY"
		if currAllowed {
			currDec = "ALLOW"
			report.CurrentAllowed++
		} else {
			report.CurrentDenied++
		}

		draftDec := "DENY"
		if draftAllowed {
			draftDec = "ALLOW"
			report.DraftAllowed++
		} else {
			report.DraftDenied++
		}

		diffType := "UNCHANGED"
		if currAllowed && !draftAllowed {
			diffType = "ALLOWED_TO_DENIED"
			report.ImpactDiffCount++
			report.AllowedToDenied++
		} else if !currAllowed && draftAllowed {
			diffType = "DENIED_TO_ALLOWED"
			report.ImpactDiffCount++
			report.DeniedToAllowed++
		}

		cmdDisplay := sc.FullCommand
		if cmdDisplay == "" {
			cmdDisplay = sc.Executable + " " + sc.Args
		}

		report.DiffItems = append(report.DiffItems, SimulationDiffItem{
			ScenarioID:      sc.ID,
			Command:         cmdDisplay,
			CurrentDecision: currDec,
			DraftDecision:   draftDec,
			CurrentReason:   currReason,
			DraftReason:     draftReason,
			DiffType:        diffType,
		})
	}

	return report, nil
}
