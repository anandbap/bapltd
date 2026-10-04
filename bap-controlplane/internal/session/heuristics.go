package session

import (
	"strings"
)

// PromptAnalysisResult contains heuristic semantic signals and risk scoring for agent prompts.
type PromptAnalysisResult struct {
	RiskScore  float64  `json:"risk_score"`
	RiskLevel  string   `json:"risk_level"` // "LOW", "ELEVATED", "CRITICAL"
	IsHighRisk bool     `json:"is_high_risk"`
	Signals    []string `json:"signals"`
	Evidence   []string `json:"evidence"`
}

type injectionRule struct {
	Signal  string
	Phrases []string
	Weight  float64
}

var injectionRules = []injectionRule{
	{
		Signal: "INSTRUCTION_OVERRIDE",
		Phrases: []string{
			"ignore previous instructions",
			"ignore all previous instructions",
			"ignore prior instructions",
			"disregard previous instructions",
			"disregard all instructions",
			"disregard prior instructions",
			"forget all instructions",
			"forget previous instructions",
			"override previous instructions",
			"override system prompt",
			"new system prompt:",
			"system prompt override",
		},
		Weight: 0.45,
	},
	{
		Signal: "JAILBREAK_PERSONA",
		Phrases: []string{
			"developer mode",
			"dan mode",
			"do anything now",
			"unrestricted ai",
			"jailbreak mode",
			"act as an uncensored",
			"bypass safety filters",
			"disable safety protocols",
		},
		Weight: 0.40,
	},
	{
		Signal: "GOVERNANCE_BYPASS",
		Phrases: []string{
			"bypass bap",
			"disable bap",
			"disable cedar",
			"bypass cedar",
			"disable guardrails",
			"disable security",
			"turn off security",
			"bypass pep",
			"skip authorization",
			"bypass policy",
			"fake grant",
		},
		Weight: 0.50,
	},
	{
		Signal: "CREDENTIAL_EXFILTRATION",
		Phrases: []string{
			"dump env",
			"printenv",
			"export env",
			"environment variables",
			"env variables",
			"cat /etc/shadow",
			"exfiltrate credentials",
			"steal tokens",
			"dump tokens",
			"send credentials to",
			"curl evil",
			"wget evil",
		},
		Weight: 0.40,
	},
	{
		Signal: "PROMPT_EXTRACTION",
		Phrases: []string{
			"reveal your prompt",
			"print your system prompt",
			"what were your original instructions",
			"repeat everything above",
			"print initial system instructions",
		},
		Weight: 0.30,
	},
}

// AnalyzePromptSemantics analyzes a prompt for semantic prompt injection patterns and computes risk metrics.
// IMPORTANT (Architectural Invariant I1): This is a risk signal and context, never authorization.
func AnalyzePromptSemantics(prompt string) PromptAnalysisResult {
	norm := strings.ToLower(prompt)
	result := PromptAnalysisResult{
		RiskScore:  0.0,
		RiskLevel:  "LOW",
		IsHighRisk: false,
		Signals:    []string{},
		Evidence:   []string{},
	}

	if strings.TrimSpace(norm) == "" {
		return result
	}

	totalWeight := 0.0
	for _, rule := range injectionRules {
		matched := false
		for _, phrase := range rule.Phrases {
			if strings.Contains(norm, phrase) {
				if !matched {
					result.Signals = append(result.Signals, rule.Signal)
					totalWeight += rule.Weight
					matched = true
				}
				result.Evidence = append(result.Evidence, rule.Signal+": "+phrase)
			}
		}
	}

	if totalWeight > 1.0 {
		totalWeight = 1.0
	}
	result.RiskScore = totalWeight

	if result.RiskScore >= 0.70 {
		result.RiskLevel = "CRITICAL"
		result.IsHighRisk = true
	} else if result.RiskScore >= 0.40 {
		result.RiskLevel = "ELEVATED"
		result.IsHighRisk = true
	} else {
		result.RiskLevel = "LOW"
		result.IsHighRisk = false
	}

	return result
}
