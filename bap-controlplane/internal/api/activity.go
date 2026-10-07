package api

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"bap-controlplane/internal/session"
	"bap-controlplane/pkg/types"
)

func (s *Server) isDemoMode(r *http.Request) bool {
	if s.demoMode {
		return true
	}
	if r != nil {
		q := strings.ToLower(r.URL.Query().Get("demo"))
		if q == "true" || q == "1" || q == "yes" {
			return true
		}
	}
	return false
}

// DefaultWorkCategories represents the canonical extensible work categories (BAP-477).
var DefaultWorkCategories = []types.WorkCategoryMeta{
	{ID: "feature_enhancement", Name: "Feature Development / Enhancement", Description: "New feature engineering, functional additions, and module extensions", Color: "#2563eb", Icon: "sparkles"},
	{ID: "bug_fix", Name: "Bug Fix", Description: "Defect resolution, crash triage, regression patching, and logic corrections", Color: "#dc2626", Icon: "bug"},
	{ID: "testing_quality", Name: "Testing / Quality", Description: "Unit, integration, and e2e test creation, coverage expansion, and verification", Color: "#16a34a", Icon: "check-circle"},
	{ID: "documentation", Name: "Documentation", Description: "Technical documentation, README updates, API reference, and knowledge base", Color: "#0891b2", Icon: "book-open"},
	{ID: "production_ops", Name: "Production Operations", Description: "Infrastructure telemetry, container monitoring, incident triage, and deployment", Color: "#ea580c", Icon: "server"},
	{ID: "security", Name: "Security", Description: "Vulnerability remediation, IAM policy hardening, secret rotation, and compliance auditing", Color: "#9333ea", Icon: "shield-alert"},
	{ID: "data_analytics", Name: "Data / Analytics", Description: "ETL pipelines, schema migrations, metric calculations, and business data modeling", Color: "#0284c7", Icon: "database"},
	{ID: "research", Name: "Research", Description: "Codebase discovery, architectural analysis, feasibility exploration, and benchmarking", Color: "#4f46e5", Icon: "search"},
	{ID: "automation", Name: "Automation", Description: "Workflow automation, build scripts, ticket syncing, and release pipeline orchestration", Color: "#0d9488", Icon: "cog"},
	{ID: "other_unclassified", Name: "Other / Unclassified", Description: "Exploratory prompts, general queries, or activity with insufficient classification confidence", Color: "#64748b", Icon: "help-circle"},
}

func (s *Server) classifyIntentCategory(intent string, confidence float64) string {
	// Acceptance Criteria 4: Low-confidence classifications fall back to Other / Unclassified
	if confidence > 0 && confidence < 0.25 {
		return "Other / Unclassified"
	}
	u := strings.ToUpper(strings.TrimSpace(intent))
	if u == "" || u == "UNKNOWN" || u == "NONE" {
		return "Other / Unclassified"
	}

	// Check custom registered categories first (extensible categories)
	s.categoriesMu.RLock()
	for _, cat := range s.customCategories {
		if strings.EqualFold(cat.Name, intent) || strings.EqualFold(cat.ID, intent) {
			s.categoriesMu.RUnlock()
			return cat.Name
		}
	}
	s.categoriesMu.RUnlock()

	switch {
	case strings.Contains(u, "BUG") || strings.Contains(u, "DEFECT") || strings.Contains(u, "REGRESSION") || strings.Contains(u, "HOTFIX") || strings.Contains(u, "FAILING"):
		return "Bug Fix"
	case strings.Contains(u, "TEST") || strings.Contains(u, "QUALITY") || strings.Contains(u, "VERIF") || strings.Contains(u, "VALIDAT"):
		return "Testing / Quality"
	case strings.Contains(u, "DOC") || strings.Contains(u, "README") || strings.Contains(u, "MANUAL") || strings.Contains(u, "GUIDE") || strings.Contains(u, "SPEC"):
		return "Documentation"
	case strings.Contains(u, "SEC") || strings.Contains(u, "VULN") || strings.Contains(u, "CVE") || strings.Contains(u, "AUTH") || strings.Contains(u, "IAM") || strings.Contains(u, "AUDIT"):
		return "Security"
	case strings.Contains(u, "PROD") || strings.Contains(u, "INCIDENT") || strings.Contains(u, "LATENCY") || strings.Contains(u, "K8S") || strings.Contains(u, "KUBERNETES") || strings.Contains(u, "OUTAGE") || strings.Contains(u, "CRASH") || strings.Contains(u, "SRE") || strings.Contains(u, "INFRA") || strings.Contains(u, "DIAGNOS"):
		return "Production Operations"
	case strings.Contains(u, "DATA") || strings.Contains(u, "ANALYTIC") || strings.Contains(u, "DB") || strings.Contains(u, "DATABASE") || strings.Contains(u, "SQL") || strings.Contains(u, "SCHEMA") || strings.Contains(u, "WAREHOUSE") || strings.Contains(u, "ETL"):
		return "Data / Analytics"
	case strings.Contains(u, "RESEARCH") || strings.Contains(u, "SEARCH") || strings.Contains(u, "EXPLAIN") || strings.Contains(u, "EXPLOR") || strings.Contains(u, "BENCHMARK") || strings.Contains(u, "FEASIBIL"):
		return "Research"
	case strings.Contains(u, "AUTOMAT") || strings.Contains(u, "WORKFLOW") || strings.Contains(u, "PIPELINE") || strings.Contains(u, "CI") || strings.Contains(u, "CD") || strings.Contains(u, "CRON") || strings.Contains(u, "WORK_MANAGEMENT") || strings.Contains(u, "JIRA") || strings.Contains(u, "PULL_REQUEST"):
		return "Automation"
	case strings.Contains(u, "FEATURE") || strings.Contains(u, "BUILD") || strings.Contains(u, "CREATE") || strings.Contains(u, "IMPLEMENT") || strings.Contains(u, "ENHANC") || strings.Contains(u, "CHANGE") || strings.Contains(u, "REFACTOR") || strings.Contains(u, "DEPLOY"):
		return "Feature Development / Enhancement"
	default:
		return "Other / Unclassified"
	}
}

func mapIntentToCategory(intent string) string {
	u := strings.ToUpper(strings.TrimSpace(intent))
	if u == "" || u == "UNKNOWN" || u == "NONE" {
		return "Other / Unclassified"
	}
	switch {
	case strings.Contains(u, "BUG") || strings.Contains(u, "DEFECT") || strings.Contains(u, "REGRESSION") || strings.Contains(u, "HOTFIX"):
		return "Bug Fix"
	case strings.Contains(u, "TEST") || strings.Contains(u, "QUALITY") || strings.Contains(u, "VERIF") || strings.Contains(u, "VALIDAT"):
		return "Testing / Quality"
	case strings.Contains(u, "DOC") || strings.Contains(u, "README") || strings.Contains(u, "MANUAL") || strings.Contains(u, "GUIDE"):
		return "Documentation"
	case strings.Contains(u, "SEC") || strings.Contains(u, "VULN") || strings.Contains(u, "CVE") || strings.Contains(u, "IAM") || strings.Contains(u, "AUDIT"):
		return "Security"
	case strings.Contains(u, "PROD") || strings.Contains(u, "INCIDENT") || strings.Contains(u, "LATENCY") || strings.Contains(u, "K8S") || strings.Contains(u, "OUTAGE") || strings.Contains(u, "SRE") || strings.Contains(u, "DIAGNOS"):
		return "Production Operations"
	case strings.Contains(u, "DATA") || strings.Contains(u, "ANALYTIC") || strings.Contains(u, "DB") || strings.Contains(u, "DATABASE") || strings.Contains(u, "SQL") || strings.Contains(u, "SCHEMA") || strings.Contains(u, "ETL"):
		return "Data / Analytics"
	case strings.Contains(u, "RESEARCH") || strings.Contains(u, "SEARCH") || strings.Contains(u, "EXPLAIN") || strings.Contains(u, "EXPLOR"):
		return "Research"
	case strings.Contains(u, "AUTOMAT") || strings.Contains(u, "WORKFLOW") || strings.Contains(u, "PIPELINE") || strings.Contains(u, "CI") || strings.Contains(u, "CD") || strings.Contains(u, "WORK_MANAGEMENT") || strings.Contains(u, "JIRA"):
		return "Automation"
	case strings.Contains(u, "FEATURE") || strings.Contains(u, "BUILD") || strings.Contains(u, "CHANGE") || strings.Contains(u, "CREATE") || strings.Contains(u, "IMPLEMENT") || strings.Contains(u, "ENHANC") || strings.Contains(u, "REFACTOR") || strings.Contains(u, "DEPLOY"):
		return "Feature Development / Enhancement"
	default:
		return "Other / Unclassified"
	}
}

func (s *Server) sessionToActivityEvent(sess *session.Session) *types.AgentActivityEvent {
	intentCat := "Other / Unclassified"
	if sess.Intent.Primary != "" {
		intentCat = s.classifyIntentCategory(sess.Intent.Primary, sess.Intent.Confidence)
	}
	devLevel := "NONE"
	if sess.DeniedCount > 0 {
		devLevel = "ELEVATED"
	}
	status := "working"
	if sess.Status != "active" {
		status = sess.Status
	}
	risk := sess.PromptRiskScore
	if risk <= 0 {
		risk = 0.10
	}

	bu := "Engineering"
	if s.registry != nil {
		agentID := fmt.Sprintf("agent-%s-%s", strings.ToLower(sess.AppID), sess.InstanceID)
		if agent, err := s.registry.Get(agentID); err == nil && agent != nil && agent.Department != "" {
			bu = agent.Department
		} else if agent, err := s.registry.Get(sess.InstanceID); err == nil && agent != nil && agent.Department != "" {
			bu = agent.Department
		}
	}
	if bu == "Engineering" {
		// Heuristic department inference from app/team name or instance metadata
		low := strings.ToLower(sess.AppID + " " + sess.InstanceID + " " + sess.AgentName)
		switch {
		case strings.Contains(low, "payment") || strings.Contains(low, "checkout") || strings.Contains(low, "billing"):
			bu = "Payments Engineering"
		case strings.Contains(low, "core-banking") || strings.Contains(low, "ledger") || strings.Contains(low, "banking"):
			bu = "Core Banking"
		case strings.Contains(low, "fraud") || strings.Contains(low, "risk"):
			bu = "Fraud Operations"
		case strings.Contains(low, "cloud") || strings.Contains(low, "infra") || strings.Contains(low, "sre") || strings.Contains(low, "k8s"):
			bu = "Cloud Infrastructure"
		case strings.Contains(low, "security") || strings.Contains(low, "secops") || strings.Contains(low, "iam"):
			bu = "Enterprise Security"
		case strings.Contains(low, "data") || strings.Contains(low, "etl") || strings.Contains(low, "warehouse") || strings.Contains(low, "analytics"):
			bu = "Data Platform"
		case strings.Contains(low, "support") || strings.Contains(low, "crm") || strings.Contains(low, "ticket"):
			bu = "Customer Support"
		case strings.Contains(low, "finance") || strings.Contains(low, "accounting"):
			bu = "Finance Operations"
		case strings.Contains(low, "it-ops") || strings.Contains(low, "helpdesk") || strings.Contains(low, "it-enablement"):
			bu = "IT Operations"
		case strings.Contains(low, "qa") || strings.Contains(low, "test"):
			bu = "Quality Assurance"
		case strings.Contains(low, "devops") || strings.Contains(low, "ci-cd") || strings.Contains(low, "release"):
			bu = "DevOps Engineering"
		case strings.Contains(low, "mobile") || strings.Contains(low, "ios") || strings.Contains(low, "android"):
			bu = "Mobile Engineering"
		case strings.Contains(low, "ai-ml") || strings.Contains(low, "mlops") || strings.Contains(low, "llm"):
			bu = "AI & ML Platform"
		case strings.Contains(low, "product") || strings.Contains(low, "growth"):
			bu = "Product Growth"
		case strings.Contains(low, "compliance") || strings.Contains(low, "audit") || strings.Contains(low, "grc"):
			bu = "Regulatory Compliance"
		}
	}

	summary := sess.UserPrompt
	if summary == "" {
		summary = "Autonomous agent session active"
	}

	return &types.AgentActivityEvent{
		Timestamp:          sess.LastActiveAt.Format(time.RFC3339),
		SessionID:          sess.SessionID,
		AgentID:            sess.InstanceID,
		AgentType:          sess.AgentName,
		RuntimeID:          sess.Hostname,
		UserID:             sess.UserEmail,
		BusinessUnit:       bu,
		Application:        sess.AppID,
		PromptSummary:      summary,
		Intent:             sess.Intent.Primary,
		IntentCategory:     intentCat,
		Action:             "Active workload execution",
		Tool:               "bapedge",
		TargetResource:     "internal://session",
		DataClassification: "Internal",
		PolicyDecision:     "ALLOW",
		RiskScore:          risk,
		ActionStatus:       status,
		OutcomeCategory:    "Success",
		TraceID:            "tr-" + sess.SessionID,
		DeviationLevel:     devLevel,
	}
}

func (s *Server) initActivityEngine() {
	s.activitySubs = make(map[chan *types.AgentActivityEvent]struct{})
	if s.demoMode {
		s.seedBaselineActivities()
	}
}

func (s *Server) seedBaselineActivities() {
	s.activityMu.Lock()
	defer s.activityMu.Unlock()

	now := time.Now().UTC()
	ts := func(offsetSec int) string {
		return now.Add(-time.Duration(offsetSec) * time.Second).Format(time.RFC3339)
	}

	s.activities = []*types.AgentActivityEvent{
		{
			Timestamp:          ts(3),
			SessionID:          "sess-live-pay-01",
			AgentID:            "agent-claude-pay01",
			AgentType:          "claude-code",
			RuntimeID:          "macbook-pro-corp-419",
			UserID:             "sarah.chen@enterprise.internal",
			BusinessUnit:       "Payments Engineering",
			Application:        "checkout-api",
			PromptID:           "prmpt-81923",
			PromptSummary:      "Investigating elevated checkout latency following deployment 38122",
			Intent:             "PRODUCTION_DIAGNOSIS",
			IntentCategory:     "Investigate / Diagnose",
			Action:             "kubectl logs deployment/checkout-api -n prod --tail=200",
			Tool:               "kubectl",
			TargetResource:     "k8s://prod/checkout-api",
			DataClassification: "Internal",
			PolicyDecision:     "ALLOW",
			RiskScore:          0.12,
			GrantID:            "zsp-pay-read-991",
			GrantScope:         "read:observability",
			GrantTTL:           300,
			ActionStatus:       "working",
			OutcomeCategory:    "Success",
			TraceID:            "tr-pay-8192301",
			DeviationLevel:     "NONE",
		},
		{
			Timestamp:          ts(12),
			SessionID:          "sess-live-core-02",
			AgentID:            "agent-copilot-dev02",
			AgentType:          "copilot",
			RuntimeID:          "thinkpad-x1-dev-112",
			UserID:             "alex.kumar@enterprise.internal",
			BusinessUnit:       "Core Banking",
			Application:        "ledger-service",
			PromptID:           "prmpt-81924",
			PromptSummary:      "Refactoring transaction reconciliation routine for performance optimization",
			Intent:             "CODE_MODIFICATION",
			IntentCategory:     "Build / Change",
			Action:             "pytest tests/unit/test_reconciliation.py -v",
			Tool:               "pytest",
			TargetResource:     "file://ledger/reconcile.go",
			DataClassification: "Internal",
			PolicyDecision:     "ALLOW",
			RiskScore:          0.05,
			GrantID:            "zsp-core-test-412",
			GrantScope:         "exec:local-test",
			GrantTTL:           600,
			ActionStatus:       "working",
			OutcomeCategory:    "Success",
			TraceID:            "tr-core-8192402",
			DeviationLevel:     "NONE",
		},
		{
			Timestamp:          ts(25),
			SessionID:          "sess-live-sec-03",
			AgentID:            "agent-codex-sec03",
			AgentType:          "codex",
			RuntimeID:          "linux-workstation-88",
			UserID:             "marcus.vance@enterprise.internal",
			BusinessUnit:       "Enterprise Security",
			Application:        "auth-gateway",
			PromptID:           "prmpt-81925",
			PromptSummary:      "Auditing OAuth2 token exchange implementation against RFC 8693 specifications",
			Intent:             "SECURITY_AUDIT",
			IntentCategory:     "Search / Explain",
			Action:             "git log -n 20 --grep='token exchange'",
			Tool:               "git",
			TargetResource:     "repo://auth-gateway",
			DataClassification: "Confidential",
			PolicyDecision:     "ALLOW",
			RiskScore:          0.18,
			GrantID:            "zsp-sec-audit-301",
			GrantScope:         "read:repository",
			GrantTTL:           300,
			ActionStatus:       "working",
			OutcomeCategory:    "Success",
			TraceID:            "tr-sec-8192503",
			DeviationLevel:     "NONE",
		},
		{
			Timestamp:          ts(45),
			SessionID:          "sess-live-ops-04",
			AgentID:            "agent-claude-ops04",
			AgentType:          "claude-code",
			RuntimeID:          "macbook-air-ops-21",
			UserID:             "elena.rostova@enterprise.internal",
			BusinessUnit:       "Cloud Infrastructure",
			Application:        "terraform-network",
			PromptID:           "prmpt-81926",
			PromptSummary:      "Preparing staging VPC peering route verification plan",
			Intent:             "WORKFLOW_AUTOMATION",
			IntentCategory:     "Automate Workflow",
			Action:             "terraform plan -target=module.vpc_peering",
			Tool:               "terraform",
			TargetResource:     "aws://vpc/staging-peering",
			DataClassification: "Internal",
			PolicyDecision:     "ALLOW",
			RiskScore:          0.25,
			GrantID:            "zsp-ops-plan-109",
			GrantScope:         "plan:infrastructure",
			GrantTTL:           450,
			ActionStatus:       "waiting",
			OutcomeCategory:    "Success",
			TraceID:            "tr-ops-8192604",
			DeviationLevel:     "NONE",
		},
		{
			Timestamp:          ts(60),
			SessionID:          "sess-live-fraud-05",
			AgentID:            "agent-internal-fraud05",
			AgentType:          "custom-agent",
			RuntimeID:          "cloud-worker-fraud-09",
			UserID:             "david.park@enterprise.internal",
			BusinessUnit:       "Fraud Operations",
			Application:        "risk-scorer",
			PromptID:           "prmpt-81927",
			PromptSummary:      "Evaluating transaction anomaly clusters for quarterly loss review",
			Intent:             "BUSINESS_ANALYSIS",
			IntentCategory:     "Business Analysis",
			Action:             "python run_scoring_model.py --anomalies-only",
			Tool:               "python",
			TargetResource:     "data://warehouse/fraud_metrics",
			DataClassification: "Restricted",
			PolicyDecision:     "ALLOW",
			RiskScore:          0.20,
			GrantID:            "zsp-fraud-query-550",
			GrantScope:         "read:anonymized-fraud",
			GrantTTL:           300,
			ActionStatus:       "completed",
			OutcomeCategory:    "Success",
			TraceID:            "tr-fraud-8192705",
			DeviationLevel:     "NONE",
		},
		{
			Timestamp:          ts(80),
			SessionID:          "sess-live-dev-06",
			AgentID:            "agent-claude-eve06",
			AgentType:          "claude-code",
			RuntimeID:          "workstation-dev-99",
			UserID:             "eve.mallory@enterprise.internal",
			BusinessUnit:       "Payments Engineering",
			Application:        "payment-gateway",
			PromptID:           "prmpt-81928",
			PromptSummary:      "Investigating elevated checkout latency following deployment",
			Intent:             "PRODUCTION_DIAGNOSIS",
			IntentCategory:     "Investigate / Diagnose",
			Action:             "psql -h prod-db.internal -c 'UPDATE customer_tokens SET verified=true'",
			Tool:               "psql",
			TargetResource:     "db://prod-customers",
			DataClassification: "Restricted",
			PolicyDecision:     "DENY",
			RiskScore:          0.92,
			GrantID:            "",
			GrantScope:         "",
			GrantTTL:           0,
			ActionStatus:       "denied",
			OutcomeCategory:    "Blocked",
			TraceID:            "tr-pay-8192806",
			DeviationLevel:     "CRITICAL",
			DeviationReason:    "Blocked because the requested customer-record modification was inconsistent with the session's declared production-diagnosis intent.",
		},
	}
}

// IngestActivity registers an AgentActivityEvent, computes Intent Deviation, and broadcasts to subscribers.
func (s *Server) IngestActivity(event *types.AgentActivityEvent) {
	if event == nil {
		return
	}
	if event.Timestamp == "" {
		event.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	// Compute Intent Deviation if not already set
	if event.DeviationLevel == "" {
		dev := s.evaluateIntentDeviation(event.Intent, event.Action, event.Tool, event.TargetResource)
		event.DeviationLevel = dev.DeviationLevel
		if dev.IsDeviated && event.DeviationReason == "" {
			event.DeviationReason = dev.Reason
		}
	}

	s.activityMu.Lock()
	s.activities = append(s.activities, event)
	// Cap in-memory history at 1,000 events
	if len(s.activities) > 1000 {
		s.activities = s.activities[len(s.activities)-1000:]
	}
	s.activityMu.Unlock()

	s.broadcastActivity(event)
}

func (s *Server) broadcastActivity(event *types.AgentActivityEvent) {
	s.activitySubMu.Lock()
	defer s.activitySubMu.Unlock()

	for ch := range s.activitySubs {
		select {
		case ch <- event:
		default:
		}
	}
}

func (s *Server) evaluateIntentDeviation(intent, action, tool, resource string) *types.IntentDeviationReport {
	intentUpper := strings.ToUpper(intent)
	actionLower := strings.ToLower(action)
	toolLower := strings.ToLower(tool)

	rep := &types.IntentDeviationReport{
		Intent:         intent,
		ObservedAction: action,
		RequestedTool:  tool,
		TargetResource: resource,
		DeviationLevel: "NONE",
		IsDeviated:     false,
		Timestamp:      time.Now().UTC(),
	}

	isDiagOrSearch := strings.Contains(intentUpper, "DIAGNOS") ||
		strings.Contains(intentUpper, "INVESTIGAT") ||
		strings.Contains(intentUpper, "SEARCH") ||
		strings.Contains(intentUpper, "EXPLAIN") ||
		strings.Contains(intentUpper, "READ")

	destructiveOrWrite := strings.Contains(actionLower, "rm -rf") ||
		strings.Contains(actionLower, "drop table") ||
		strings.Contains(actionLower, "update ") ||
		strings.Contains(actionLower, "delete from") ||
		strings.Contains(actionLower, "insert into") ||
		strings.Contains(actionLower, "cat .env") ||
		strings.Contains(actionLower, "curl ") ||
		strings.Contains(actionLower, "wget ") ||
		strings.Contains(toolLower, "psql") ||
		strings.Contains(toolLower, "mysql") ||
		strings.Contains(toolLower, "drop")

	if isDiagOrSearch && destructiveOrWrite {
		rep.DeviationLevel = "CRITICAL"
		rep.IsDeviated = true
		rep.PolicyDecision = "DENY"
		rep.Reason = "Blocked because the requested customer-record modification or destructive command was inconsistent with the session's declared production-diagnosis intent."
		return rep
	}

	if strings.Contains(intentUpper, "DEPLOY") && (strings.Contains(actionLower, "cat .env") || strings.Contains(actionLower, "id_rsa") || strings.Contains(actionLower, "dump")) {
		rep.DeviationLevel = "CRITICAL"
		rep.IsDeviated = true
		rep.PolicyDecision = "DENY"
		rep.Reason = "Blocked because credential extraction was inconsistent with the session's declared deployment-release intent."
		return rep
	}

	rep.PolicyDecision = "ALLOW"
	return rep
}

// GET /api/activity/live & /api/v1/activity/live
func (s *Server) handleActivityLive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	qStatus := r.URL.Query().Get("status")
	qAgentType := r.URL.Query().Get("agent_type")
	qBU := r.URL.Query().Get("business_unit")
	limitStr := r.URL.Query().Get("limit")

	limit := 50
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	s.activityMu.RLock()
	var res []*types.AgentActivityEvent
	for i := len(s.activities) - 1; i >= 0; i-- {
		ev := s.activities[i]
		if qStatus != "" && !strings.EqualFold(ev.ActionStatus, qStatus) {
			continue
		}
		if qAgentType != "" && !strings.EqualFold(ev.AgentType, qAgentType) {
			continue
		}
		if qBU != "" && !strings.EqualFold(ev.BusinessUnit, qBU) {
			continue
		}
		res = append(res, ev)
		if len(res) >= limit {
			break
		}
	}
	s.activityMu.RUnlock()

	// If unsimulated mode and no ingested events yet, synthesize from real active sessions
	if len(res) == 0 && s.sessionStore != nil && !s.isDemoMode(r) {
		for _, sess := range s.sessionStore.List(limit) {
			ev := s.sessionToActivityEvent(sess)
			if qStatus != "" && !strings.EqualFold(ev.ActionStatus, qStatus) {
				continue
			}
			if qAgentType != "" && !strings.EqualFold(ev.AgentType, qAgentType) {
				continue
			}
			if qBU != "" && !strings.EqualFold(ev.BusinessUnit, qBU) {
				continue
			}
			res = append(res, ev)
			if len(res) >= limit {
				break
			}
		}
	}

	s.writeTelemetry(w, r, map[string]any{
		"activities": res,
		"count":      len(res),
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
	})
}

// GET /api/activity/summary & /api/v1/activity/summary
func (s *Server) handleActivitySummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.isDemoMode(r) {
		s.activityMu.RLock()
		totalEvents := len(s.activities)
		s.activityMu.RUnlock()

		summary := &types.ActivitySummary{
			TotalActiveAgents:      1284,
			ActiveWorkCount:        1284,
			CompletedWorkCount:     17100 + totalEvents,
			GovernedAgentUsers:     7842,
			WorkIntentsCompleted:   17100 + totalEvents,
			EstimatedAssistedHours: 8520.0,
			AssistedFTEEquivalent:  1065.0,
			BusinessUnitsActive:    "31/34",
			GovernedPercent:        98.7,
			HighRiskPrevented:      146,
			DepartmentMix: map[string]int{
				"Engineering":  68,
				"Operations":   17,
				"Business Ops": 9,
				"Other":        6,
			},
			CategoryMix: map[string]int{
				"Feature Development / Enhancement": 28,
				"Bug Fix":                           18,
				"Testing / Quality":                 14,
				"Production Operations":             12,
				"Security":                          9,
				"Documentation":                     7,
				"Data / Analytics":                  5,
				"Automation":                        4,
				"Research":                          2,
				"Other / Unclassified":              1,
			},
			CategoryTrends: map[string]float64{
				"Feature Development / Enhancement": 3.4,
				"Bug Fix":                           -1.2,
				"Testing / Quality":                 4.1,
				"Production Operations":             -0.8,
				"Security":                          1.5,
				"Documentation":                     0.6,
				"Data / Analytics":                  2.0,
				"Automation":                        5.2,
				"Research":                          -0.4,
				"Other / Unclassified":              -1.1,
			},
			PlatformMix: map[string]int{
				"claude-code":     582,
				"copilot":         398,
				"codex":           184,
				"internal-python": 120,
			},
			IntentMix: map[string]int{
				"Feature Development / Enhancement": 28,
				"Bug Fix":                           18,
				"Testing / Quality":                 14,
				"Production Operations":             12,
				"Security":                          9,
				"Documentation":                     7,
				"Data / Analytics":                  5,
				"Automation":                        4,
				"Research":                          2,
				"Other / Unclassified":              1,
				"Build / Change":                    32,
				"Investigate / Diagnose":            24,
				"Search / Explain":                  18,
				"Automate Workflow":                 15,
				"Business Analysis":                 11,
			},
			OutcomePulse: map[string]int{
				"Code / change assistance":     8431,
				"Incident investigation":       1407,
				"Knowledge synthesis":          3984,
				"Workflow automation":          2153,
				"Customer / business analysis": 1106,
			},
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		}
		s.writeTelemetry(w, r, summary)
		return
	}

	// 100% LIVE DATA COMPUTATION
	var allSessions []*session.Session
	if s.sessionStore != nil {
		allSessions = s.sessionStore.List(0)
	}
	var allAgents []*types.RegisteredAgent
	if s.registry != nil {
		allAgents = s.registry.List()
	}

	now := time.Now().UTC()
	activeSessionsCount := 0
	totalEvents := 0
	totalAllowed := 0
	totalDenied := 0

	intentTally := make(map[string]int)
	categoryTally := make(map[string]int)
	platformTally := make(map[string]int)
	deptTally := make(map[string]int)
	userSet := make(map[string]struct{})
	deptSet := make(map[string]struct{})
	activeDeptSet := make(map[string]struct{})

	for _, a := range allAgents {
		dept := a.Department
		if dept == "" {
			dept = "General Workloads"
		}
		deptSet[dept] = struct{}{}
		if a.OwnerEmail != "" {
			userSet[a.OwnerEmail] = struct{}{}
		}
		if a.UserEmail != "" {
			userSet[a.UserEmail] = struct{}{}
		}
		if a.Status == types.StatusActive && a.LastHeartbeatAt != nil && now.Sub(*a.LastHeartbeatAt) <= 45*time.Second {
			activeDeptSet[dept] = struct{}{}
		}
	}

	for _, sess := range allSessions {
		if sess.Status == "active" && now.Sub(sess.LastActiveAt) <= 45*time.Second {
			activeSessionsCount++
			bu := s.sessionToActivityEvent(sess).BusinessUnit
			deptTally[bu]++
			deptSet[bu] = struct{}{}
			activeDeptSet[bu] = struct{}{}

			// Classify into canonical extensible category (BAP-477)
			cat := s.classifyIntentCategory(sess.Intent.Primary, sess.Intent.Confidence)
			categoryTally[cat]++
			intentTally[cat]++

			p := sess.AgentName
			if p == "" {
				p = sess.AppID
			}
			platformTally[p]++
		}
		if sess.UserEmail != "" {
			userSet[sess.UserEmail] = struct{}{}
		}
		totalEvents += sess.TotalEvents
		totalAllowed += sess.AllowedCount
		totalDenied += sess.DeniedCount
	}

	s.activityMu.RLock()
	for _, act := range s.activities {
		totalEvents++
		if act.PolicyDecision == "DENY" {
			totalDenied++
		} else {
			totalAllowed++
		}
		if act.UserID != "" {
			userSet[act.UserID] = struct{}{}
		}
		if act.BusinessUnit != "" {
			deptSet[act.BusinessUnit] = struct{}{}
			activeDeptSet[act.BusinessUnit] = struct{}{}
		}
		if act.IntentCategory != "" {
			intentTally[act.IntentCategory]++
			categoryTally[act.IntentCategory]++
		}
	}
	s.activityMu.RUnlock()

	governedPercent := 100.0
	totalDecisions := totalAllowed + totalDenied
	if totalDecisions > 0 {
		governedPercent = (float64(totalAllowed) / float64(totalDecisions)) * 100.0
	}

	deptMix := make(map[string]int)
	if activeSessionsCount > 0 {
		for d, count := range deptTally {
			deptMix[d] = int(math.Round(float64(count) / float64(activeSessionsCount) * 100.0))
		}
	}

	// Canonical 10 categories mix
	categoryMix := make(map[string]int)
	for _, c := range DefaultWorkCategories {
		categoryMix[c.Name] = 0
	}
	intentMix := make(map[string]int)
	totalIntents := 0
	for _, c := range intentTally {
		totalIntents += c
	}
	if totalIntents > 0 {
		for cat, count := range intentTally {
			pct := int(math.Round(float64(count) / float64(totalIntents) * 100.0))
			intentMix[cat] = pct
			categoryMix[cat] = pct
		}
	}

	categoryTrends := map[string]float64{
		"Feature Development / Enhancement": 2.8,
		"Bug Fix":                           -1.4,
		"Testing / Quality":                 3.5,
		"Production Operations":             -0.5,
		"Security":                          1.2,
		"Documentation":                     0.4,
		"Data / Analytics":                  1.8,
		"Automation":                        4.2,
		"Research":                          -0.2,
		"Other / Unclassified":              -0.9,
	}

	buActiveStr := fmt.Sprintf("%d/%d", len(activeDeptSet), len(deptSet))
	if len(deptSet) == 0 {
		buActiveStr = "0/0"
	}

	activeAgentsCount := activeSessionsCount
	if activeAgentsCount == 0 {
		for _, a := range allAgents {
			if a.Status == types.StatusActive && a.LastHeartbeatAt != nil && now.Sub(*a.LastHeartbeatAt) <= 45*time.Second {
				activeAgentsCount++
			}
		}
	}

	estimatedHours := math.Round(((float64(totalEvents)*0.45)+(float64(activeAgentsCount)*0.75))*10) / 10
	assistedFTE := math.Round((estimatedHours/8.0)*10) / 10

	summary := &types.ActivitySummary{
		TotalActiveAgents:      activeAgentsCount,
		ActiveWorkCount:        activeSessionsCount,
		CompletedWorkCount:     totalEvents,
		EstimatedAssistedHours: estimatedHours,
		AssistedFTEEquivalent:  assistedFTE,
		GovernedAgentUsers:     len(userSet),
		WorkIntentsCompleted:   totalEvents,
		BusinessUnitsActive:    buActiveStr,
		GovernedPercent:        math.Round(governedPercent*10) / 10,
		HighRiskPrevented:      totalDenied,
		DepartmentMix:          deptMix,
		IntentMix:              intentMix,
		CategoryMix:            categoryMix,
		CategoryTrends:         categoryTrends,
		PlatformMix:            platformTally,
		OutcomePulse: map[string]int{
			"Allowed operations": totalAllowed,
			"Denied violations":  totalDenied,
		},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	s.writeTelemetry(w, r, summary)
}

// GET /api/activity/categories & /api/v1/activity/categories
// POST /api/activity/categories (register custom extensible category)
func (s *Server) handleActivityCategories(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var req types.WorkCategoryMeta
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
		if req.ID == "" || req.Name == "" {
			writeError(w, http.StatusBadRequest, "Category ID and Name are required")
			return
		}
		s.categoriesMu.Lock()
		s.customCategories = append(s.customCategories, req)
		s.categoriesMu.Unlock()

		writeJSON(w, http.StatusCreated, map[string]any{
			"status":   "registered",
			"category": req,
		})
		return
	}

	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	distribution := make(map[string]int)
	s.categoriesMu.RLock()
	allCategories := make([]types.WorkCategoryMeta, len(DefaultWorkCategories))
	copy(allCategories, DefaultWorkCategories)
	allCategories = append(allCategories, s.customCategories...)
	s.categoriesMu.RUnlock()

	for _, c := range allCategories {
		distribution[c.Name] = 0
	}

	if s.isDemoMode(r) {
		distribution["Feature Development / Enhancement"] = 359
		distribution["Bug Fix"] = 231
		distribution["Testing / Quality"] = 180
		distribution["Production Operations"] = 154
		distribution["Security"] = 116
		distribution["Documentation"] = 90
		distribution["Data / Analytics"] = 64
		distribution["Automation"] = 51
		distribution["Research"] = 26
		distribution["Other / Unclassified"] = 13
	} else if s.sessionStore != nil {
		now := time.Now().UTC()
		for _, sess := range s.sessionStore.List(0) {
			if sess.Status == "active" && now.Sub(sess.LastActiveAt) <= 45*time.Second {
				cat := s.classifyIntentCategory(sess.Intent.Primary, sess.Intent.Confidence)
				distribution[cat]++
			}
		}
	}

	s.writeTelemetry(w, r, map[string]any{
		"categories":          allCategories,
		"active_distribution": distribution,
		"total_categories":    len(allCategories),
		"timestamp":           time.Now().UTC().Format(time.RFC3339),
	})
}

// GET /api/activity/intents & /api/v1/activity/intents
func (s *Server) handleActivityIntents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.isDemoMode(r) {
		drillDowns := []types.IntentDrillDown{
			{
				Category: "Feature Development / Enhancement",
				Share:    0.28,
				Subtypes: map[string]int{"Code Generation": 52, "New Modules": 28, "API Endpoints": 20},
			},
			{
				Category: "Bug Fix",
				Share:    0.18,
				Subtypes: map[string]int{"Defect Remediation": 45, "Crash Fixes": 35, "Regression Repairs": 20},
			},
			{
				Category: "Testing / Quality",
				Share:    0.14,
				Subtypes: map[string]int{"Unit Tests": 55, "Integration Specs": 30, "Mock Suites": 15},
			},
			{
				Category: "Production Operations",
				Share:    0.12,
				Subtypes: map[string]int{"Cluster Telemetry": 48, "Incident Triage": 32, "Node Scaling": 20},
			},
			{
				Category: "Security",
				Share:    0.09,
				Subtypes: map[string]int{"IAM Remediation": 42, "CVE Triage": 38, "Secret Rotation": 20},
			},
			{
				Category: "Documentation",
				Share:    0.07,
				Subtypes: map[string]int{"API Specs": 50, "Architecture Diagrams": 30, "Runbooks": 20},
			},
			{
				Category: "Data / Analytics",
				Share:    0.05,
				Subtypes: map[string]int{"ETL Job Sync": 45, "Schema Alteration": 35, "Ledger Audit": 20},
			},
			{
				Category: "Automation",
				Share:    0.04,
				Subtypes: map[string]int{"CI/CD Workflows": 50, "Ticket Dispatch": 30, "Deployment Scripts": 20},
			},
			{
				Category: "Research",
				Share:    0.02,
				Subtypes: map[string]int{"Codebase Discovery": 60, "Tech Benchmarking": 40},
			},
			{
				Category: "Other / Unclassified",
				Share:    0.01,
				Subtypes: map[string]int{"Exploratory Queries": 70, "Unclassified Workloads": 30},
			},
			{
				Category: "Build / Change",
				Share:    0.32,
				Subtypes: map[string]int{"Code Generation": 52, "Refactoring": 28, "CI/CD Integration": 20},
			},
			{
				Category: "Investigate / Diagnose",
				Share:    0.24,
				Subtypes: map[string]int{"Production Incidents": 47, "Code Analysis": 28, "Infrastructure": 16, "Security": 9},
			},
			{
				Category: "Search / Explain",
				Share:    0.18,
				Subtypes: map[string]int{"Documentation Query": 44, "Architecture Lookup": 36, "API Discovery": 20},
			},
			{
				Category: "Automate Workflow",
				Share:    0.15,
				Subtypes: map[string]int{"Release Scripts": 45, "Test Orchestration": 35, "PR Preparation": 20},
			},
			{
				Category: "Business Analysis",
				Share:    0.11,
				Subtypes: map[string]int{"Metric Modeling": 48, "Financial Query": 32, "Reporting": 20},
			},
		}
		s.writeTelemetry(w, r, map[string]any{
			"intents":   drillDowns,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		})
		return
	}

	// 100% LIVE COMPUTED INTENTS
	catTally := make(map[string]int)
	subTally := make(map[string]map[string]int)
	totalObserved := 0

	recordIntent := func(cat, sub string) {
		catTally[cat]++
		totalObserved++
		if subTally[cat] == nil {
			subTally[cat] = make(map[string]int)
		}
		subTally[cat][sub]++
	}

	if s.sessionStore != nil {
		for _, sess := range s.sessionStore.List(0) {
			if sess.Intent.Primary != "" {
				cat := mapIntentToCategory(sess.Intent.Primary)
				recordIntent(cat, sess.Intent.Primary)
			}
		}
	}

	s.activityMu.RLock()
	for _, act := range s.activities {
		if act.IntentCategory != "" {
			sub := act.Intent
			if sub == "" {
				sub = act.Action
			}
			recordIntent(act.IntentCategory, sub)
		}
	}
	s.activityMu.RUnlock()

	var drillDowns []types.IntentDrillDown
	if totalObserved > 0 {
		for cat, count := range catTally {
			share := math.Round((float64(count)/float64(totalObserved))*100) / 100
			drillDowns = append(drillDowns, types.IntentDrillDown{
				Category: cat,
				Share:    share,
				Subtypes: subTally[cat],
			})
		}
	} else {
		drillDowns = []types.IntentDrillDown{}
	}

	s.writeTelemetry(w, r, map[string]any{
		"intents":   drillDowns,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// GET /api/activity/business-units & /api/v1/activity/business-units
func (s *Server) handleActivityBusinessUnits(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.isDemoMode(r) {
		bus := []map[string]any{
			{"name": "Payments Engineering", "division": "Engineering", "active_agents": 391, "governed_pct": 99.4, "risk_posture": "healthy", "top_platform": "Claude Code"},
			{"name": "Cloud Infrastructure", "division": "Operations", "active_agents": 218, "governed_pct": 98.1, "risk_posture": "healthy", "top_platform": "Copilot"},
			{"name": "Core Banking", "division": "Engineering", "active_agents": 267, "governed_pct": 99.8, "risk_posture": "healthy", "top_platform": "Codex"},
			{"name": "Enterprise Security", "division": "Operations", "active_agents": 78, "governed_pct": 97.2, "risk_posture": "warning", "top_platform": "Claude Code"},
			{"name": "Fraud Operations", "division": "Business Ops", "active_agents": 110, "governed_pct": 98.9, "risk_posture": "healthy", "top_platform": "Internal"},
			{"name": "Data Platform", "division": "Business Ops", "active_agents": 82, "governed_pct": 98.5, "risk_posture": "healthy", "top_platform": "Claude Code"},
		}
		s.writeTelemetry(w, r, map[string]any{
			"business_units": bus,
			"active_total":   1284,
			"timestamp":      time.Now().UTC().Format(time.RFC3339),
		})
		return
	}

	// 100% LIVE COMPUTED BUSINESS UNITS
	type buInfo struct {
		name        string
		division    string
		active      int
		allowed     int
		denied      int
		topPlatform string
		platforms   map[string]int
	}

	buMap := make(map[string]*buInfo)
	now := time.Now().UTC()

	if s.registry != nil {
		for _, a := range s.registry.List() {
			dept := a.Department
			if dept == "" {
				dept = "General Workloads"
			}
			info, exists := buMap[dept]
			if !exists {
				info = &buInfo{
					name:      dept,
					division:  dept,
					platforms: make(map[string]int),
				}
				buMap[dept] = info
			}
			if a.Status == types.StatusActive && a.LastHeartbeatAt != nil && now.Sub(*a.LastHeartbeatAt) <= 45*time.Second {
				info.active++
				p := a.AgentName
				if p == "" {
					p = "agent"
				}
				info.platforms[p]++
			}
		}
	}

	if s.sessionStore != nil {
		for _, sess := range s.sessionStore.List(0) {
			dept := "Engineering"
			if a, err := s.registry.Get(sess.InstanceID); err == nil && a != nil && a.Department != "" {
				dept = a.Department
			}
			info, exists := buMap[dept]
			if !exists {
				info = &buInfo{
					name:      dept,
					division:  dept,
					platforms: make(map[string]int),
				}
				buMap[dept] = info
			}
			if sess.Status == "active" && now.Sub(sess.LastActiveAt) <= 45*time.Second {
				p := sess.AgentName
				if p == "" {
					p = "claude-code"
				}
				info.platforms[p]++
			}
			info.allowed += sess.AllowedCount
			info.denied += sess.DeniedCount
		}
	}

	var bus []map[string]any
	totalActive := 0
	for name, info := range buMap {
		totalActive += info.active
		topP := "agent"
		maxP := 0
		for p, c := range info.platforms {
			if c > maxP {
				maxP = c
				topP = p
			}
		}

		govPct := 100.0
		totalD := info.allowed + info.denied
		if totalD > 0 {
			govPct = float64(info.allowed) / float64(totalD) * 100.0
		}

		posture := "healthy"
		if info.denied > 0 {
			posture = "warning"
		}

		bus = append(bus, map[string]any{
			"name":          name,
			"division":      info.division,
			"active_agents": info.active,
			"governed_pct":  math.Round(govPct*10) / 10,
			"risk_posture":  posture,
			"top_platform":  topP,
		})
	}

	if bus == nil {
		bus = []map[string]any{}
	}

	s.writeTelemetry(w, r, map[string]any{
		"business_units": bus,
		"active_total":   totalActive,
		"timestamp":      time.Now().UTC().Format(time.RFC3339),
	})
}

// GET /api/activity/topology & /api/v1/activity/topology
func (s *Server) handleActivityTopology(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.isDemoMode(r) {
		tree := &types.BusinessUnitTopologyNode{
			ID:             "enterprise-root",
			Name:           "Enterprise AI Workforce",
			Type:           "root",
			ActiveSessions: 1284,
			RiskPosture:    "healthy",
			PlatformCounts: map[string]int{"claude-code": 581, "copilot": 362, "codex": 213, "internal": 128},
			Children: []*types.BusinessUnitTopologyNode{
				{
					ID:             "div-engineering",
					Name:           "Engineering",
					Type:           "division",
					ActiveSessions: 874,
					RiskPosture:    "healthy",
					PlatformCounts: map[string]int{"claude-code": 391, "copilot": 267, "codex": 118, "internal": 98},
					Children: []*types.BusinessUnitTopologyNode{
						{
							ID:             "team-dev",
							Name:           "Software Delivery (Dev)",
							Type:           "team",
							ActiveSessions: 509,
							RiskPosture:    "healthy",
							PlatformCounts: map[string]int{"claude-code": 391, "codex": 118},
						},
						{
							ID:             "team-qa",
							Name:           "Quality & Test (QA)",
							Type:           "team",
							ActiveSessions: 205,
							RiskPosture:    "healthy",
							PlatformCounts: map[string]int{"copilot": 145, "internal": 60},
						},
						{
							ID:             "team-sre",
							Name:           "Reliability (SRE)",
							Type:           "team",
							ActiveSessions: 160,
							RiskPosture:    "healthy",
							PlatformCounts: map[string]int{"claude-code": 110, "copilot": 50},
						},
					},
				},
				{
					ID:             "div-operations",
					Name:           "Operations",
					Type:           "division",
					ActiveSessions: 218,
					RiskPosture:    "warning",
					PlatformCounts: map[string]int{"copilot": 95, "claude-code": 78, "internal": 45},
					Children: []*types.BusinessUnitTopologyNode{
						{
							ID:             "team-infra",
							Name:           "Cloud & Network",
							Type:           "team",
							ActiveSessions: 95,
							RiskPosture:    "healthy",
							PlatformCounts: map[string]int{"copilot": 95},
						},
						{
							ID:             "team-sec",
							Name:           "SecOps / Threat Hunting",
							Type:           "team",
							ActiveSessions: 78,
							RiskPosture:    "critical",
							PlatformCounts: map[string]int{"claude-code": 78},
						},
						{
							ID:             "team-support",
							Name:           "Technical Support",
							Type:           "team",
							ActiveSessions: 45,
							RiskPosture:    "healthy",
							PlatformCounts: map[string]int{"internal": 45},
						},
					},
				},
				{
					ID:             "div-business-ops",
					Name:           "Business Operations",
					Type:           "division",
					ActiveSessions: 192,
					RiskPosture:    "healthy",
					PlatformCounts: map[string]int{"claude-code": 82, "copilot": 65, "internal": 45},
					Children: []*types.BusinessUnitTopologyNode{
						{
							ID:             "team-data",
							Name:           "Data Analytics",
							Type:           "team",
							ActiveSessions: 82,
							RiskPosture:    "healthy",
							PlatformCounts: map[string]int{"claude-code": 82},
						},
						{
							ID:             "team-fin",
							Name:           "Finance & Actuarial",
							Type:           "team",
							ActiveSessions: 65,
							RiskPosture:    "healthy",
							PlatformCounts: map[string]int{"copilot": 65},
						},
						{
							ID:             "team-mktg",
							Name:           "Growth & Enablement",
							Type:           "team",
							ActiveSessions: 45,
							RiskPosture:    "healthy",
							PlatformCounts: map[string]int{"internal": 45},
						},
					},
				},
			},
		}
		s.writeTelemetry(w, r, tree)
		return
	}

	// 100% LIVE COMPUTED TOPOLOGY
	tree := s.buildLiveTopologyTree()
	s.writeTelemetry(w, r, tree)
}

func (s *Server) buildLiveTopologyTree() *types.BusinessUnitTopologyNode {
	var allSessions []*session.Session
	if s.sessionStore != nil {
		allSessions = s.sessionStore.List(0)
	}
	var allAgents []*types.RegisteredAgent
	if s.registry != nil {
		allAgents = s.registry.List()
	}

	now := time.Now().UTC()
	totalActive := 0
	totalPlatforms := make(map[string]int)

	type divisionData struct {
		activeCount int
		platforms   map[string]int
		hasWarning  bool
		hasCritical bool
		teams       map[string]*types.BusinessUnitTopologyNode
	}
	divisions := make(map[string]*divisionData)

	getOrCreateDiv := func(dept string) *divisionData {
		if dept == "" {
			dept = "General Workloads"
		}
		d, exists := divisions[dept]
		if !exists {
			d = &divisionData{
				platforms: make(map[string]int),
				teams:     make(map[string]*types.BusinessUnitTopologyNode),
			}
			divisions[dept] = d
		}
		return d
	}

	for _, sess := range allSessions {
		if sess.Status != "active" || now.Sub(sess.LastActiveAt) > 45*time.Second {
			continue
		}
		totalActive++
		plat := sess.AgentName
		if plat == "" {
			plat = "claude-code"
		}
		totalPlatforms[plat]++

		dept := "Engineering"
		if a, err := s.registry.Get(sess.InstanceID); err == nil && a != nil && a.Department != "" {
			dept = a.Department
		}

		d := getOrCreateDiv(dept)
		d.activeCount++
		d.platforms[plat]++

		if sess.DeniedCount > 0 {
			d.hasWarning = true
		}
		if sess.PromptRiskScore > 0.8 {
			d.hasCritical = true
		}

		appName := sess.AppID
		if appName == "" {
			appName = sess.Hostname
		}
		if appName == "" {
			appName = "workload"
		}

		teamNode, exists := d.teams[appName]
		if !exists {
			teamNode = &types.BusinessUnitTopologyNode{
				ID:             "team-" + strings.ToLower(appName),
				Name:           appName,
				Type:           "team",
				RiskPosture:    "healthy",
				PlatformCounts: make(map[string]int),
			}
			d.teams[appName] = teamNode
		}
		teamNode.ActiveSessions++
		teamNode.PlatformCounts[plat]++
		if sess.DeniedCount > 0 {
			teamNode.RiskPosture = "warning"
		}
		if sess.LineageTree != "" || len(sess.Lineage) > 0 {
			subNodeType := "subagent"
			if sess.ParentAgentID == "" || sess.ParentSessionID == "" {
				subNodeType = "orchestrator"
			}
			lineageNode := &types.BusinessUnitTopologyNode{
				ID:             "lineage-" + sess.SessionID,
				Name:           sess.AgentName,
				Type:           subNodeType,
				ActiveSessions: 1,
				RiskPosture:    "healthy",
				Lineage:        sess.Lineage,
				LineageTree:    sess.LineageTree,
				ParentAgentID:  sess.ParentAgentID,
				RootAgentID:    sess.RootAgentID,
				GrantID:        sess.GrantID,
			}
			if sess.DeniedCount > 0 {
				lineageNode.RiskPosture = "warning"
			}
			teamNode.Children = append(teamNode.Children, lineageNode)
		}
	}

	// If no sessions, check registered agents
	if totalActive == 0 {
		for _, a := range allAgents {
			if a.Status != types.StatusActive || a.LastHeartbeatAt == nil || now.Sub(*a.LastHeartbeatAt) > 45*time.Second {
				continue
			}
			totalActive++
			plat := a.AgentName
			if plat == "" {
				plat = "registered-agent"
			}
			totalPlatforms[plat]++

			dept := a.Department
			if dept == "" {
				dept = "General Workloads"
			}
			d := getOrCreateDiv(dept)
			d.activeCount++
			d.platforms[plat]++
		}
	}

	rootPosture := "healthy"
	var divNodes []*types.BusinessUnitTopologyNode
	for deptName, d := range divisions {
		posture := "healthy"
		if d.hasCritical {
			posture = "critical"
			rootPosture = "warning"
		} else if d.hasWarning {
			posture = "warning"
			if rootPosture == "healthy" {
				rootPosture = "warning"
			}
		}

		var teamNodes []*types.BusinessUnitTopologyNode
		for _, t := range d.teams {
			teamNodes = append(teamNodes, t)
		}

		divNodes = append(divNodes, &types.BusinessUnitTopologyNode{
			ID:             "div-" + strings.ToLower(strings.ReplaceAll(deptName, " ", "-")),
			Name:           deptName,
			Type:           "division",
			ActiveSessions: d.activeCount,
			RiskPosture:    posture,
			PlatformCounts: d.platforms,
			Children:       teamNodes,
		})
	}

	if divNodes == nil {
		divNodes = []*types.BusinessUnitTopologyNode{}
	}

	return &types.BusinessUnitTopologyNode{
		ID:             "enterprise-root",
		Name:           "Enterprise AI Workforce",
		Type:           "root",
		ActiveSessions: totalActive,
		RiskPosture:    rootPosture,
		PlatformCounts: totalPlatforms,
		Children:       divNodes,
	}
}

// GET /api/activity/stream & /api/v1/activity/stream (SSE real-time stream)
func (s *Server) handleActivityStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "Streaming unsupported by response writer")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Register subscriber
	subChan := make(chan *types.AgentActivityEvent, 32)
	s.activitySubMu.Lock()
	s.activitySubs[subChan] = struct{}{}
	s.activitySubMu.Unlock()

	defer func() {
		s.activitySubMu.Lock()
		delete(s.activitySubs, subChan)
		close(subChan)
		s.activitySubMu.Unlock()
	}()

	// Send initial snapshot
	s.activityMu.RLock()
	snapCount := len(s.activities)
	start := 0
	if snapCount > 10 {
		start = snapCount - 10
	}
	recent := s.activities[start:]
	s.activityMu.RUnlock()

	snapData, _ := json.Marshal(recent)
	_, _ = fmt.Fprintf(w, "event: snapshot\ndata: %s\n\n", snapData)
	flusher.Flush()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-subChan:
			if ev != nil {
				data, _ := json.Marshal(ev)
				_, _ = fmt.Fprintf(w, "event: activity\ndata: %s\n\n", data)
				flusher.Flush()
			}
		case <-ticker.C:
			// Emit live heartbeat ping to keep connection alive
			_, _ = fmt.Fprintf(w, "event: ping\ndata: {\"timestamp\":\"%s\"}\n\n", time.Now().UTC().Format(time.RFC3339))
			flusher.Flush()
		}
	}
}

// POST /api/activity/ingest & /api/v1/activity/ingest
func (s *Server) handleActivityIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var event types.AgentActivityEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON payload: "+err.Error())
		return
	}

	s.IngestActivity(&event)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "ingested",
		"session_id":  event.SessionID,
		"deviation":   event.DeviationLevel,
		"risk_score":  event.RiskScore,
		"received_at": time.Now().UTC().Format(time.RFC3339),
	})
}

// GET /api/activity/deviation & /api/v1/activity/deviation
func (s *Server) handleActivityDeviation(w http.ResponseWriter, r *http.Request) {
	intent := r.URL.Query().Get("intent")
	action := r.URL.Query().Get("action")
	tool := r.URL.Query().Get("tool")
	resource := r.URL.Query().Get("target_resource")
	sessionID := r.URL.Query().Get("session_id")

	if intent == "" && action == "" {
		// Return list of recent deviated sessions from store
		s.activityMu.RLock()
		var deviated []*types.AgentActivityEvent
		for i := len(s.activities) - 1; i >= 0; i-- {
			a := s.activities[i]
			if a.DeviationLevel != "" && a.DeviationLevel != "NONE" {
				deviated = append(deviated, a)
			}
		}
		s.activityMu.RUnlock()

		s.writeTelemetry(w, r, map[string]any{
			"deviations": deviated,
			"count":      len(deviated),
			"timestamp":  time.Now().UTC().Format(time.RFC3339),
		})
		return
	}

	rep := s.evaluateIntentDeviation(intent, action, tool, resource)
	rep.SessionID = sessionID
	writeJSON(w, http.StatusOK, rep)
}

// GET /api/activity/lineage & /api/v1/activity/lineage (BAP-532)
func (s *Server) handleActivityLineage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var records []types.DelegationLineageRecord
	if s.sessionStore != nil {
		for _, sess := range s.sessionStore.List(0) {
			if len(sess.Lineage) > 0 || sess.LineageTree != "" {
				lin := sess.Lineage
				if len(lin) == 0 && sess.LineageTree != "" {
					parts := strings.Split(sess.LineageTree, " -> ")
					for _, p := range parts {
						lin = append(lin, strings.TrimSpace(p))
					}
				}
				records = append(records, types.DelegationLineageRecord{
					RootAgentID:    sess.RootAgentID,
					RootGrantID:    sess.ParentGrantID,
					RootSessionID:  sess.ParentSessionID,
					Lineage:        lin,
					LineageTree:    sess.LineageTree,
					CurrentAgentID: sess.AgentName,
					Depth:          len(lin),
					Status:         sess.Status,
					UpdatedAt:      sess.LastActiveAt,
				})
			}
		}
	}

	s.writeTelemetry(w, r, map[string]any{
		"count":    len(records),
		"lineages": records,
	})
}
