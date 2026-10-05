package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"bap-controlplane/pkg/types"
)

func (s *Server) initActivityEngine() {
	s.activitySubs = make(map[chan *types.AgentActivityEvent]struct{})
	s.seedBaselineActivities()
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

	s.activityMu.RLock()
	totalEvents := len(s.activities)
	activeCount := 0
	for _, a := range s.activities {
		if a.ActionStatus == "working" || a.ActionStatus == "waiting" {
			activeCount++
		}
	}
	s.activityMu.RUnlock()

	// Merge with real registered agents count if higher
	realAgents := len(s.registry.List())
	activeAgents := 1284
	if realAgents > 0 {
		activeAgents = 1284 + realAgents
	}

	summary := &types.ActivitySummary{
		TotalActiveAgents:    activeAgents,
		GovernedAgentUsers:   7842,
		WorkIntentsCompleted: 17100 + totalEvents,
		BusinessUnitsActive:  "31/34",
		GovernedPercent:      98.7,
		HighRiskPrevented:    146,
		DepartmentMix: map[string]int{
			"Engineering":  68,
			"Operations":   17,
			"Business Ops": 9,
			"Other":        6,
		},
		IntentMix: map[string]int{
			"Build / Change":         32,
			"Investigate / Diagnose": 24,
			"Search / Explain":       18,
			"Automate Workflow":      15,
			"Business Analysis":      11,
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
}

// GET /api/activity/intents & /api/v1/activity/intents
func (s *Server) handleActivityIntents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	drillDowns := []types.IntentDrillDown{
		{
			Category: "Build / Change",
			Share:    0.32,
			Subtypes: map[string]int{
				"Code Generation":    52,
				"Refactoring":        28,
				"CI/CD Integration":  20,
			},
		},
		{
			Category: "Investigate / Diagnose",
			Share:    0.24,
			Subtypes: map[string]int{
				"Production Incidents": 47,
				"Code Analysis":        28,
				"Infrastructure":       16,
				"Security":             9,
			},
		},
		{
			Category: "Search / Explain",
			Share:    0.18,
			Subtypes: map[string]int{
				"Documentation Query": 44,
				"Architecture Lookup": 36,
				"API Discovery":       20,
			},
		},
		{
			Category: "Automate Workflow",
			Share:    0.15,
			Subtypes: map[string]int{
				"Release Scripts":    45,
				"Test Orchestration": 35,
				"PR Preparation":     20,
			},
		},
		{
			Category: "Business Analysis",
			Share:    0.11,
			Subtypes: map[string]int{
				"Metric Modeling": 48,
				"Financial Query": 32,
				"Reporting":       20,
			},
		},
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
}

// GET /api/activity/topology & /api/v1/activity/topology
func (s *Server) handleActivityTopology(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

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
