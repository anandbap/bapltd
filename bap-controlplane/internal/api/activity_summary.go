package api

import (
	"math"
	"strings"
	"time"
)

// Session operation counters and the bounded activity feed are different
// datasets. Never add them together: producers can report to both surfaces,
// and a canonical cross-layer operation identity is not yet available.
func (s *Server) liveActivitySummary() map[string]any {
	sessions := s.sessionStore.List(0)
	now := time.Now().UTC()
	active, operations, allowed, denied, observations := 0, 0, 0, 0, 0
	categories := map[string]int{}
	platforms := map[string]int{}
	departments := map[string]int{}
	users := map[string]bool{}
	knownSessions := map[string]bool{}
	deptByInstance := map[string]string{}
	for _, agent := range s.registry.List() {
		if agent.Department != "" {
			deptByInstance[agent.InstanceID] = agent.Department
		}
	}
	for _, sess := range sessions {
		knownSessions[sess.SessionID] = true
		operations += sess.TotalEvents
		allowed += sess.AllowedCount
		denied += sess.DeniedCount
		if email := strings.ToLower(strings.TrimSpace(sess.UserEmail)); email != "" {
			users[email] = true
		}
		if sess.Status != "active" || now.Sub(sess.LastActiveAt) > 45*time.Second || sess.LastActiveAt.After(now.Add(5*time.Second)) {
			continue
		}
		active++
		if len(sess.ReportingLayers) == 1 && sess.ReportingLayers[0] == "discovery" {
			observations++
		}
		category := s.classifyIntentCategory(sess.Intent.Primary, sess.Intent.Confidence)
		if category == "Other / Unclassified" && sess.UserPrompt != "" {
			category = s.classifyIntentCategory(sess.UserPrompt, 1)
		}
		// Agent/platform names are not evidence of the user's work intent.
		categories[category]++
		platforms[sess.AppID]++
		dept := deptByInstance[sess.InstanceID]
		if dept == "" {
			dept = "Unknown"
		}
		departments[dept]++
	}
	activityCount, activityAllowed, activityDenied, activityUnknown, unlinked := 0, 0, 0, 0, 0
	s.activityMu.RLock()
	for _, act := range s.activities {
		activityCount++
		switch strings.ToUpper(act.PolicyDecision) {
		case "ALLOW":
			activityAllowed++
		case "DENY":
			activityDenied++
		default:
			activityUnknown++
		}
		if !knownSessions[act.SessionID] {
			unlinked++
		}
	}
	s.activityMu.RUnlock()
	categoryMix := map[string]int{}
	departmentMix := map[string]int{}
	for _, cat := range DefaultWorkCategories {
		categoryMix[cat.Name] = 0
	}
	if active > 0 {
		for name, count := range categories {
			categoryMix[name] = int(math.Round(float64(count) * 100 / float64(active)))
		}
		for name, count := range departments {
			departmentMix[name] = int(math.Round(float64(count) * 100 / float64(active)))
		}
	}
	var allowance any
	if allowed+denied > 0 {
		allowance = math.Round(float64(allowed)*1000/float64(allowed+denied)) / 10
	}
	return map[string]any{
		"mode": "live", "simulated": false, "metrics_version": 2,
		"total_active_agents": active, "active_session_count": active, "process_only_active_sessions": observations,
		"observed_session_users": len(users), "session_operation_records": operations,
		"allowed_operation_records": allowed, "denied_operation_records": denied, "operation_allowance_percent": allowance,
		"activity_records_retained": activityCount, "activity_allowed_records": activityAllowed, "activity_denied_records": activityDenied, "activity_unknown_decision_records": activityUnknown, "unlinked_activity_records": unlinked,
		"platform_mix": platforms, "department_mix": departmentMix, "category_mix": categoryMix, "intent_mix": categoryMix,
		"outcome_pulse": map[string]int{"Allowed operation records": allowed, "Denied operation records": denied},
		// Legacy keys remain present so consumers can explicitly render unavailable.
		"active_work_count": nil, "completed_work_count": nil, "work_intents_completed": nil,
		"estimated_assisted_hours": nil, "assisted_fte_equivalent": nil, "governed_percent": nil, "governed_agent_users": nil,
		"high_risk_prevented": nil, "business_units_active": nil, "category_trends": nil,
		"metric_availability": map[string]string{"verified_work_outcomes": "unavailable: no verified deliverable source", "assisted_hours": "unavailable: no measured baseline", "governance_coverage": "unavailable: no complete enforcement denominator", "category_trends": "unavailable: no comparable historical windows"},
		"measurement_scope":   map[string]string{"operations": "retained session counters; records, not unique cross-layer operations or completed work", "activity": "separate bounded feed (up to 1000 records); not added to session counters", "categories": "current classified intent of active sessions; not completed work", "users": "known authenticated email identities in retained sessions; not the expected employee roster"},
		"timestamp":           now.Format(time.RFC3339Nano),
	}
}
