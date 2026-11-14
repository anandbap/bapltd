package session

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"time"

	"bap-controlplane/internal/audit"
)

// Evidence grades describe how trustworthy a record is. They are observation
// metadata only and must never feed an authorization decision.
const (
	GradeVerified     = "verified"
	GradeMediated     = "mediated"
	GradeSelfReported = "self_reported"
	GradePresence     = "presence"
)

// Coverage states per defense layer.
const (
	CoverageObserved = "observed"
	CoverageSilent   = "silent"
)

// Degraded reasons surfaced to the dashboard and status output.
const (
	DegradedHooksDisabled   = "hooks_disabled"
	DegradedHooksUnapproved = "hooks_unapproved_or_disabled"
	DegradedNoEvidence      = "no_evidence_above_discovery"
)

// layerPrecedence ranks reporting layers; lower wins. Gateway is orthogonal
// (network scope) and handled separately by the arbiter.
var layerPrecedence = map[string]int{
	"hook":      0,
	"plugin":    0,
	"launcher":  0,
	"broker":    1,
	"shim":      2,
	"mcp":       3,
	"sdk":       3,
	"gateway":   4,
	"discovery": 5,
}

func precedence(layer string) int {
	if p, ok := layerPrecedence[layer]; ok {
		return p
	}
	return 99
}

// GradeFor returns the explicit grade when set, otherwise a default derived
// from the reporting layer. A model-reported MCP record must carry the
// explicit self_reported grade; the default for mcp is mediated.
func GradeFor(ev audit.Event) string {
	if ev.EvidenceGrade != "" {
		return ev.EvidenceGrade
	}
	switch ev.ReportingLayer {
	case "hook", "plugin", "launcher", "broker", "shim", "gateway":
		return GradeVerified
	case "mcp", "sdk":
		return GradeMediated
	case "discovery":
		return GradePresence
	}
	return ""
}

// DedupKeyFor returns the arbitration key for an event, or "" when the event
// has no stable identity and must pass through unmerged.
func DedupKeyFor(ev audit.Event) string {
	if ev.DedupKey != "" {
		return ev.DedupKey
	}
	if ev.Executable == "user_prompt" && ev.TurnID != "" {
		return "prompt:" + ev.TurnID
	}
	cmd := strings.Join(strings.Fields(strings.ToLower(ev.FullCommand)), " ")
	if cmd == "" || ev.Executable == "user_prompt" {
		return ""
	}
	ts, err := time.Parse(time.RFC3339Nano, ev.Timestamp)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256([]byte(cmd))
	bucket := ts.UTC().Unix() / 5
	return "cmd:" + hex.EncodeToString(sum[:8]) + ":" + strconv.FormatInt(bucket, 10)
}

// Arbitrate merges events that describe the same request. For each
// (session, dedup key) the highest-precedence layer becomes the primary
// record and the other layers are attached as CorroboratingLayers. Events
// without a dedup key, and gateway events, are never merged or suppressed.
// Input order is preserved for primaries; the input slice is not modified.
func Arbitrate(events []audit.Event) []audit.Event {
	type slot struct {
		index int
		layer string
		seen  map[string]struct{}
	}
	out := make([]audit.Event, 0, len(events))
	slots := make(map[string]*slot)
	for _, ev := range events {
		ev.EvidenceGrade = GradeFor(ev)
		key := DedupKeyFor(ev)
		if key == "" || ev.ReportingLayer == "gateway" {
			out = append(out, ev)
			continue
		}
		k := ev.SessionID + "\x00" + key
		s, ok := slots[k]
		if !ok {
			slots[k] = &slot{index: len(out), layer: ev.ReportingLayer, seen: map[string]struct{}{}}
			out = append(out, ev)
			continue
		}
		if precedence(ev.ReportingLayer) < precedence(s.layer) {
			// New event outranks the current primary: swap, keep old layer as support.
			prev := out[s.index]
			s.seen[prev.ReportingLayer] = struct{}{}
			for _, l := range prev.CorroboratingLayers {
				s.seen[l] = struct{}{}
			}
			delete(s.seen, ev.ReportingLayer)
			out[s.index] = ev
			s.layer = ev.ReportingLayer
		} else if ev.ReportingLayer != s.layer {
			s.seen[ev.ReportingLayer] = struct{}{}
		}
		layers := make([]string, 0, len(s.seen))
		for l := range s.seen {
			layers = append(layers, l)
		}
		sort.Strings(layers)
		out[s.index].CorroboratingLayers = layers
	}
	return out
}

// applyCoverage derives per-layer coverage and a degraded reason from the
// layers a session has actually reported. It never claims compliance: a layer
// is "observed" only after real events from it, otherwise "silent".
func applyCoverage(sess *Session) {
	has := map[string]bool{}
	for _, l := range sess.ReportingLayers {
		has[l] = true
	}
	cov := map[string]string{
		"layer1_hooks":   CoverageSilent,
		"layer2_mcp":     CoverageSilent,
		"layer3_shims":   CoverageSilent,
		"layer4_broker":  CoverageSilent,
		"layer5_gateway": CoverageSilent,
	}
	if has["hook"] || has["plugin"] || has["launcher"] {
		cov["layer1_hooks"] = CoverageObserved
	}
	if has["mcp"] {
		cov["layer2_mcp"] = CoverageObserved
	}
	if has["shim"] {
		cov["layer3_shims"] = CoverageObserved
	}
	if has["broker"] {
		cov["layer4_broker"] = CoverageObserved
	}
	if has["gateway"] {
		cov["layer5_gateway"] = CoverageObserved
	}
	sess.Coverage = cov

	lowerSeen := has["mcp"] || has["shim"] || has["broker"] || has["gateway"]
	switch {
	case sess.HooksDisabled || has["unmonitored"]:
		sess.DegradedReason = DegradedHooksDisabled
	case cov["layer1_hooks"] == CoverageSilent && lowerSeen:
		sess.DegradedReason = DegradedHooksUnapproved
	case !has["hook"] && !has["plugin"] && !has["launcher"] && !lowerSeen && len(sess.ReportingLayers) > 0:
		sess.DegradedReason = DegradedNoEvidence
	default:
		sess.DegradedReason = ""
	}
}
