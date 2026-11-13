package learn

import (
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"

	"bap-edge/internal/capability"
)

type ProfileRecommendation struct {
	Profile               capability.Profile `json:"profile"`
	Sessions              int                `json:"sessions"`
	AddReadOnly           []string           `json:"add_read_only"`
	AddEgress             []string           `json:"add_egress"`
	RequiresHumanApproval bool               `json:"requires_human_approval"`
}

// GenerateProfile learns exact observed read paths and approved destinations.
// It never generalizes to a parent directory, wildcard, root, or write scope.
// It returns advice only. A denied or predicted effect is not observed access.
func GenerateProfile(events []Event, current capability.Profile, minSessions int) (ProfileRecommendation, error) {
	result := ProfileRecommendation{Profile: current, RequiresHumanApproval: true}
	if err := current.Validate(); err != nil {
		return result, err
	}
	if minSessions < 2 {
		return result, fmt.Errorf("profile generation requires at least two observed sessions")
	}
	sessions := map[string]bool{}
	reads := map[string]bool{}
	hosts := map[string]bool{}
	for _, e := range events {
		if e.Project != current.Workspace || !e.Observed || e.Session == "" || e.Verdict != "allow" || (e.Source != "sandbox" && e.Source != "egress-proxy") {
			continue
		}
		sessions[e.Session] = true
		if e.Kind == "fs" && e.Mode == "read" && filepath.IsAbs(e.Target) && !capability.IsMasked(e.Target) {
			target := filepath.Clean(e.Target)
			if root := filepath.Dir(target); root == target {
				continue
			}
			if strings.ContainsAny(target, "*?") {
				continue
			}
			rel, err := filepath.Rel(current.Workspace, target)
			if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				continue
			}
			reads[target] = true
		}
		if e.Kind == "egress" {
			host := hostOf(e.Target)
			port := portOf(e.Target)
			if host == "" || port == "" || net.ParseIP(host) != nil || strings.ContainsAny(host, "*/\\") {
				continue
			}
			if capability.ValidateEgressPattern(host+":"+port) == nil {
				hosts[host+":"+port] = true
			}
		}
	}
	result.Sessions = len(sessions)
	if result.Sessions < minSessions {
		return result, fmt.Errorf("observed %d sessions; need %d", result.Sessions, minSessions)
	}
	for _, path := range current.ReadOnly {
		delete(reads, path)
	}
	for path := range reads {
		result.AddReadOnly = append(result.AddReadOnly, path)
	}
	sort.Strings(result.AddReadOnly)
	result.Profile.ReadOnly = append(append([]string(nil), current.ReadOnly...), result.AddReadOnly...)
	for host := range hosts {
		h, p := hostOf(host), portOf(host)
		if !capability.MatchEgress(current.EgressAllow, h, p) {
			result.AddEgress = append(result.AddEgress, host)
		}
	}
	sort.Strings(result.AddEgress)
	for _, host := range result.AddEgress {
		var err error
		result.Profile, err = result.Profile.AddEgress(host)
		if err != nil {
			return result, err
		}
	}
	return result, result.Profile.Validate()
}
