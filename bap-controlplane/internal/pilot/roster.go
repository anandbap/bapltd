// Package pilot defines operator-assigned reporting expectations, not execution authority.
package pilot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

type Window struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}
type Entry struct {
	PersonID   string   `json:"person_id"`
	OwnerEmail string   `json:"owner_email"`
	Team       string   `json:"team"`
	InstanceID string   `json:"instance_id"`
	Windows    []Window `json:"windows"`
}
type Roster struct {
	SchemaVersion    int     `json:"schema_version"`
	RosterID         string  `json:"roster_id"`
	FreshnessSeconds int     `json:"freshness_seconds"`
	Entries          []Entry `json:"entries"`
}

// Decode accepts a bounded, strict operator configuration. Unknown/empty coverage
// is never silently converted into a zero-person or fully covered pilot.
func Decode(r io.Reader) (*Roster, string, error) {
	b, err := io.ReadAll(io.LimitReader(r, (1<<20)+1))
	if err != nil || len(b) > 1<<20 {
		return nil, "", errors.New("roster exceeds read limit")
	}
	var roster Roster
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if err := d.Decode(&roster); err != nil {
		return nil, "", err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, "", errors.New("one roster object required")
	}
	if roster.SchemaVersion != 1 || !label(roster.RosterID) || roster.FreshnessSeconds < 30 || roster.FreshnessSeconds > 3600 || len(roster.Entries) == 0 || len(roster.Entries) > 1000 {
		return nil, "", errors.New("invalid roster header or bounds")
	}
	instances := map[string]bool{}
	people := map[string]string{}
	emails := map[string]string{}
	for _, e := range roster.Entries {
		if !label(e.PersonID) || !label(e.InstanceID) || !label(e.Team) || !label(e.OwnerEmail) || !strings.Contains(e.OwnerEmail, "@") || e.OwnerEmail != strings.TrimSpace(e.OwnerEmail) || len(e.Windows) == 0 || len(e.Windows) > 64 || instances[e.InstanceID] {
			return nil, "", errors.New("invalid or duplicate workstation expectation")
		}
		identity := strings.ToLower(e.OwnerEmail)
		if old, ok := people[e.PersonID]; ok && old != identity+"\x00"+e.Team {
			return nil, "", errors.New("conflicting person assignments")
		}
		if old, ok := emails[identity]; ok && old != e.PersonID {
			return nil, "", errors.New("email assigned to multiple people")
		}
		people[e.PersonID] = identity + "\x00" + e.Team
		emails[identity] = e.PersonID
		instances[e.InstanceID] = true
		for i, w := range e.Windows {
			if w.Start.IsZero() || !w.End.After(w.Start) || w.End.Sub(w.Start) > 31*24*time.Hour || (i > 0 && w.Start.Before(e.Windows[i-1].End)) {
				return nil, "", errors.New("windows must be ordered, nonoverlapping and at most 31 days")
			}
		}
	}
	canonical, _ := json.Marshal(roster)
	sum := sha256.Sum256(canonical)
	return &roster, hex.EncodeToString(sum[:]), nil
}
func label(s string) bool {
	return strings.TrimSpace(s) == s && len(s) > 0 && len(s) <= 256 && !strings.ContainsAny(s, "\r\n\t\x00")
}

type Checkin struct {
	OwnerEmail   string
	At           time.Time
	Active       bool
	RecoveryOnly bool
}
type Row struct {
	Entry
	State        string     `json:"state"`
	LastCheckin  *time.Time `json:"last_checkin,omitempty"`
	RecoveryOnly bool       `json:"recovery_only"`
}
type Report struct {
	SchemaVersion        int       `json:"schema_version"`
	RosterID             string    `json:"roster_id"`
	RosterRevision       string    `json:"roster_revision"`
	AsOf                 time.Time `json:"as_of"`
	ExpectedWorkstations int       `json:"expected_workstations"`
	FreshWorkstations    int       `json:"fresh_workstations"`
	ExpectedPeople       int       `json:"expected_people"`
	Rows                 []Row     `json:"rows"`
	Scope                string    `json:"scope"`
	HistoryDurable       bool      `json:"history_durable"`
}

func Evaluate(roster *Roster, revision string, now time.Time, observed map[string][]Checkin) Report {
	r := Report{SchemaVersion: 1, RosterID: roster.RosterID, RosterRevision: revision, AsOf: now.UTC(), Rows: make([]Row, 0, len(roster.Entries)), Scope: "Current registry enrollment/liveness check-ins only; not prompt, operation, enforcement or work completion coverage. Server restart may lose observations."}
	people := map[string]bool{}
	for _, e := range roster.Entries {
		row := Row{Entry: e, State: "not_expected"}
		var start time.Time
		for _, w := range e.Windows {
			if !now.Before(w.Start) && now.Before(w.End) {
				start = w.Start
				break
			}
		}
		if !start.IsZero() {
			r.ExpectedWorkstations++
			people[e.PersonID] = true
			row.State = "missing"
			conflict := false
			for _, c := range observed[e.InstanceID] {
				if !strings.EqualFold(c.OwnerEmail, e.OwnerEmail) {
					conflict = true
					continue
				}
				if c.At.IsZero() || c.At.After(now) {
					continue
				}
				if row.LastCheckin == nil || c.At.After(*row.LastCheckin) {
					stamp := c.At
					row.LastCheckin = &stamp
					row.RecoveryOnly = c.RecoveryOnly
				}
				if !c.At.Before(start) && now.Sub(c.At) <= time.Duration(roster.FreshnessSeconds)*time.Second && c.Active {
					row.State = "fresh"
				}
			}
			if conflict {
				row.State = "ownership_conflict"
			} else if row.State != "fresh" && row.LastCheckin != nil {
				row.State = "stale"
			}
			if row.State == "fresh" {
				r.FreshWorkstations++
			}
		}
		r.Rows = append(r.Rows, row)
	}
	r.ExpectedPeople = len(people)
	return r
}
