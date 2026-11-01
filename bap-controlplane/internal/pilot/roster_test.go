package pilot

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestTwentyWorkstationDenominatorAndMultipleMachinesPerPerson(t *testing.T) {
	now := time.Now().UTC()
	roster := fixture(now)
	roster.Entries = nil
	observed := map[string][]Checkin{}
	for i := 0; i < 20; i++ {
		e := fixture(now).Entries[0]
		e.InstanceID = fmt.Sprintf("station-%02d", i)
		e.PersonID = fmt.Sprintf("person-%02d", i/2)
		e.OwnerEmail = e.PersonID + "@example.test"
		roster.Entries = append(roster.Entries, e)
		if i < 18 {
			observed[e.InstanceID] = []Checkin{{OwnerEmail: e.OwnerEmail, At: now.Add(-time.Second), Active: true}}
		}
	}
	b, _ := json.Marshal(roster)
	decoded, revision, err := Decode(strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	out := Evaluate(decoded, revision, now, observed)
	if out.ExpectedWorkstations != 20 || out.ExpectedPeople != 10 || out.FreshWorkstations != 18 || len(out.Rows) != 20 {
		t.Fatal(out)
	}
	// An otherwise fresh observation from before the window cannot qualify.
	decoded.Entries[0].Windows[0].Start = now.Add(-500 * time.Millisecond)
	out = Evaluate(decoded, revision, now, observed)
	if out.FreshWorkstations != 17 || out.Rows[0].State != "stale" {
		t.Fatal(out)
	}
}

func fixture(now time.Time) Roster {
	return Roster{SchemaVersion: 1, RosterID: "pilot", FreshnessSeconds: 60, Entries: []Entry{{PersonID: "person", OwnerEmail: "person@example.test", Team: "engineering", InstanceID: "station", Windows: []Window{{Start: now.Add(-time.Hour), End: now.Add(time.Hour)}}}}}
}
func TestRosterRejectsAmbiguousDenominators(t *testing.T) {
	now := time.Now().UTC()
	for _, name := range []string{"empty", "duplicate-instance", "conflicting-person", "conflicting-email", "overlap", "unbounded-window", "bad-freshness"} {
		t.Run(name, func(t *testing.T) {
			r := fixture(now)
			switch name {
			case "empty":
				r.Entries = nil
			case "duplicate-instance":
				r.Entries = append(r.Entries, r.Entries[0])
			case "conflicting-person":
				e := r.Entries[0]
				e.InstanceID = "second"
				e.OwnerEmail = "other@example.test"
				r.Entries = append(r.Entries, e)
			case "conflicting-email":
				e := r.Entries[0]
				e.InstanceID = "second"
				e.PersonID = "other"
				r.Entries = append(r.Entries, e)
			case "overlap":
				r.Entries[0].Windows = append(r.Entries[0].Windows, r.Entries[0].Windows[0])
			case "unbounded-window":
				r.Entries[0].Windows[0].End = now.Add(32 * 24 * time.Hour)
			case "bad-freshness":
				r.FreshnessSeconds = 0
			}
			b, _ := json.Marshal(r)
			if _, _, err := Decode(strings.NewReader(string(b))); err == nil {
				t.Fatal("invalid roster accepted")
			}
		})
	}
	r := fixture(now)
	b, _ := json.Marshal(r)
	for _, data := range []string{string(b) + "{}", strings.Replace(string(b), `"schema_version":1`, `"schema_version":1,"ignored":true`, 1), strings.Repeat(" ", (1<<20)+1)} {
		if _, _, err := Decode(strings.NewReader(data)); err == nil {
			t.Fatal("invalid stream accepted")
		}
	}
	_, revision, err := Decode(strings.NewReader(string(b)))
	if err != nil || len(revision) != 64 {
		t.Fatal(revision, err)
	}
}

func TestCoverageUsesExactOwnerWindowAndActiveCheckin(t *testing.T) {
	now := time.Now().UTC()
	r := fixture(now)
	for _, tc := range []struct {
		name     string
		checkins []Checkin
		want     string
	}{
		{"missing", nil, "missing"},
		{"fresh", []Checkin{{OwnerEmail: "PERSON@example.test", At: now.Add(-time.Second), Active: true}}, "fresh"},
		{"stale", []Checkin{{OwnerEmail: "person@example.test", At: now.Add(-2 * time.Minute), Active: true}}, "stale"},
		{"before-window", []Checkin{{OwnerEmail: "person@example.test", At: now.Add(-2 * time.Hour), Active: true}}, "stale"},
		{"restricted", []Checkin{{OwnerEmail: "person@example.test", At: now, Active: false}}, "stale"},
		{"future", []Checkin{{OwnerEmail: "person@example.test", At: now.Add(time.Second), Active: true}}, "missing"},
		{"wrong-owner", []Checkin{{OwnerEmail: "other@example.test", At: now, Active: true}}, "ownership_conflict"},
		{"ambiguous", []Checkin{{OwnerEmail: "other@example.test", At: now, Active: true}, {OwnerEmail: "person@example.test", At: now, Active: true}}, "ownership_conflict"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := Evaluate(&r, "revision", now, map[string][]Checkin{"station": tc.checkins, "unrostered": {{At: now, Active: true}}})
			if out.Rows[0].State != tc.want || out.ExpectedWorkstations != 1 || out.ExpectedPeople != 1 || out.HistoryDurable {
				t.Fatal(out)
			}
			want := 0
			if tc.want == "fresh" {
				want = 1
			}
			if out.FreshWorkstations != want {
				t.Fatal(out)
			}
		})
	}
	out := Evaluate(&r, "revision", r.Entries[0].Windows[0].End, nil)
	if out.ExpectedWorkstations != 0 || out.Rows[0].State != "not_expected" {
		t.Fatal(out)
	}
}
