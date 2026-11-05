package discovery

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Reports contain metadata only. Free-form details, command arguments, environment
// values and arbitrary server-side paths are intentionally absent from the wire.
type ScopeResult struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}
type Observation struct {
	Key         string    `json:"key"`
	Scope       string    `json:"scope"`
	Kind        string    `json:"kind"`
	Name        string    `json:"name"`
	Client      string    `json:"client"`
	Evidence    string    `json:"evidence"`
	ObservedAt  time.Time `json:"observed_at"`
	PID         int       `json:"pid,omitempty"`
	Birth       string    `json:"birth,omitempty"`
	OperationID string    `json:"operation_id,omitempty"`
	Outcome     string    `json:"outcome,omitempty"`
}
type Report struct {
	Version      int           `json:"version"`
	RunID        string        `json:"run_id"`
	Epoch        int64         `json:"epoch"`
	StartedAt    time.Time     `json:"started_at"`
	CompletedAt  time.Time     `json:"completed_at"`
	Status       string        `json:"status"`
	Scopes       []ScopeResult `json:"scopes"`
	Observations []Observation `json:"observations"`
}
type Asset struct {
	ID         string `json:"id"`
	InstanceID string `json:"instance_id"`
	Owner      string `json:"owner"`
	Observation
	FirstSeen      time.Time  `json:"first_seen"`
	LastSeen       time.Time  `json:"last_seen"`
	LastCompleteAt time.Time  `json:"last_complete_at"`
	State          string     `json:"state"`
	Mediation      string     `json:"mediation"`
	Approval       string     `json:"approval"`
	Disposition    string     `json:"disposition,omitempty"`
	Reason         string     `json:"reason,omitempty"`
	Actor          string     `json:"actor,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
}
type ScanState struct {
	InstanceID string `json:"instance_id"`
	Owner      string `json:"owner"`
	Report
	ReceivedAt time.Time `json:"received_at"`
}
type directive struct {
	Epoch   int64            `json:"epoch"`
	Fleet   int64            `json:"fleet"`
	Targets map[string]int64 `json:"targets"`
}
type Inventory struct {
	mu        sync.RWMutex
	db        *sql.DB
	assets    map[string]Asset
	latest    map[string]ScanState
	seen      map[string]string
	directive directive
	revision  uint64
}

var ErrConflict = errors.New("discovery run ID already has different content")

func NewInventory(db *sql.DB) (*Inventory, error) {
	s := &Inventory{db: db, assets: map[string]Asset{}, latest: map[string]ScanState{}, seen: map[string]string{}, revision: uint64(time.Now().UnixMicro())}
	if db == nil {
		return s, nil
	}
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS discovery_assets (id TEXT PRIMARY KEY, body TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS discovery_runs (id TEXT PRIMARY KEY, digest TEXT NOT NULL, instance_id TEXT NOT NULL, completed_at TEXT NOT NULL, body TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS discovery_runs_instance ON discovery_runs(instance_id,completed_at)`,
		`CREATE TABLE IF NOT EXISTS discovery_directive (id INTEGER PRIMARY KEY, body TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS discovery_latest (instance_id TEXT PRIMARY KEY, body TEXT NOT NULL)`,
	} {
		if _, err := db.Exec(q); err != nil {
			return nil, err
		}
	}
	rows, err := db.Query(`SELECT body FROM discovery_assets`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var body string
		var a Asset
		if err := rows.Scan(&body); err != nil {
			rows.Close()
			return nil, err
		}
		if json.Unmarshal([]byte(body), &a) != nil {
			rows.Close()
			return nil, errors.New("invalid persisted discovery asset")
		}
		s.assets[a.ID] = a
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	rows, err = db.Query(`SELECT body FROM discovery_latest`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var body string
		var st ScanState
		if err := rows.Scan(&body); err != nil {
			rows.Close()
			return nil, err
		}
		if json.Unmarshal([]byte(body), &st) != nil {
			rows.Close()
			return nil, errors.New("invalid persisted discovery run")
		}
		if _, ok := s.latest[st.InstanceID]; !ok {
			s.latest[st.InstanceID] = st
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	var raw string
	if err := db.QueryRow(`SELECT body FROM discovery_directive WHERE id=1`).Scan(&raw); err == nil {
		if json.Unmarshal([]byte(raw), &s.directive) != nil {
			return nil, errors.New("invalid discovery directive")
		}
	} else if err != sql.ErrNoRows {
		return nil, err
	}
	return s, nil
}

func safeField(v string, max int) bool {
	if len(v) > max {
		return false
	}
	for _, c := range v {
		if c < 32 || c == 127 {
			return false
		}
	}
	// Display labels are not a channel for authentication material.
	lower := strings.ToLower(v)
	return !strings.Contains(lower, "bearer ") && !strings.Contains(lower, "api_key=") && !strings.Contains(lower, "password=") && !strings.Contains(v, "-----BEGIN") && !strings.Contains(v, "eyJ")
}
func validID(v string) bool {
	if v == "" || len(v) > 160 {
		return false
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-_.:", c)) {
			return false
		}
	}
	return true
}
func ValidateReport(r Report) error {
	if r.Version != 1 || !validID(r.RunID) || r.Epoch < 0 || r.StartedAt.IsZero() || r.CompletedAt.Before(r.StartedAt) || r.CompletedAt.After(time.Now().Add(5*time.Minute)) {
		return errors.New("invalid discovery run identity or time")
	}
	if r.Status != "complete" && r.Status != "partial" && r.Status != "failed" {
		return errors.New("invalid scan status")
	}
	if len(r.Scopes) == 0 || len(r.Scopes) > 64 || len(r.Observations) > 512 {
		return errors.New("discovery scope or observation limit exceeded")
	}
	scopes := map[string]string{}
	for _, scope := range r.Scopes {
		if !validID(scope.ID) || scopes[scope.ID] != "" {
			return errors.New("invalid or duplicate scope")
		}
		if scope.Status != "complete" && scope.Status != "error" && scope.Status != "unsupported" {
			return errors.New("invalid scope result")
		}
		if r.Status == "complete" && scope.Status != "complete" {
			return errors.New("complete report has incomplete scope")
		}
		scopes[scope.ID] = scope.Status
	}
	keys := map[string]bool{}
	for _, o := range r.Observations {
		if !validID(o.Key) || scopes[o.Scope] == "" || keys[o.Key] || !safeField(o.Name, 120) || o.Name == "" || !safeField(o.Client, 40) || o.ObservedAt.IsZero() || o.ObservedAt.After(r.CompletedAt.Add(time.Second)) || o.ObservedAt.Before(r.StartedAt.Add(-time.Second)) {
			return errors.New("invalid discovery observation")
		}
		keys[o.Key] = true
		if o.Kind != "mcp_config" && o.Kind != "agent_process" && o.Kind != "mcp_call" && o.Kind != "agent_plugin" {
			return errors.New("unsupported discovery asset kind")
		}
		if (o.Kind == "mcp_config" && o.Evidence != "configured") || (o.Kind == "agent_process" && o.Evidence != "running") || (o.Kind == "mcp_call" && o.Evidence != "invocation") || (o.Kind == "agent_plugin" && o.Evidence == "") {
			return errors.New("evidence does not match asset kind")
		}
		if o.Kind == "agent_process" && (o.PID <= 0 || !validID(o.Birth)) {
			return errors.New("process birth required")
		}
		if o.Kind == "mcp_call" && (!validID(o.OperationID) || (o.Outcome != "attempted" && o.Outcome != "succeeded" && o.Outcome != "failed" && o.Outcome != "denied")) {
			return errors.New("invalid invocation evidence")
		}
	}
	return nil
}
func assetID(instance, key string) string {
	sum := sha256.Sum256([]byte(instance + "\x00" + key))
	return hex.EncodeToString(sum[:16])
}

// SQL commit precedes cache mutation. No API entry performs filesystem scanning.
func isHexSuffix(s string) bool {
	if len(s) != 8 && len(s) != 12 && len(s) != 16 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func hostPrefix(instance string) string {
	if idx := strings.LastIndex(instance, "-"); idx != -1 {
		suffix := instance[idx+1:]
		if isHexSuffix(suffix) {
			return instance[:idx]
		}
	}
	return ""
}

func (s *Inventory) Ingest(instance, owner string, r Report) (bool, error) {
	if err := ValidateReport(r); err != nil {
		return false, err
	}
	if instance == "" {
		return false, errors.New("workstation required")
	}
	raw, _ := json.Marshal(r)
	// Keep immutable copies even when an in-process producer reuses its slices.
	var immutable Report
	_ = json.Unmarshal(raw, &immutable)
	r = immutable
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	runKey := instance + "/" + r.RunID
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := s.seen[runKey]
	if previous == "" && s.db != nil {
		err := s.db.QueryRow(`SELECT digest FROM discovery_runs WHERE id=?`, runKey).Scan(&previous)
		if err != nil && err != sql.ErrNoRows {
			return false, err
		}
	}
	if previous != "" {
		if previous != digest {
			return false, ErrConflict
		}
		return true, nil
	}
	newAssets := 0
	for _, o := range r.Observations {
		if _, ok := s.assets[assetID(instance, o.Key)]; !ok {
			newAssets++
		}
	}
	if len(s.assets)+newAssets > 20000 || len(s.latest) >= 2000 && s.latest[instance].RunID == "" {
		return false, errors.New("discovery inventory capacity reached")
	}

	// Purge stale/superseded instance assets from the exact same host
	hPrefix := hostPrefix(instance)
	if hPrefix != "" {
		for oldID, oldAsset := range s.assets {
			if oldAsset.InstanceID != instance && hostPrefix(oldAsset.InstanceID) == hPrefix {
				delete(s.assets, oldID)
				if s.db != nil {
					_, _ = s.db.Exec(`DELETE FROM discovery_assets WHERE id = ?`, oldID)
				}
			}
		}
	}
	changes := map[string]Asset{}
	present := map[string]bool{}
	for _, o := range r.Observations {
		id := assetID(instance, o.Key)
		present[id] = true
		a, ok := s.assets[id]
		if ok && (o.ObservedAt.Before(a.LastSeen) || o.ObservedAt.Before(a.LastCompleteAt)) {
			continue
		}
		if !ok {
			a = Asset{ID: id, InstanceID: instance, Owner: owner, FirstSeen: o.ObservedAt, Approval: "unreviewed"}
		}
		a.Observation = o
		a.LastSeen = o.ObservedAt
		a.State = "present"
		a.Mediation = "observation_only"
		if o.Kind == "mcp_config" {
			a.Mediation = "not_observed"
		}
		changes[id] = a
	}
	last := s.latest[instance]
	// A late historical report cannot supersede current scan state or resolve it.
	runtimeOnly := len(r.Scopes) == 1 && r.Scopes[0].ID == "native-mcp"
	newLatest := !runtimeOnly && (r.CompletedAt.After(last.CompletedAt) || last.RunID == "")
	if newLatest && r.Status != "failed" {
		complete := map[string]bool{}
		for _, scope := range r.Scopes {
			complete[scope.ID] = scope.Status == "complete"
		}
		for id, a := range s.assets {
			if a.InstanceID == instance && a.Kind != "mcp_call" && complete[a.Scope] && !present[id] && r.CompletedAt.After(a.LastSeen) {
				a.State = "not_seen"
				a.LastCompleteAt = r.CompletedAt
				changes[id] = a
			}
		}
	}
	st := ScanState{InstanceID: instance, Owner: owner, Report: r, ReceivedAt: time.Now().UTC()}
	if s.db != nil {
		tx, err := s.db.Begin()
		if err != nil {
			return false, err
		}
		defer tx.Rollback()
		for id, a := range changes {
			body, _ := json.Marshal(a)
			if _, err = tx.Exec(`INSERT INTO discovery_assets(id,body) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body`, id, string(body)); err != nil {
				return false, err
			}
		}
		body, _ := json.Marshal(st)
		if _, err = tx.Exec(`INSERT INTO discovery_runs(id,digest,instance_id,completed_at,body) VALUES(?,?,?,?,?)`, runKey, digest, instance, r.CompletedAt.UTC().Format(time.RFC3339Nano), string(body)); err != nil {
			return false, err
		}
		if newLatest {
			if _, err = tx.Exec(`INSERT INTO discovery_latest(instance_id,body) VALUES(?,?) ON CONFLICT(instance_id) DO UPDATE SET body=excluded.body`, instance, string(body)); err != nil {
				return false, err
			}
		}
		if err = tx.Commit(); err != nil {
			return false, err
		}
	}
	for id, a := range changes {
		s.assets[id] = a
	}
	if newLatest {
		s.latest[instance] = st
	}
	if len(s.seen) >= 20000 {
		s.seen = map[string]string{}
	}
	s.seen[runKey] = digest
	s.revision++
	return false, nil
}
func (s *Inventory) Trigger(scope string, instances []string) (int64, error) {
	if scope != "fleet" && scope != "selected" || scope == "selected" && (len(instances) == 0 || len(instances) > 200) {
		return 0, errors.New("explicit fleet or selected workstation scope required")
	}
	for _, id := range instances {
		if !validID(id) {
			return 0, errors.New("invalid workstation ID")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	epoch := time.Now().UnixMilli()
	if epoch <= s.directive.Epoch {
		epoch = s.directive.Epoch + 1
	}
	d := directive{Epoch: epoch, Fleet: s.directive.Fleet, Targets: map[string]int64{}}
	for id, value := range s.directive.Targets {
		d.Targets[id] = value
	}
	if scope == "fleet" {
		d.Fleet = epoch
		d.Targets = map[string]int64{}
	} else {
		for _, id := range instances {
			d.Targets[id] = epoch
		}
	}
	if len(d.Targets) > 2000 {
		return 0, errors.New("directive capacity reached")
	}
	if s.db != nil {
		body, _ := json.Marshal(d)
		if _, err := s.db.Exec(`INSERT INTO discovery_directive(id,body) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body`, string(body)); err != nil {
			return 0, err
		}
	}
	s.directive = d
	return epoch, nil
}
func (s *Inventory) EpochFor(instance string) int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.directive.Targets[instance] > s.directive.Fleet {
		return s.directive.Targets[instance]
	}
	return s.directive.Fleet
}

type Page struct {
	Findings []Asset `json:"findings"`
	Count    int     `json:"count"`
	Total    int     `json:"total"`
	Next     string  `json:"next_cursor,omitempty"`
	Revision uint64  `json:"revision"`
}

// Cursor is a last ID and dataset revision; changes require an explicit refresh.
func (s *Inventory) List(instance, kind, state, after string, limit int, revision uint64) (Page, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p := Page{Findings: []Asset{}, Revision: s.revision}
	if revision != 0 && revision != s.revision {
		return p, ErrConflict
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	type dedupKey struct {
		host string
		kind string
		name string
	}
	latestByEntity := make(map[dedupKey]Asset)
	for _, a := range s.assets {
		if instance != "" && a.InstanceID != instance || kind != "" && a.Kind != kind || state != "" && a.State != state {
			continue
		}
		host := a.InstanceID
		if instance == "" {
			if pfx := hostPrefix(a.InstanceID); pfx != "" {
				host = pfx
			}
		}
		k := dedupKey{host: host, kind: a.Kind, name: a.Name}
		existing, ok := latestByEntity[k]
		if !ok || a.LastSeen.After(existing.LastSeen) || (a.State == "present" && existing.State != "present") {
			latestByEntity[k] = a
		}
	}
	var ids []string
	filteredAssets := make(map[string]Asset, len(latestByEntity))
	for _, a := range latestByEntity {
		ids = append(ids, a.ID)
		filteredAssets[a.ID] = a
	}
	sort.Strings(ids)
	p.Total = len(ids)
	for _, id := range ids {
		if id <= after {
			continue
		}
		if len(p.Findings) == limit {
			p.Next = p.Findings[len(p.Findings)-1].ID
			break
		}
		p.Findings = append(p.Findings, filteredAssets[id])
	}
	p.Count = len(p.Findings)
	return p, nil
}
func (s *Inventory) Reports() []ScanState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ScanState, 0, len(s.latest))
	for _, r := range s.latest {
		r.Observations = nil
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ReceivedAt.After(out[j].ReceivedAt) })
	return out
}
func (s *Inventory) Summary(expected []string) map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now().UTC()
	fresh, partial, stale, notScanned, open := 0, 0, 0, 0, 0
	for _, id := range expected {
		r, ok := s.latest[id]
		if !ok {
			notScanned++
			continue
		}
		if now.Sub(r.CompletedAt) > 10*time.Minute {
			stale++
		} else if r.Status != "complete" {
			partial++
		} else {
			fresh++
		}
	}
	for _, a := range s.assets {
		if a.State == "present" && a.Disposition != "acknowledged" && (a.Disposition != "exception" || a.ExpiresAt == nil || now.After(*a.ExpiresAt)) {
			open++
		}
	}
	return map[string]any{"open_findings": open, "assets": len(s.assets), "expected_workstations": len(expected), "fresh_workstations": fresh, "partial_workstations": partial, "stale_workstations": stale, "not_scanned_workstations": notScanned, "revision": s.revision, "storage": s.Storage(), "durable": false, "server_time": now}
}
func (s *Inventory) Storage() string {
	if s.db != nil {
		return "sqlite"
	}
	return "memory"
}
func (s *Inventory) Disposition(id, state, reason string, expires *time.Time) error {
	if state != "acknowledged" && state != "exception" && state != "open" {
		return errors.New("invalid disposition")
	}
	if !safeField(reason, 240) || strings.TrimSpace(reason) == "" {
		return errors.New("reason required")
	}
	if state == "exception" && (expires == nil || !expires.After(time.Now()) || expires.After(time.Now().Add(30*24*time.Hour))) {
		return errors.New("exception must expire within 30 days")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.assets[id]
	if !ok {
		return fmt.Errorf("asset not found")
	}
	a.Disposition = state
	a.Reason = reason
	a.Actor = "authenticated-operator"
	a.ExpiresAt = expires
	if s.db != nil {
		body, _ := json.Marshal(a)
		if _, err := s.db.Exec(`UPDATE discovery_assets SET body=? WHERE id=?`, string(body), id); err != nil {
			return err
		}
	}
	s.assets[id] = a
	s.revision++
	return nil
}
