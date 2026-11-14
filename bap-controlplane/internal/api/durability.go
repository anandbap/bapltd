package api

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"bap-controlplane/internal/audit"
	"bap-controlplane/internal/policy"
)

// A single-node compatibility backend using the existing SQLite pool. The checkpoint and new
// canonical ledger links commit in one transaction before an API response is released. This is
// deliberately NOT a multi-replica PostgreSQL implementation. A generation comparison fences a
// mistakenly started second writer rather than acknowledging divergent authority.
type durableState struct {
	mu         sync.Mutex
	db         *sql.DB
	generation int64
	auditCount int
	failure    error
}

type checkpointCodec interface {
	MarshalCheckpoint() ([]byte, error)
	RestoreCheckpoint([]byte) error
}

type authorityCheckpoint struct {
	Schema        int                        `json:"schema"`
	TokenIdentity string                     `json:"token_identity"`
	PolicyKey     string                     `json:"policy_key"`
	PolicyPublic  string                     `json:"policy_public"`
	Stores        map[string]json.RawMessage `json:"stores"`
	Restorations  map[string]bool            `json:"restorations"`
}

func (s *Server) checkpointStores() map[string]checkpointCodec {
	return map[string]checkpointCodec{"registry": s.registry, "policy": s.policyStore, "sessions": s.sessionStore,
		"tokens": s.minter, "otc": s.otcStore, "governance": s.govStore, "escalations": s.escalationMgr}
}

// EnableDurability must run before serving. Existing standalone session tables are retained for
// compatibility; once enabled, the complete checkpoint is authoritative on restart.
func (s *Server) EnableDurability(allowInitialize bool) error {
	db := s.sessionStore.PersistenceDB()
	if db == nil {
		return fmt.Errorf("durable authority requires a persistent database")
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS authority_checkpoint (id INTEGER PRIMARY KEY CHECK(id=1), generation INTEGER NOT NULL, payload BLOB NOT NULL, digest TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS authority_audit (sequence INTEGER PRIMARY KEY, event_id TEXT NOT NULL UNIQUE, payload BLOB NOT NULL);`); err != nil {
		return err
	}
	d := &durableState{db: db}
	var raw []byte
	var digest string
	err := db.QueryRow(`SELECT generation, payload, digest FROM authority_checkpoint WHERE id=1`).Scan(&d.generation, &raw, &digest)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if err == sql.ErrNoRows && !allowInitialize {
		return fmt.Errorf("authority checkpoint missing; restore the approved database or explicitly initialize a new isolated authority")
	}
	if err == nil {
		if fmt.Sprintf("%x", sha256.Sum256(raw)) != digest {
			return fmt.Errorf("authority checkpoint integrity mismatch")
		}
		var checkpoint authorityCheckpoint
		if err := json.Unmarshal(raw, &checkpoint); err != nil {
			return err
		}
		if checkpoint.Schema != 1 || checkpoint.TokenIdentity != s.minter.CheckpointIdentity() {
			return fmt.Errorf("authority checkpoint schema or token-signing identity changed; restore deployment configuration")
		}
		key := ""
		if signer := s.policyStore.Signer(); signer != nil {
			key = signer.KeyID()
		}
		if checkpoint.PolicyKey != key {
			signer := s.policyStore.Signer()
			if signer == nil {
				return fmt.Errorf("authority checkpoint policy signer is missing")
			}
			pub, valid := policy.VerifyRotationChain(checkpoint.PolicyKey, checkpoint.PolicyPublic, signer.Chain(), key)
			if !valid || pub != signer.PublicKeyB64() {
				return fmt.Errorf("authority checkpoint policy-signing identity changed without an authenticated rotation chain")
			}
		}
		for name, codec := range s.checkpointStores() {
			if len(checkpoint.Stores[name]) == 0 {
				return fmt.Errorf("authority checkpoint missing %s", name)
			}
			if err := codec.RestoreCheckpoint(checkpoint.Stores[name]); err != nil {
				return fmt.Errorf("restore %s: %w", name, err)
			}
		}
		s.recoveryRestores = checkpoint.Restorations
	}
	rows, err := db.Query(`SELECT sequence, payload FROM authority_audit ORDER BY sequence`)
	if err != nil {
		return err
	}
	var events []audit.Event
	for rows.Next() {
		var sequence int
		var raw []byte
		if err := rows.Scan(&sequence, &raw); err != nil {
			rows.Close()
			return err
		}
		var event audit.Event
		if err := json.Unmarshal(raw, &event); err != nil {
			rows.Close()
			return err
		}
		if sequence != len(events)+1 {
			rows.Close()
			return fmt.Errorf("audit sequence gap")
		}
		events = append(events, event)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if d.generation == 0 && len(events) != 0 {
		return fmt.Errorf("audit history exists without its authority checkpoint")
	}
	if err := s.auditStore.RestoreCheckpoint(events); err != nil {
		return err
	}
	s.sessionStore.RestoreEventDetails(events)
	d.auditCount = len(events)
	s.durable = d
	s.policyStore.UseCheckpointPersistence()
	return s.commitAuthority()
}

func (s *Server) commitAuthority() error {
	d := s.durable
	checkpoint := authorityCheckpoint{Schema: 1, TokenIdentity: s.minter.CheckpointIdentity(), Stores: map[string]json.RawMessage{}}
	if signer := s.policyStore.Signer(); signer != nil {
		checkpoint.PolicyKey = signer.KeyID()
		checkpoint.PolicyPublic = signer.PublicKeyB64()
	}
	for name, codec := range s.checkpointStores() {
		raw, err := codec.MarshalCheckpoint()
		if err != nil {
			return err
		}
		checkpoint.Stores[name] = raw
	}
	s.recoveryMu.Lock()
	checkpoint.Restorations = make(map[string]bool, len(s.recoveryRestores))
	for k, v := range s.recoveryRestores {
		checkpoint.Restorations[k] = v
	}
	s.recoveryMu.Unlock()
	raw, err := json.Marshal(checkpoint)
	if err != nil {
		return err
	}
	events, count, err := s.auditStore.CheckpointSuffix(d.auditCount)
	if err != nil {
		return err
	}
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var result sql.Result
	digest := fmt.Sprintf("%x", sha256.Sum256(raw))
	if d.generation == 0 {
		result, err = tx.Exec(`INSERT INTO authority_checkpoint(id,generation,payload,digest) VALUES(1,1,?,?)`, raw, digest)
	} else {
		result, err = tx.Exec(`UPDATE authority_checkpoint SET generation=generation+1,payload=?,digest=? WHERE id=1 AND generation=?`, raw, digest, d.generation)
	}
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return fmt.Errorf("authority writer generation conflict")
	}
	for i, event := range events {
		payload, err := json.Marshal(event)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO authority_audit(sequence,event_id,payload) VALUES(?,?,?)`, d.auditCount+i+1, event.EventID, payload); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	d.generation++
	d.auditCount = count
	return nil
}

func (s *Server) serveDurably(w http.ResponseWriter, r *http.Request) {
	if s.durable == nil {
		s.mux.ServeHTTP(w, r)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") && r.URL.Path != "/health" {
		s.mux.ServeHTTP(w, r)
		return
	}
	d := s.durable
	// Streaming reads cannot hold the authority lock for their lifetime. They never issue grants
	// or acknowledge mutations. Every ordinary API read is serialized with writes.
	if strings.HasSuffix(r.URL.Path, "/activity/stream") {
		s.mux.ServeHTTP(w, r)
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failure != nil {
		writeError(w, 503, "Durable authority unavailable; operator must restore storage and restart")
		return
	}
	recorded := httptest.NewRecorder()
	s.mux.ServeHTTP(recorded, r)
	// Some GET routes consume login state, so commit all API responses rather than guessing
	// mutation from the HTTP method. Even a rejected request can have security audit evidence.
	if err := s.commitAuthority(); err != nil {
		d.failure = err
		writeError(w, 503, "Authority change was not durably confirmed; operator must restore storage and restart")
		return
	}
	for key, values := range recorded.Header() {
		w.Header()[key] = values
	}
	w.Header().Set("X-BAP-Durability", "committed")
	w.WriteHeader(recorded.Code)
	_, _ = w.Write(recorded.Body.Bytes())
}
