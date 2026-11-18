package session

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"bap-controlplane/pkg/types"
)

// EnsureZSPGrantsSchema creates the zsp_grants SQLite table and indexes if not exists.
func (s *Store) EnsureZSPGrantsSchema() error {
	if s.db == nil {
		return nil
	}
	schema := `
	CREATE TABLE IF NOT EXISTS zsp_grants (
		grant_id TEXT PRIMARY KEY,
		envelope_id TEXT NOT NULL,
		session_id TEXT NOT NULL,
		principal_svid TEXT NOT NULL,
		human_owner TEXT NOT NULL,
		allowed_actions TEXT NOT NULL,
		allowed_resources TEXT NOT NULL,
		requested_actions TEXT,
		requested_resources TEXT,
		narrowing_applied INTEGER DEFAULT 0,
		narrowing_reason TEXT,
		max_uses INTEGER DEFAULT 1,
		remaining_uses INTEGER DEFAULT 1,
		issued_at TEXT NOT NULL,
		expires_at TEXT NOT NULL,
		delegation_type TEXT,
		client_type TEXT,
		is_burned INTEGER DEFAULT 0,
		burn_reason TEXT,
		consumed_cmd TEXT,
		receipt_id TEXT,
		authority_signature TEXT,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		grant_class TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_zsp_grants_session ON zsp_grants(session_id);
	CREATE INDEX IF NOT EXISTS idx_zsp_grants_issued ON zsp_grants(issued_at);
	`
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}
	// BAP-1102: databases created before grant classes gain the column; a duplicate-column error on
	// an up-to-date database is expected and ignored.
	_, _ = s.db.Exec(`ALTER TABLE zsp_grants ADD COLUMN grant_class TEXT`)
	return nil
}

// SaveZSPGrant persists or updates a TaskGrant with full rich details.
func (s *Store) SaveZSPGrant(g *types.TaskGrant) error {
	if g == nil || g.GrantID == "" {
		return fmt.Errorf("grant and grant_id cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.zspGrants == nil {
		s.zspGrants = make(map[string]*types.TaskGrant)
	}
	s.zspGrants[g.GrantID] = g

	if s.db == nil {
		return nil
	}

	allowedActionsJSON, _ := json.Marshal(g.AllowedActions)
	allowedResourcesJSON, _ := json.Marshal(g.AllowedResources)
	requestedActionsJSON, _ := json.Marshal(g.RequestedActions)
	requestedResourcesJSON, _ := json.Marshal(g.RequestedResources)

	narrowingInt := 0
	if g.NarrowingApplied {
		narrowingInt = 1
	}
	isBurnedInt := 0
	if g.IsBurned {
		isBurnedInt = 1
	}

	issuedAtStr := g.IssuedAt.UTC().Format(time.RFC3339Nano)
	expiresAtStr := g.ExpiresAt.UTC().Format(time.RFC3339Nano)
	nowStr := time.Now().UTC().Format(time.RFC3339Nano)

	query := `
	INSERT INTO zsp_grants (
		grant_id, envelope_id, session_id, principal_svid, human_owner,
		allowed_actions, allowed_resources, requested_actions, requested_resources,
		narrowing_applied, narrowing_reason, max_uses, remaining_uses,
		issued_at, expires_at, delegation_type, client_type,
		is_burned, burn_reason, consumed_cmd, receipt_id, authority_signature,
		created_at, updated_at, grant_class
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(grant_id) DO UPDATE SET
		grant_class = COALESCE(NULLIF(excluded.grant_class, ''), zsp_grants.grant_class),
		remaining_uses = excluded.remaining_uses,
		is_burned = excluded.is_burned,
		burn_reason = excluded.burn_reason,
		consumed_cmd = COALESCE(NULLIF(excluded.consumed_cmd, ''), zsp_grants.consumed_cmd),
		receipt_id = COALESCE(NULLIF(excluded.receipt_id, ''), zsp_grants.receipt_id),
		updated_at = excluded.updated_at;
	`

	_, err := s.db.Exec(query,
		g.GrantID, g.EnvelopeID, g.SessionID, g.PrincipalSVID, g.HumanOwner,
		string(allowedActionsJSON), string(allowedResourcesJSON),
		string(requestedActionsJSON), string(requestedResourcesJSON),
		narrowingInt, g.NarrowingReason, g.MaxUses, g.RemainingUses,
		issuedAtStr, expiresAtStr, g.DelegationType, g.ClientType,
		isBurnedInt, g.BurnReason, g.ConsumedCmd, g.ReceiptID, g.AuthoritySignature,
		nowStr, nowStr, g.GrantClass,
	)
	return err
}

// SaveZSPGrants persists a batch of TaskGrants.
func (s *Store) SaveZSPGrants(grants []*types.TaskGrant) error {
	for _, g := range grants {
		if err := s.SaveZSPGrant(g); err != nil {
			return err
		}
	}
	return nil
}

// GetZSPGrant returns a single grant with full details by ID.
func (s *Store) GetZSPGrant(grantID string) (*types.TaskGrant, error) {
	s.mu.RLock()
	if s.zspGrants != nil {
		if g, ok := s.zspGrants[grantID]; ok {
			s.mu.RUnlock()
			return g, nil
		}
	}
	s.mu.RUnlock()

	if s.db == nil {
		return nil, fmt.Errorf("grant %s not found", grantID)
	}

	query := `
	SELECT grant_id, envelope_id, session_id, principal_svid, human_owner,
	       allowed_actions, allowed_resources, requested_actions, requested_resources,
	       narrowing_applied, narrowing_reason, max_uses, remaining_uses,
	       issued_at, expires_at, delegation_type, client_type,
	       is_burned, burn_reason, consumed_cmd, receipt_id, authority_signature, grant_class
	FROM zsp_grants WHERE grant_id = ?
	`
	row := s.db.QueryRow(query, grantID)
	g, err := scanGrantRow(row)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	if s.zspGrants == nil {
		s.zspGrants = make(map[string]*types.TaskGrant)
	}
	s.zspGrants[g.GrantID] = g
	s.mu.Unlock()

	return g, nil
}

// ListZSPGrants returns grants matching sessionID (or all sessions if sessionID is empty).
func (s *Store) ListZSPGrants(sessionID string, limit int) ([]*types.TaskGrant, error) {
	if limit <= 0 {
		limit = 100
	}

	if s.db == nil {
		s.mu.RLock()
		defer s.mu.RUnlock()
		var res []*types.TaskGrant
		for _, g := range s.zspGrants {
			if sessionID == "" || strings.EqualFold(g.SessionID, sessionID) {
				res = append(res, g)
			}
		}
		sort.Slice(res, func(i, j int) bool {
			return res[i].IssuedAt.After(res[j].IssuedAt)
		})
		if len(res) > limit {
			res = res[:limit]
		}
		return res, nil
	}

	var rows *sql.Rows
	var err error
	if sessionID != "" {
		query := `
		SELECT grant_id, envelope_id, session_id, principal_svid, human_owner,
		       allowed_actions, allowed_resources, requested_actions, requested_resources,
		       narrowing_applied, narrowing_reason, max_uses, remaining_uses,
		       issued_at, expires_at, delegation_type, client_type,
		       is_burned, burn_reason, consumed_cmd, receipt_id, authority_signature, grant_class
		FROM zsp_grants WHERE session_id = ? ORDER BY issued_at DESC LIMIT ?
		`
		rows, err = s.db.Query(query, sessionID, limit)
	} else {
		query := `
		SELECT grant_id, envelope_id, session_id, principal_svid, human_owner,
		       allowed_actions, allowed_resources, requested_actions, requested_resources,
		       narrowing_applied, narrowing_reason, max_uses, remaining_uses,
		       issued_at, expires_at, delegation_type, client_type,
		       is_burned, burn_reason, consumed_cmd, receipt_id, authority_signature, grant_class
		FROM zsp_grants ORDER BY issued_at DESC LIMIT ?
		`
		rows, err = s.db.Query(query, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var grants []*types.TaskGrant
	for rows.Next() {
		g, err := scanGrantRows(rows)
		if err == nil {
			grants = append(grants, g)
		}
	}
	return grants, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanGrantRow(r rowScanner) (*types.TaskGrant, error) {
	var g types.TaskGrant
	var allowedActionsStr, allowedResourcesStr string
	var reqActionsStr, reqResourcesStr sql.NullString
	var narrowingInt, isBurnedInt int
	var issuedAtStr, expiresAtStr string
	var delegType, clientType sql.NullString
	var burnReason, consumedCmd, receiptID, authSig, grantClass sql.NullString

	err := r.Scan(
		&g.GrantID, &g.EnvelopeID, &g.SessionID, &g.PrincipalSVID, &g.HumanOwner,
		&allowedActionsStr, &allowedResourcesStr, &reqActionsStr, &reqResourcesStr,
		&narrowingInt, &g.NarrowingReason, &g.MaxUses, &g.RemainingUses,
		&issuedAtStr, &expiresAtStr, &delegType, &clientType,
		&isBurnedInt, &burnReason, &consumedCmd, &receiptID, &authSig, &grantClass,
	)
	if err != nil {
		return nil, err
	}

	_ = json.Unmarshal([]byte(allowedActionsStr), &g.AllowedActions)
	_ = json.Unmarshal([]byte(allowedResourcesStr), &g.AllowedResources)
	if reqActionsStr.Valid {
		_ = json.Unmarshal([]byte(reqActionsStr.String), &g.RequestedActions)
	}
	if reqResourcesStr.Valid {
		_ = json.Unmarshal([]byte(reqResourcesStr.String), &g.RequestedResources)
	}

	g.NarrowingApplied = narrowingInt == 1
	g.IsBurned = isBurnedInt == 1
	g.IssuedAt, _ = time.Parse(time.RFC3339Nano, issuedAtStr)
	g.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expiresAtStr)

	if delegType.Valid {
		g.DelegationType = delegType.String
	}
	if clientType.Valid {
		g.ClientType = clientType.String
	}
	if burnReason.Valid {
		g.BurnReason = burnReason.String
	}
	if consumedCmd.Valid {
		g.ConsumedCmd = consumedCmd.String
	}
	if receiptID.Valid {
		g.ReceiptID = receiptID.String
	}
	if authSig.Valid {
		g.AuthoritySignature = authSig.String
	}
	if grantClass.Valid {
		g.GrantClass = grantClass.String
	}

	return &g, nil
}

func scanGrantRows(rows *sql.Rows) (*types.TaskGrant, error) {
	return scanGrantRow(rows)
}
