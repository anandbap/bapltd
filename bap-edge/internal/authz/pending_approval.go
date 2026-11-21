package authz

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"bap-edge/pkg/types"
)

// Human-in-the-loop requests (BAP-936). When an agent asks for something in the `approve` tier it
// must not simply fail: BAP raises a persistent, reviewable REQUEST. The developer lists requests,
// approves or denies them in their own terminal (approval needs a real terminal and a one-time code),
// and the agent retries. Approval mints the same grant the agent asked for, bound to the same session.

var (
	ErrApprovalNotFound = errors.New("approval request not found")
	ErrApprovalDecided  = errors.New("approval request is not pending")
	ErrApprovalExpired  = errors.New("approval request has expired")
	ErrApprovalChanged  = errors.New("approval request changed since it was reviewed; review it again")
)

const defaultApprovalRequestTTL = 30 * time.Minute

// PendingApproval is one raised human-approval request.
type PendingApproval struct {
	ID                  string    `json:"id"`
	SessionID           string    `json:"session_id"`
	RequestingSessionID string    `json:"requesting_session_id,omitempty"`
	ClientType          string    `json:"client_type"`
	Mission             string    `json:"mission"`
	Goal                string    `json:"goal"`
	Actions             []string  `json:"actions"`
	Resources           []string  `json:"resources"`
	MaxUses             int       `json:"max_uses"`
	TTLSeconds          int       `json:"ttl_seconds"`
	Reason              string    `json:"reason"`
	Status              string    `json:"status"` // pending | approved | denied
	CreatedAt           time.Time `json:"created_at"`
	ExpiresAt           time.Time `json:"expires_at"`
	DecidedAt           time.Time `json:"decided_at,omitempty"`
	GrantID             string    `json:"grant_id,omitempty"`
}

func approvalsDir(zspDir string) string { return filepath.Join(zspDir, "approvals") }

func approvalPath(zspDir, id string) string {
	return filepath.Join(approvalsDir(zspDir), sanitizeZSPKey(id)+".json")
}

func approvalFingerprint(sessionID string, actions, resources []string) string {
	a := append([]string(nil), actions...)
	r := append([]string(nil), resources...)
	sort.Strings(a)
	sort.Strings(r)
	return sessionID + "|" + strings.Join(a, ",") + "|" + strings.Join(r, ",")
}

// RaisePendingApproval records a request, or returns the existing identical pending one so a retrying
// agent does not flood the developer with duplicates.
func RaisePendingApproval(zspDir string, p PendingApproval) (*PendingApproval, error) {
	if zspDir == "" {
		zspDir = ResolveZSPDir()
	}
	if len(p.Actions) == 0 {
		return nil, fmt.Errorf("%w: approval request needs at least one action", ErrInvalidEnvelope)
	}
	var out *PendingApproval
	effectiveRequester := func(pa PendingApproval) string {
		if pa.RequestingSessionID != "" {
			return pa.RequestingSessionID
		}
		return pa.SessionID
	}
	err := withZSPStoreLock(zspDir, "__approvals__", func() error {
		existing, _ := ListPendingApprovals(zspDir)
		fp := approvalFingerprint(p.SessionID+"\x00"+effectiveRequester(p)+"\x00"+p.ClientType, p.Actions, p.Resources)
		for i := range existing {
			e := existing[i]
			if e.Status == "pending" && time.Now().Before(e.ExpiresAt) && approvalFingerprint(e.SessionID+"\x00"+effectiveRequester(e)+"\x00"+e.ClientType, e.Actions, e.Resources) == fp {
				out = &e
				return nil
			}
		}
		b := make([]byte, 4)
		_, _ = rand.Read(b)
		p.ID = "req-" + hex.EncodeToString(b)
		p.Status = "pending"
		p.CreatedAt = time.Now().UTC()
		if p.TTLSeconds <= 0 {
			p.TTLSeconds = 300
		}
		p.ExpiresAt = p.CreatedAt.Add(defaultApprovalRequestTTL)
		data, mErr := json.MarshalIndent(p, "", "  ")
		if mErr != nil {
			return mErr
		}
		if wErr := writeFileAtomic(approvalPath(zspDir, p.ID), data, 0600); wErr != nil {
			return wErr
		}
		out = &p
		return nil
	})
	return out, err
}

// ListPendingApprovals returns every recorded request, newest first.
func ListPendingApprovals(zspDir string) ([]PendingApproval, error) {
	if zspDir == "" {
		zspDir = ResolveZSPDir()
	}
	entries, err := os.ReadDir(approvalsDir(zspDir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []PendingApproval
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, rErr := os.ReadFile(filepath.Join(approvalsDir(zspDir), e.Name()))
		if rErr != nil {
			continue
		}
		var p PendingApproval
		if json.Unmarshal(data, &p) == nil && p.ID != "" {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// GetPendingApproval loads one request.
func GetPendingApproval(zspDir, id string) (*PendingApproval, error) {
	if zspDir == "" {
		zspDir = ResolveZSPDir()
	}
	data, err := os.ReadFile(approvalPath(zspDir, id))
	if err != nil {
		return nil, ErrApprovalNotFound
	}
	var p PendingApproval
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, ErrApprovalNotFound
	}
	return &p, nil
}

// CheckDecidable reports whether the request can still be approved or denied. Callers that prompt a
// human (the one-time-code challenge) must call it first, so nobody is asked to confirm a request
// that is already decided or has expired.
func (p *PendingApproval) CheckDecidable() error {
	if p.Status != "pending" {
		return fmt.Errorf("%w: %s is %s", ErrApprovalDecided, p.ID, p.Status)
	}
	if time.Now().After(p.ExpiresAt) {
		return fmt.Errorf("%w: %s", ErrApprovalExpired, p.ID)
	}
	return nil
}

// CheckReviewed binds a decision to every displayed request field, including
// linked identity, scope, use limits and expiry, rather than just its ID.
func (p *PendingApproval) CheckReviewed(reviewed PendingApproval) error {
	if !reflect.DeepEqual(*p, reviewed) {
		return ErrApprovalChanged
	}
	return nil
}

// DecidePendingApproval approves (minting the requested grant for the requesting session with the human
// out-of-band delegation) or denies a pending request. Callers must have already verified a human is
// present (terminal one-time code); this function does not and must never be reachable by an agent.
func DecidePendingApproval(zspDir, id string, approve bool) (*PendingApproval, *types.TaskGrant, error) {
	return decidePendingApproval(zspDir, id, approve, nil)
}

// DecidePendingApprovalReviewed re-checks the exact human-reviewed snapshot
// under the same lock used to decide and mint the grant.
func DecidePendingApprovalReviewed(zspDir, id string, approve bool, reviewed PendingApproval) (*PendingApproval, *types.TaskGrant, error) {
	return decidePendingApproval(zspDir, id, approve, &reviewed)
}

func decidePendingApproval(zspDir, id string, approve bool, reviewed *PendingApproval) (*PendingApproval, *types.TaskGrant, error) {
	if zspDir == "" {
		zspDir = ResolveZSPDir()
	}
	var (
		req   *PendingApproval
		grant *types.TaskGrant
	)
	err := withZSPStoreLock(zspDir, "__approvals__", func() error {
		p, gErr := GetPendingApproval(zspDir, id)
		if gErr != nil {
			return gErr
		}
		if dErr := p.CheckDecidable(); dErr != nil {
			return dErr
		}
		if reviewed != nil {
			if err := p.CheckReviewed(*reviewed); err != nil {
				return err
			}
		}
		p.DecidedAt = time.Now().UTC()
		if approve {
			g, _, sErr := SubmitTaskEnvelopeWithDelegation(zspDir, p.SessionID, p.ClientType, p.Mission, p.Goal, p.Goal,
				p.Actions, p.Resources, "", "human_interactive_oob", p.MaxUses, time.Duration(p.TTLSeconds)*time.Second, p.RequestingSessionID)
			if sErr != nil {
				return sErr
			}
			grant = g
			p.Status = "approved"
			p.GrantID = g.GrantID
		} else {
			p.Status = "denied"
		}
		data, mErr := json.MarshalIndent(p, "", "  ")
		if mErr != nil {
			return mErr
		}
		req = p
		return writeFileAtomic(approvalPath(zspDir, p.ID), data, 0600)
	})
	return req, grant, err
}
