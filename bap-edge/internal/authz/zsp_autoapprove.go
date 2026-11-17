package authz

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Optional ZSP step-up auto-approve (BAP-1100).
//
// When a human turns it ON, requests that fall in the permission policy's "approve" tier are
// granted without a per-request approval for a bounded window. It is OFF by default and:
//   - only a human can turn it on (terminal one-time-code challenge, refused inside the agent broker);
//   - it expires (default 1h, maximum 8h) and is re-verified on every request, so a stale envelope
//     cannot outlive the window;
//   - it never covers policy-mutation or governance escalations (policy:, grant:, admin:, ...),
//     hard denies, credential paths, or the Cedar invariants;
//   - grants minted under it carry delegation type "auto_approve" so the audit trail shows it.

// DelegationAutoApprove marks an envelope minted while auto-approve was active.
const DelegationAutoApprove = "auto_approve"

const (
	DefaultAutoApproveWindow = time.Hour
	MaxAutoApproveWindow     = 8 * time.Hour
)

// AutoApproveActive is installed by the command layer; nil means off.
var AutoApproveActive func() bool

type autoApproveRecord struct {
	EnabledAt time.Time `json:"enabled_at"`
	ExpiresAt time.Time `json:"expires_at"`
	EnabledBy string    `json:"enabled_by"`
	Signature string    `json:"signature"`
}

func autoApprovePath(zspDir string) string {
	return filepath.Join(zspDir, "autoapprove.json")
}

func autoApproveSignature(secret string, r autoApproveRecord) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "autoapprove|%d|%d|%s", r.EnabledAt.Unix(), r.ExpiresAt.Unix(), r.EnabledBy)
	return hex.EncodeToString(mac.Sum(nil))
}

// SetAutoApprove turns auto-approve on for ttl (clamped to MaxAutoApproveWindow) or off. Callers
// must enforce that turning it on is a human action.
func SetAutoApprove(zspDir string, on bool, ttl time.Duration, by string) (time.Time, error) {
	if zspDir == "" {
		zspDir = ResolveZSPDir()
	}
	if !on {
		if err := os.Remove(autoApprovePath(zspDir)); err != nil && !os.IsNotExist(err) {
			return time.Time{}, err
		}
		return time.Time{}, nil
	}
	if ttl <= 0 {
		ttl = DefaultAutoApproveWindow
	}
	if ttl > MaxAutoApproveWindow {
		ttl = MaxAutoApproveWindow
	}
	secret, err := loadOrCreatePEPSecret(zspDir)
	if err != nil {
		return time.Time{}, err
	}
	now := time.Now().UTC()
	rec := autoApproveRecord{EnabledAt: now, ExpiresAt: now.Add(ttl), EnabledBy: by}
	rec.Signature = autoApproveSignature(secret, rec)
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return time.Time{}, err
	}
	if err := writeFileAtomic(autoApprovePath(zspDir), data, 0600); err != nil {
		return time.Time{}, err
	}
	return rec.ExpiresAt, nil
}

// AutoApproveStatus reports whether a valid, unexpired, correctly signed auto-approve window is
// open. Anything missing, expired, malformed or tampered with means off.
func AutoApproveStatus(zspDir string) (active bool, expires time.Time, by string) {
	if zspDir == "" {
		zspDir = ResolveZSPDir()
	}
	data, err := os.ReadFile(autoApprovePath(zspDir))
	if err != nil {
		return false, time.Time{}, ""
	}
	var rec autoApproveRecord
	if json.Unmarshal(data, &rec) != nil {
		return false, time.Time{}, ""
	}
	secret, err := loadOrCreatePEPSecret(zspDir)
	if err != nil {
		return false, time.Time{}, ""
	}
	if !hmac.Equal([]byte(autoApproveSignature(secret, rec)), []byte(rec.Signature)) {
		return false, time.Time{}, ""
	}
	if !time.Now().UTC().Before(rec.ExpiresAt) || rec.ExpiresAt.Sub(rec.EnabledAt) > MaxAutoApproveWindow {
		return false, rec.ExpiresAt, rec.EnabledBy
	}
	return true, rec.ExpiresAt, rec.EnabledBy
}
