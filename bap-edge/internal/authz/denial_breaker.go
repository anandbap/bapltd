package authz

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Anti-spin circuit breaker (BAP-936). An agent that is refused will often retry the identical request
// in a loop, burning tokens and the developer's patience while no human can answer. BAP therefore
//   1. answers the first refusal immediately (never blocks waiting for input),
//   2. tells the agent explicitly to STOP and wait after a repeat, and
//   3. HALTS the agent turn (hook `continue:false` with a stopReason) when the same refusal keeps recurring,
// so the developer sees one clear message instead of a spinning session.

const (
	// DenialWarnAfter: from this many identical refusals the guidance becomes an unmistakable STOP notice.
	DenialWarnAfter = 3
	// DenialHaltAfter: from this many identical refusals the agent turn is halted.
	DenialHaltAfter = 5
	denialWindow    = 5 * time.Minute
)

type denialEntry struct {
	Count int       `json:"count"`
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
}

func denialsPath(zspDir, sessionID string) string {
	return filepath.Join(zspDir, "denials", sanitizeZSPKey(sessionID)+".json")
}

// DenialKey derives a stable key for "the same refusal".
func DenialKey(parts ...string) string {
	h := sha256.Sum256([]byte(strings.ToLower(strings.Join(parts, "|"))))
	return hex.EncodeToString(h[:8])
}

// AuthorizeDenialKey is the shared key for repeated `zsp authorize` asks (CLI records it, the hook reads it).
func AuthorizeDenialKey(actions, resources []string) string {
	a := append([]string(nil), actions...)
	r := append([]string(nil), resources...)
	if len(r) == 0 {
		r = []string{"workspace://current"}
	}
	sort.Strings(a)
	sort.Strings(r)
	return DenialKey("authorize", strings.Join(a, ","), strings.Join(r, ","))
}

func loadDenials(zspDir, sessionID string) map[string]denialEntry {
	m := map[string]denialEntry{}
	if data, err := os.ReadFile(denialsPath(zspDir, sessionID)); err == nil {
		_ = json.Unmarshal(data, &m)
	}
	return m
}

// RecordDenial counts one more refusal of key for the session within the rolling window and returns the count.
func RecordDenial(zspDir, sessionID, key string) int {
	if zspDir == "" {
		zspDir = ResolveZSPDir()
	}
	count := 0
	_ = withZSPStoreLock(zspDir, "denials-"+sessionID, func() error {
		now := time.Now().UTC()
		m := loadDenials(zspDir, sessionID)
		for k, e := range m {
			if now.Sub(e.Last) > denialWindow {
				delete(m, k)
			}
		}
		e := m[key]
		if e.Count == 0 {
			e.First = now
		}
		e.Count++
		e.Last = now
		m[key] = e
		count = e.Count
		data, err := json.Marshal(m)
		if err != nil {
			return err
		}
		return writeFileAtomic(denialsPath(zspDir, sessionID), data, 0600)
	})
	return count
}

// DenialCount reads the current count without incrementing it.
func DenialCount(zspDir, sessionID, key string) int {
	if zspDir == "" {
		zspDir = ResolveZSPDir()
	}
	e, ok := loadDenials(zspDir, sessionID)[key]
	if !ok || time.Since(e.Last) > denialWindow {
		return 0
	}
	return e.Count
}

// ClearDenial forgets a key (for example after the request was approved and the retry succeeded).
func ClearDenial(zspDir, sessionID, key string) {
	if zspDir == "" {
		zspDir = ResolveZSPDir()
	}
	_ = withZSPStoreLock(zspDir, "denials-"+sessionID, func() error {
		m := loadDenials(zspDir, sessionID)
		delete(m, key)
		data, _ := json.Marshal(m)
		return writeFileAtomic(denialsPath(zspDir, sessionID), data, 0600)
	})
}

// RepeatedDenialNotice is prepended to the guidance once the same refusal repeats.
func RepeatedDenialNotice(count int) string {
	return fmt.Sprintf("STOP: BAP has refused this exact request %d times. Retrying will not change the answer. "+
		"Do not retry, rephrase or look for another way. Tell the developer what you were trying to do and wait for their instruction. ", count)
}

// HaltReason is the stopReason shown to the developer when the agent turn is halted.
func HaltReason(count int, what string) string {
	return fmt.Sprintf("BAP halted the agent: the same request was refused %d times (%s). A human decision is needed; "+
		"review `bapedge zsp approvals` or the refusal message, then resume the agent with new instructions.", count, what)
}
