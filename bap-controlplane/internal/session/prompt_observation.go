package session

import (
	"encoding/json"
	"time"
)

type promptObservation struct {
	Hash         string
	TurnID       string
	Layer        string
	Category     string
	RecordedAt   time.Time
	Layers       map[string]bool
	HistoryIndex int
}

type promptIndex struct {
	Active  string
	Records map[string]promptObservation
}

// Session-scoped keys are persisted with authority checkpoints and SQLite. A
// content hash is a compatibility key, never a substitute for a native turn id.
func (s *Store) promptIndexLocked(sess *Session) *promptIndex {
	if s.promptIndexes == nil {
		s.promptIndexes = map[string]*promptIndex{}
	}
	if index := s.promptIndexes[sess.SessionID]; index != nil {
		return index
	}
	index := &promptIndex{Records: map[string]promptObservation{}}
	if s.db != nil {
		_, _ = s.db.Exec(`CREATE TABLE IF NOT EXISTS prompt_correlation (session_id TEXT PRIMARY KEY, data TEXT NOT NULL)`)
		var raw string
		if s.db.QueryRow(`SELECT data FROM prompt_correlation WHERE session_id=?`, sess.SessionID).Scan(&raw) == nil {
			_ = json.Unmarshal([]byte(raw), index)
		}
	}
	if index.Records == nil {
		index.Records = map[string]promptObservation{}
	}
	// Adopt a prompt already counted by session-start or an older server.
	if len(index.Records) == 0 && sess.PromptCount > 0 && sess.Intent.PromptHash != "" {
		key := "hash:" + sess.Intent.PromptHash
		layer := "sdk"
		index.Active = key
		index.Records[key] = promptObservation{Hash: sess.Intent.PromptHash, Layer: layer, Category: sess.Intent.Primary, RecordedAt: sess.LastActiveAt, HistoryIndex: len(sess.IntentHistory) - 1}
	}
	s.promptIndexes[sess.SessionID] = index
	return index
}

func (s *Store) observePromptLocked(sess *Session, prompt string, intent IntentContext, turnID, layer string) bool {
	prompt = CleanUserPrompt(prompt)
	normalized := normalizeIntent(intent, prompt)
	if normalized.PromptHash == "" {
		normalized.PromptHash = intent.PromptHash
	}
	if normalized.PromptHash == "" && turnID == "" {
		return false
	}
	if layer == "" {
		layer = "sdk"
	}
	index := s.promptIndexLocked(sess)
	key := "hash:" + normalized.PromptHash
	if turnID != "" {
		key = "turn:" + turnID
	}
	observation, exists := index.Records[key]
	// Bridge a legacy/fallback report to the native identity when it arrives.
	if !exists && turnID != "" {
		active, ok := index.Records[index.Active]
		if ok && active.TurnID == "" && active.Hash == normalized.PromptHash {
			delete(index.Records, index.Active)
			index.Active = key
			observation, exists = active, true
		}
	}
	if !exists && turnID == "" {
		// Legacy producers may retry after another turn. They can corroborate
		// known content, but cannot claim a distinct repeated turn without an id.
		for candidate, record := range index.Records {
			if record.Hash == normalized.PromptHash && (!exists || record.RecordedAt.After(observation.RecordedAt)) {
				key, observation, exists = candidate, record, true
			}
		}
	}
	now := time.Now().UTC()
	promote := !exists || promptSourceRank(layer) < promptSourceRank(observation.Layer)
	if !exists {
		observation = promptObservation{Hash: normalized.PromptHash, TurnID: turnID, Layer: layer, Category: normalized.Primary, RecordedAt: now}
		index.Active = key
		sess.PromptCount++
		sess.IntentHistory = append(sess.IntentHistory, normalized.Primary)
		observation.HistoryIndex = len(sess.IntentHistory) - 1
		s.recordIntentLocked(sess.SessionID, normalized.Primary, now)
	} else if promote && observation.Category != normalized.Primary {
		old := observation.Category
		if observation.HistoryIndex >= 0 && observation.HistoryIndex < len(sess.IntentHistory) {
			sess.IntentHistory = append([]string(nil), sess.IntentHistory...)
			sess.IntentHistory[observation.HistoryIndex] = normalized.Primary
		}
		if s.intentCounts[old] > 0 {
			s.intentCounts[old]--
		}
		s.intentCounts[normalized.Primary]++
		for i := range s.prompts {
			if s.prompts[i].SessionID == sess.SessionID && s.prompts[i].Timestamp.Equal(observation.RecordedAt) {
				s.prompts[i].Category = normalized.Primary
			}
		}
		if s.db != nil {
			_, _ = s.db.Exec(`UPDATE intent_stats SET count=MAX(count-1,0) WHERE category=?`, old)
			_, _ = s.db.Exec(`INSERT INTO intent_stats(category,count) VALUES(?,1) ON CONFLICT(category) DO UPDATE SET count=count+1`, normalized.Primary)
			_, _ = s.db.Exec(`UPDATE prompt_history SET category=? WHERE session_id=? AND timestamp=?`, normalized.Primary, sess.SessionID, observation.RecordedAt.Format(time.RFC3339Nano))
		}
		observation.Category = normalized.Primary
	}
	if observation.Layers == nil {
		observation.Layers = map[string]bool{}
	}
	observation.Layers[layer] = true
	if turnID != "" {
		observation.TurnID = turnID
	}
	if promote {
		observation.Layer = layer
		observation.Hash = normalized.PromptHash
	}
	index.Records[key] = observation
	if index.Active == key && (promote || (sess.UserPrompt == "" && prompt != "" && promptSourceRank(layer) == promptSourceRank(observation.Layer))) {
		sess.UserPrompt, sess.Intent = prompt, normalized
		sess.PromptRiskScore, sess.PromptRiskLevel = normalized.PromptRiskScore, normalized.PromptRiskLevel
		sess.InjectionSignals, sess.IsHighRisk = normalized.InjectionSignals, normalized.IsHighRisk
	}
	if s.db != nil {
		raw, _ := json.Marshal(index)
		_, _ = s.db.Exec(`INSERT INTO prompt_correlation(session_id,data) VALUES(?,?) ON CONFLICT(session_id) DO UPDATE SET data=excluded.data`, sess.SessionID, string(raw))
	}
	return !exists
}
