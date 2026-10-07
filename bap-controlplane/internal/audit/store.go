package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

type Event struct {
	EventID            string   `json:"event_id"`
	AgentID            string   `json:"agent_id,omitempty"`
	SessionID          string   `json:"session_id,omitempty"`
	UserID             string   `json:"user_id,omitempty"`
	UserEmail          string   `json:"user_email,omitempty"`
	SPIFFEID           string   `json:"spiffe_id,omitempty"`
	Timestamp          string   `json:"timestamp"`
	Source             string   `json:"source"`
	ClientPID          int      `json:"client_pid,omitempty"`
	Executable         string   `json:"executable"`
	Arguments          string   `json:"arguments,omitempty"`
	FullCommand        string   `json:"full_command"`
	Decision           string   `json:"decision"`
	Reason             string   `json:"reason,omitempty"`
	UserPrompt         string   `json:"user_prompt,omitempty"`
	PrimaryIntent      string   `json:"primary_intent,omitempty"`
	SecondaryIntents   []string `json:"secondary_intents,omitempty"`
	IntentTags         []string `json:"intent_tags,omitempty"`
	IntentConfidence   float64  `json:"intent_confidence,omitempty"`
	IntentClassifier   string   `json:"intent_classifier,omitempty"`
	PromptHash          string   `json:"prompt_hash,omitempty"`
	PromptCaptured      bool     `json:"prompt_captured"`
	DurationMs          int64    `json:"duration_ms,omitempty"`
	ExitCode            int      `json:"exit_code"`
	DestinationTenantID string   `json:"destination_tenant_id,omitempty"`
	CanonicalResource   string   `json:"canonical_resource,omitempty"`
	PreviousHash        string   `json:"previous_hash"`
	EventHash           string   `json:"event_hash"`
}

type Store struct {
	mu       sync.RWMutex
	lastHash string
	events   []Event
	seenIDs  map[string]struct{}
}

func NewStore() *Store {
	return &Store{
		lastHash: "genesis-bapltd-control-plane",
		events:   make([]Event, 0),
		seenIDs:  make(map[string]struct{}),
	}
}

func (s *Store) Ingest(incoming []Event) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ingested := 0
	for _, ev := range incoming {
		if ev.EventID == "" {
			ev.EventID = fmt.Sprintf("ev-%d-%d", time.Now().UTC().UnixNano(), len(s.events))
		}
		if ev.Timestamp == "" {
			ev.Timestamp = time.Now().UTC().Format(time.RFC3339)
		} else if parsed, err := time.Parse(time.RFC3339, ev.Timestamp); err == nil {
			ev.Timestamp = parsed.UTC().Format(time.RFC3339)
		}

		if _, exists := s.seenIDs[ev.EventID]; exists {
			continue // skip duplicate
		}

		ev.PreviousHash = s.lastHash

		h := sha256.New()
		h.Write([]byte(ev.PreviousHash))
		h.Write([]byte(ev.EventID))
		h.Write([]byte(ev.Timestamp))
		h.Write([]byte(ev.Source))
		h.Write([]byte(ev.FullCommand))
		h.Write([]byte(ev.Decision))
		h.Write([]byte(ev.PrimaryIntent))
		h.Write([]byte(ev.IntentClassifier))
		h.Write([]byte(ev.PromptHash))
		ev.EventHash = hex.EncodeToString(h.Sum(nil))

		s.lastHash = ev.EventHash
		s.seenIDs[ev.EventID] = struct{}{}
		s.events = append(s.events, ev)
		ingested++
	}

	return ingested, nil
}

func (s *Store) List(limit int) []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 || limit > len(s.events) {
		limit = len(s.events)
	}

	start := len(s.events) - limit
	result := make([]Event, limit)
	copy(result, s.events[start:])
	return result
}

func (s *Store) VerifyChain() (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	expectedPrev := "genesis-bapltd-control-plane"
	for i, ev := range s.events {
		if ev.PreviousHash != expectedPrev {
			return false, fmt.Errorf("chain broken at index %d: expected previous %s, got %s", i, expectedPrev, ev.PreviousHash)
		}

		h := sha256.New()
		h.Write([]byte(ev.PreviousHash))
		h.Write([]byte(ev.EventID))
		h.Write([]byte(ev.Timestamp))
		h.Write([]byte(ev.Source))
		h.Write([]byte(ev.FullCommand))
		h.Write([]byte(ev.Decision))
		h.Write([]byte(ev.PrimaryIntent))
		h.Write([]byte(ev.IntentClassifier))
		h.Write([]byte(ev.PromptHash))
		computed := hex.EncodeToString(h.Sum(nil))

		if ev.EventHash != computed {
			return false, fmt.Errorf("hash mismatch at index %d: event_hash %s != computed %s", i, ev.EventHash, computed)
		}
		expectedPrev = ev.EventHash
	}
	return true, nil
}

// LastHash returns the current tail hash of the sequential SHA-256 chain.
func (s *Store) LastHash() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastHash
}
