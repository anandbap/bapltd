package api

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

// Server-sent-event streams cannot send an Authorization header (the browser EventSource API has no
// way to set one), and an admin credential in a URL lands in access logs, proxies and browser history.
// Instead an authenticated administrator exchanges the credential for a short-lived, single-use
// ticket and passes only that ticket in the stream URL.

const streamTicketTTL = 30 * time.Second

type streamTicketStore struct {
	mu      sync.Mutex
	tickets map[string]time.Time
	now     func() time.Time
}

var streamTickets = &streamTicketStore{tickets: make(map[string]time.Time), now: time.Now}

func (st *streamTicketStore) issue() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	ticket := "bap_stk_" + hex.EncodeToString(b)
	st.mu.Lock()
	defer st.mu.Unlock()
	now := st.now()
	for k, exp := range st.tickets {
		if now.After(exp) {
			delete(st.tickets, k)
		}
	}
	st.tickets[ticket] = now.Add(streamTicketTTL)
	return ticket, nil
}

// consume validates and burns a ticket; a ticket works exactly once.
func (st *streamTicketStore) consume(ticket string) bool {
	if ticket == "" {
		return false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	exp, ok := st.tickets[ticket]
	if !ok {
		return false
	}
	delete(st.tickets, ticket)
	return !st.now().After(exp)
}

// handleStreamTicket issues a stream ticket. It is wrapped in requireAdminAuth.
func (s *Server) handleStreamTicket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	ticket, err := streamTickets.issue()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Unable to issue stream ticket")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ticket":     ticket,
		"expires_in": int(streamTicketTTL.Seconds()),
	})
}
