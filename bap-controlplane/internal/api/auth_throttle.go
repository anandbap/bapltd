package api

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// authFailureThrottle slows repeated invalid administrative credentials from one client address and
// stops each failure from writing an audit event once the client is over the limit (BAP-1098).
//
// It never blocks a valid credential: behind a reverse proxy every caller shares the proxy's
// address, and locking that address out would let an attacker deny service to the real administrator.
type authFailureThrottle struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	clients map[string]*authFailureWindow
	now     func() time.Time
}

type authFailureWindow struct {
	count   int
	resetAt time.Time
}

func newAuthFailureThrottle(limit int, window time.Duration) *authFailureThrottle {
	return &authFailureThrottle{limit: limit, window: window, clients: make(map[string]*authFailureWindow), now: time.Now}
}

// adminThrottle returns the per-server limiter shared by every administrative route.
func (s *Server) adminThrottle() *authFailureThrottle {
	s.adminThrottleOnce.Do(func() {
		s.adminThrottleState = newAuthFailureThrottle(10, time.Minute)
	})
	return s.adminThrottleState
}

func clientAddress(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// recordFailure registers one invalid credential and reports whether the client is now over the
// limit, plus how long it should wait.
func (t *authFailureThrottle) recordFailure(client string) (over bool, retryAfter time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	// Opportunistic cleanup keeps the map bounded by the number of recently active addresses.
	if len(t.clients) > 4096 {
		for k, w := range t.clients {
			if now.After(w.resetAt) {
				delete(t.clients, k)
			}
		}
	}
	w, ok := t.clients[client]
	if !ok || now.After(w.resetAt) {
		w = &authFailureWindow{resetAt: now.Add(t.window)}
		t.clients[client] = w
	}
	w.count++
	if w.count > t.limit {
		return true, w.resetAt.Sub(now)
	}
	return false, 0
}

// reset clears the failure history after a successful authentication.
func (t *authFailureThrottle) reset(client string) {
	t.mu.Lock()
	delete(t.clients, client)
	t.mu.Unlock()
}
