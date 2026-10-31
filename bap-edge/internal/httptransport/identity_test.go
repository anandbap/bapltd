package httptransport

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"bap-edge/internal/state"
)

type identityRoundTrip func(*http.Request) (*http.Response, error)

func (f identityRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestIdentityStaysBoundToControlPlaneOrigin(t *testing.T) {
	// In-memory synthetic enrollment; never read a user's credential file.
	previous := credentialCache
	credentialCache.path, credentialCache.until = state.CredentialsPath(), time.Now().Add(time.Hour)
	credentialCache.value = workstationCredential{ServerURL: "https://control.test", Token: "fixture-proof"}
	t.Cleanup(func() { credentialCache = previous })
	for _, tc := range []struct {
		url  string
		want bool
	}{
		{"https://control.test/api/v1/sessions/heartbeat", true},
		{"https://other.test/api/v1/sessions/heartbeat", false},
		{"https://control.test.evil/api/v1/sessions/heartbeat", false},
		{"https://control.test/unrelated", false},
	} {
		transport := identityTransport{next: identityRoundTrip(func(r *http.Request) (*http.Response, error) {
			if (r.Header.Get("Authorization") == "Bearer fixture-proof") != tc.want {
				t.Errorf("credential routing mismatch for %s", tc.url)
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
		})}
		req, _ := http.NewRequest("POST", tc.url, nil)
		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if req.Header.Get("Authorization") != "" {
			t.Fatal("caller request was mutated")
		}
	}
}

func TestAuthenticatedRedirectCannotLeakProof(t *testing.T) {
	original, _ := http.NewRequest("POST", "https://control.test/api/v1/sessions/start", nil)
	original.Header.Set("Authorization", "Bearer fixture-proof")
	next, _ := http.NewRequest("GET", "https://control.test.evil/collect", nil)
	next.Header = original.Header.Clone()
	if err := identityRedirect(next, []*http.Request{original}); err == nil {
		t.Fatal("accepted cross-origin redirect")
	}
	if next.Header.Get("Authorization") != "" {
		t.Fatal("redirect retained proof")
	}
}
