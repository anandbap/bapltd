package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

type hookIdentityFixture func(*http.Request) (*http.Response, error)

func (f hookIdentityFixture) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestHookIdentityBoundToOrigin(t *testing.T) {
	previous := hookEnrollment
	hookEnrollment = func() hookCredential {
		return hookCredential{ServerURL: "https://control.test", Token: "fixture-proof"}
	}
	t.Cleanup(func() { hookEnrollment = previous })
	for _, target := range []string{"https://control.test/api/v1/sessions/prompt", "https://other.test/api/v1/sessions/prompt"} {
		transport := hookIdentityTransport{next: hookIdentityFixture(func(r *http.Request) (*http.Response, error) {
			if (r.Header.Get("Authorization") == "Bearer fixture-proof") != (r.URL.Host == "control.test") {
				t.Error("hook credential escaped its origin")
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(""))}, nil
		})}
		req, _ := http.NewRequest("POST", target, nil)
		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
}
