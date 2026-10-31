package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type hookCredential struct {
	ServerURL string `json:"server_url"`
	Token     string `json:"session_token"`
}

var hookEnrollment = func() hookCredential {
	path := os.Getenv("BAP_CREDENTIALS")
	if path == "" {
		dir := os.Getenv("BAP_STATE_DIR")
		if dir == "" {
			home, _ := os.UserHomeDir()
			dir = filepath.Join(home, ".bapstate")
		}
		path = filepath.Join(dir, "credentials.json")
	}
	var credential hookCredential
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &credential)
	}
	return credential
}

type hookIdentityTransport struct{ next http.RoundTripper }

func (t *hookIdentityTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasPrefix(req.URL.Path, "/api/v1/sessions/") && req.Header.Get("Authorization") == "" {
		credential := hookEnrollment()
		origin, err := url.Parse(credential.ServerURL)
		if err == nil && credential.Token != "" && origin.Scheme == req.URL.Scheme && origin.Host == req.URL.Host && strings.TrimRight(origin.Path, "/") == "" {
			local := req.URL.Hostname() == "localhost" || req.URL.Hostname() == "127.0.0.1" || req.URL.Hostname() == "::1"
			if req.URL.Scheme != "https" && !local {
				return nil, fmt.Errorf("authenticated lifecycle requires HTTPS")
			}
			req = req.Clone(req.Context())
			req.Header.Set("Authorization", "Bearer "+credential.Token)
		}
	}
	return t.next.RoundTrip(req)
}

func hookIdentityRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return fmt.Errorf("too many redirects")
	}
	if len(via) > 0 && via[0].Header.Get("Authorization") != "" && (via[0].URL.Scheme != req.URL.Scheme || via[0].URL.Host != req.URL.Host) {
		req.Header.Del("Authorization")
		return fmt.Errorf("authenticated cross-origin redirect refused")
	}
	return nil
}
