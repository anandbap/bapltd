package httptransport

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"bap-edge/internal/state"
)

type workstationCredential struct {
	ServerURL string `json:"server_url"`
	Token     string `json:"session_token"`
}

var credentialMu sync.Mutex
var credentialCache struct {
	path  string
	until time.Time
	value workstationCredential
}

func currentCredential() workstationCredential {
	credentialMu.Lock()
	defer credentialMu.Unlock()
	path := state.CredentialsPath()
	if path != credentialCache.path || time.Now().After(credentialCache.until) {
		credentialCache.path, credentialCache.until, credentialCache.value = path, time.Now().Add(time.Second), workstationCredential{}
		if data, err := os.ReadFile(path); err == nil {
			_ = json.Unmarshal(data, &credentialCache.value)
		}
	}
	return credentialCache.value
}

func lifecyclePath(path string) bool {
	return strings.HasPrefix(path, "/api/v1/sessions/") || path == "/api/v1/instances/heartbeat" || path == "/api/v1/control/heartbeat" || path == "/api/v1/audit/ingest" || path == "/api/activity/ingest" || path == "/api/v1/activity/ingest"
}

func localHost(host string) bool { return host == "localhost" || host == "127.0.0.1" || host == "::1" }

func identityRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return fmt.Errorf("too many redirects")
	}
	if len(via) > 0 && (req.URL.Scheme != via[0].URL.Scheme || req.URL.Host != via[0].URL.Host) {
		req.Header.Del("Authorization")
		if via[0].Header.Get("Authorization") != "" {
			return fmt.Errorf("refusing authenticated cross-origin redirect")
		}
	}
	return nil
}

type identityTransport struct{ next http.RoundTripper }

var serverEpochs sync.Map

func ControlPlaneEpoch(server string) string {
	u, err := url.Parse(server)
	if err != nil {
		return ""
	}
	if value, ok := serverEpochs.Load(u.Scheme + "://" + u.Host); ok {
		return value.(string)
	}
	return ""
}

func (t *identityTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if lifecyclePath(req.URL.Path) && req.Header.Get("Authorization") == "" {
		creds := currentCredential()
		base, err := url.Parse(creds.ServerURL)
		if err == nil && creds.Token != "" && base.Scheme == req.URL.Scheme && base.Host == req.URL.Host && strings.TrimRight(base.Path, "/") == "" {
			if req.URL.Scheme != "https" && !localHost(req.URL.Hostname()) {
				return nil, fmt.Errorf("workstation identity requires HTTPS")
			}
			req = req.Clone(req.Context())
			req.Header.Set("Authorization", "Bearer "+creds.Token)
		}
	}
	if req.Header.Get("Authorization") != "" && !localHost(req.URL.Hostname()) {
		if req.URL.Scheme != "https" || os.Getenv("BAP_INSECURE_SKIP_VERIFY") == "1" {
			return nil, fmt.Errorf("authenticated control-plane traffic requires verified HTTPS")
		}
	}
	resp, err := t.next.RoundTrip(req)
	if err == nil && resp != nil {
		if epoch := resp.Header.Get("X-BAP-Server-Epoch"); epoch != "" {
			serverEpochs.Store(req.URL.Scheme+"://"+req.URL.Host, epoch)
		}
	}
	return resp, err
}
