package config

import (
	"bap-edge/internal/httptransport"
	"bap-edge/internal/policystore"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	DefaultCloudControlPlaneURL = "https://bap-controlplane.onrender.com"
	DefaultLocalHTTPSURL        = "https://localhost:8443"
	DefaultLocalHTTPURL         = "http://localhost:8080"
)

var (
	ErrNoPolicyAvailable = errors.New("policy.cedar not available: control plane unreachable (https://bap-controlplane.onrender.com failed after 30s cold-start budget, local 8443 and 8080 offline) and no local policy found. bapedge cannot start")

	// DefaultProbeTransport allows in-memory test mocks without creating OS loopback sockets.
	DefaultProbeTransport http.RoundTripper
)

// BootstrapResult captures the outcome of the zero-trust cascading control plane discovery.
type BootstrapResult struct {
	ActiveURL    string `json:"active_url"`
	Connected    bool   `json:"connected"`
	DegradedMode bool   `json:"degraded_mode"`
	PolicyPath   string `json:"policy_path"`
	PolicyDigest string `json:"policy_digest"`
	StatusText   string `json:"status_text"`
}

// probeEndpoint tests whether a given control plane URL is alive and responding.
func probeEndpoint(url string, timeout time.Duration, skipTLS bool) bool {
	if url == "" {
		return false
	}
	url = strings.TrimRight(url, "/")

	client := httptransport.New(timeout)
	if httptransport.MockTransport == nil && skipTLS {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	healthURL := url + "/health"
	resp, err := client.Get(healthURL)
	if err != nil {
		return false
	}
	if resp != nil {
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}
	return false
}

// BootstrapControlPlane executes the full cascading discovery and policy synchronization.
//
// Order of Resolution:
// 1. Explicitly configured URL (via flag, env vars BAP_SERVER_URL/BAP_CONTROL_PLANE_URL, or local/global config files).
// 2. If unconfigured (first-time start):
//    a. "https://bap-controlplane.onrender.com" with a 30-second cold-start budget:
//       - Try 1 (up to 12s timeout)
//       - If failed, wait 15 seconds to allow the sleeping Render instance to spin up
//       - Try 2 (up to 15s timeout)
//    b. If onrender fails after 30s, probe local HTTPS: "https://localhost:8443" and "https://127.0.0.1:8443".
//    c. If 8443 fails, probe local HTTP: "http://localhost:8080" and "http://127.0.0.1:8080".
// 3. Once connected, sync policy.cedar from the control plane and store in the policy cache.
// 4. Fail-closed invariant:
//    - If ALL control planes are unreachable:
//      - If a valid policy.cedar is available locally on disk: enter Degraded Mode.
//      - If NO policy.cedar is available: FAIL CLOSED! bapedge cannot start.
func BootstrapControlPlane(serverOverride string) (BootstrapResult, error) {
	endpoints := ResolveEndpoints()
	serverURL := strings.TrimSpace(serverOverride)

	isExplicit := serverURL != ""
	if !isExplicit {
		if envURL := getFirstEnv("BAP_SERVER_URL", "BAP_CONTROL_PLANE_URL", "LTD_SERVER_URL"); envURL != "" {
			serverURL = envURL
			isExplicit = true
		} else if endpoints.ConfigSource != "default_fallback" && endpoints.ControlPlaneURL != "" {
			serverURL = endpoints.ControlPlaneURL
			isExplicit = true
		}
	}

	policyStore := policystore.New("")
	var activeURL string
	connected := false

	sleepDuration := 15 * time.Second
	if os.Getenv("BAP_TEST_MODE") == "1" || os.Getenv("BAP_FAST_BOOT") == "1" {
		sleepDuration = 100 * time.Millisecond
	}

	if isExplicit {
		serverURL = strings.TrimRight(serverURL, "/")
		isRemote := strings.HasPrefix(serverURL, "https://") || (!strings.Contains(serverURL, "localhost") && !strings.Contains(serverURL, "127.0.0.1"))
		
		if isRemote {
			// Remote explicit endpoint: allow 2 attempts with 15s sleep for cloud wake-up
			if probeEndpoint(serverURL, 12*time.Second, false) {
				activeURL = serverURL
				connected = true
			} else {
				time.Sleep(sleepDuration)
				if probeEndpoint(serverURL, 15*time.Second, false) {
					activeURL = serverURL
					connected = true
				}
			}
		} else {
			// Local explicit endpoint
			if probeEndpoint(serverURL, 3*time.Second, true) {
				activeURL = serverURL
				connected = true
			}
		}
	} else {
		// First-time start: run the full discovery cascade
		// Step 1: Primary cloud target (https://bap-controlplane.onrender.com) with 30s budget
		cloudURL := DefaultCloudControlPlaneURL
		if probeEndpoint(cloudURL, 12*time.Second, false) {
			activeURL = cloudURL
			connected = true
		} else {
			// Render cold-start wait
			time.Sleep(sleepDuration)
			if probeEndpoint(cloudURL, 15*time.Second, false) {
				activeURL = cloudURL
				connected = true
			}
		}

		// Step 2: Fallback to local HTTPS (8443)
		if !connected {
			for _, localHTTPS := range []string{DefaultLocalHTTPSURL, "https://127.0.0.1:8443"} {
				if probeEndpoint(localHTTPS, 2*time.Second, true) {
					activeURL = localHTTPS
					connected = true
					break
				}
			}
		}

		// Step 3: Fallback to local HTTP (8080)
		if !connected {
			for _, localHTTP := range []string{DefaultLocalHTTPURL, "http://127.0.0.1:8080"} {
				if probeEndpoint(localHTTP, 2*time.Second, false) {
					activeURL = localHTTP
					connected = true
					break
				}
			}
		}
	}

	// If connected, sync policy.cedar from the active control plane
	if connected && activeURL != "" {
		bundle, isFallback, syncErr := policyStore.SyncWithServer(activeURL, "", 5*time.Second)
		if syncErr == nil && !isFallback {
			cedarPath := filepath.Join(policyStore.Directory(), "policy.cedar")
			return BootstrapResult{
				ActiveURL:    activeURL,
				Connected:    true,
				DegradedMode: false,
				PolicyPath:   cedarPath,
				PolicyDigest: bundle.Digest,
				StatusText:   fmt.Sprintf("ONLINE: Connected to %s (Policy synced, digest: %s)", activeURL, bundle.Digest),
			}, nil
		}
	}

	// Control plane is offline / unreachable: check for local policy.cedar
	cedarPath, _, stateRec, err := policyStore.Current()
	if err != nil || cedarPath == "" {
		// FAIL-CLOSED: No control plane and no local policy file exists.
		return BootstrapResult{}, ErrNoPolicyAvailable
	}

	fallbackURL := activeURL
	if fallbackURL == "" {
		if serverURL != "" {
			fallbackURL = serverURL
		} else {
			fallbackURL = DefaultCloudControlPlaneURL
		}
	}

	return BootstrapResult{
		ActiveURL:    fallbackURL,
		Connected:    false,
		DegradedMode: true,
		PolicyPath:   cedarPath,
		PolicyDigest: stateRec.Digest,
		StatusText:   fmt.Sprintf("DEGRADED MODE: Control plane offline (%s). Operating with local cached policy %s.", fallbackURL, cedarPath),
	}, nil
}
