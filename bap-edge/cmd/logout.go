package cmd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"bap-edge/internal/config"
	"bap-edge/internal/httptransport"
	"bap-edge/internal/state"
)

// RunLogout executes workstation session logout and deregistration from the central BAP Control Plane.
func RunLogout(args []string) error {
	fs := flag.NewFlagSet("logout", flag.ContinueOnError)
	configPath := fs.String("config", DefaultCredentialsPath(), "Path to store enrolled credentials")
	caCertPath := fs.String("ca-cert", os.Getenv("BAP_CA_CERT"), "Path to custom CA certificate for HTTPS verification")
	insecureTLS := fs.Bool("insecure", false, "Skip TLS certificate verification (development only)")
	force := fs.Bool("force", false, "Force local credential cleanup even if remote deregistration fails")

	if err := fs.Parse(args); err != nil {
		return err
	}
	_ = *force

	credsFile := *configPath
	if credsFile == "" {
		credsFile = DefaultCredentialsPath()
	}

	// 1. Discover and load enrolled credentials from any candidate location
	candidatePaths := []string{
		credsFile,
		state.CredentialsPath(),
	}
	if home, hErr := os.UserHomeDir(); hErr == nil && home != "" {
		candidatePaths = append(candidatePaths,
			filepath.Join(home, ".bapstate", "credentials.json"),
			filepath.Join(home, ".ltd", "credentials.json"),
			filepath.Join(home, ".bap", "credentials.json"),
		)
	}
	candidatePaths = append(candidatePaths,
		filepath.Join(".bapstate", "credentials.json"),
		filepath.Join(".ltd", "credentials.json"),
		filepath.Join(".bap", "credentials.json"),
	)
	if envCreds := os.Getenv("BAP_CREDENTIALS"); envCreds != "" {
		candidatePaths = append(candidatePaths, envCreds)
	}

	var credsData []byte
	foundPath := credsFile
	for _, cp := range candidatePaths {
		if cp == "" {
			continue
		}
		if data, err := os.ReadFile(cp); err == nil && len(data) > 0 {
			credsData = data
			foundPath = cp
			break
		}
	}

	var creds StoredCredentials
	if len(credsData) > 0 {
		if jErr := json.Unmarshal(credsData, &creds); jErr != nil {
			fmt.Printf("[!] Warning: Could not parse %s: %v\n", foundPath, jErr)
		}
	}

	// 2. Prepare HTTP client
	httpClient := httptransport.New(5 * time.Second)
	if *insecureTLS {
		httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			Timeout: 5 * time.Second,
		}
	} else if *caCertPath != "" {
		if caData, cErr := os.ReadFile(*caCertPath); cErr == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(caData) {
				httpClient = &http.Client{
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{RootCAs: pool},
					},
					Timeout: 5 * time.Second,
				}
			}
		}
	}

	// 3. Notify Central Control Plane to deregister session
	serverURL := creds.ServerURL
	if serverURL == "" {
		serverURL = config.ResolveEndpoints().ControlPlaneURL
	}

	serverContacted := false
	if serverURL != "" && (creds.AgentID != "" || creds.InstanceID != "" || creds.SessionToken != "") {
		for _, endpoint := range []string{"/api/v1/agents/deregister", "/api/v1/auth/logout"} {
			deregURL := strings.TrimRight(serverURL, "/") + endpoint
			reqPayload := map[string]string{
				"agent_id":      creds.AgentID,
				"instance_id":   creds.InstanceID,
				"session_token": creds.SessionToken,
				"target":        creds.AgentID,
				"reason":        "User logged out via bapedge logout",
			}
			reqBody, _ := json.Marshal(reqPayload)
			httpReq, rErr := http.NewRequest(http.MethodPost, deregURL, bytes.NewReader(reqBody))
			if rErr == nil {
				httpReq.Header.Set("Content-Type", "application/json")
				if creds.SessionToken != "" {
					httpReq.Header.Set("Authorization", "Bearer "+creds.SessionToken)
				}
				resp, postErr := httpClient.Do(httpReq)
				if postErr == nil {
					_ = resp.Body.Close()
					if resp.StatusCode == http.StatusOK {
						serverContacted = true
					}
				}
			}
		}
	}

	// 4. Exhaustively purge all local credentials and session tokens across all candidate locations
	state.PurgeAllCredentials(foundPath)
	state.PurgeAllCredentials(credsFile)

	fmt.Println("================================================================================")
	fmt.Println("  [BAP ZERO-TRUST] 🚪 Developer Workstation Logout & Deregistration")
	fmt.Println("================================================================================")
	if serverContacted {
		fmt.Printf("  [✓] Central Control Plane Session Revoked: %s\n", serverURL)
	} else if serverURL != "" && (creds.AgentID != "" || creds.InstanceID != "") {
		fmt.Printf("  [!] Remote Server Notice: Control plane unreachable (%s); deregistered locally.\n", serverURL)
	}
	if creds.UserEmail != "" {
		fmt.Printf("  [✓] Authenticated Identity: %s (%s)\n", creds.UserEmail, creds.IdPProvider)
	}
	if creds.InstanceID != "" {
		fmt.Printf("  [✓] Workstation Instance:   %s\n", creds.InstanceID)
	}
	fmt.Printf("  [✓] Removed credentials:    %s\n", foundPath)
	fmt.Println("  [✓] Workstation is now logged out. Run 'bap login' to re-authenticate.")
	fmt.Println("================================================================================")
	return nil
}
