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

	credsFile := *configPath
	if credsFile == "" {
		credsFile = DefaultCredentialsPath()
	}

	// 1. Check if enrolled credentials exist
	credsData, err := os.ReadFile(credsFile)
	if err != nil {
		altPath := state.CredentialsPath()
		if altPath != credsFile {
			if altData, altErr := os.ReadFile(altPath); altErr == nil {
				credsFile = altPath
				credsData = altData
				err = nil
			}
		}
	}

	if err != nil || len(credsData) == 0 {
		fmt.Println("[i] No active enrolled credentials found. Workstation is already logged out.")
		return nil
	}

	var creds StoredCredentials
	if jErr := json.Unmarshal(credsData, &creds); jErr != nil {
		fmt.Printf("[!] Warning: Could not parse %s: %v\n", credsFile, jErr)
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
	if serverURL != "" {
		deregURL := strings.TrimRight(serverURL, "/") + "/api/v1/agents/deregister"
		reqPayload := map[string]string{
			"agent_id":      creds.AgentID,
			"instance_id":   creds.InstanceID,
			"session_token": creds.SessionToken,
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
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					serverContacted = true
				}
			}
		}
	}

	// 4. Remove local credentials file
	if rErr := os.Remove(credsFile); rErr != nil && !os.IsNotExist(rErr) {
		if !*force {
			return fmt.Errorf("failed to remove local credentials file %s: %w", credsFile, rErr)
		}
	}

	// 5. Also purge secondary session state if present
	_ = os.Remove(state.CredentialsPath())

	fmt.Println("================================================================================")
	fmt.Println("  [BAP ZERO-TRUST] 🚪 Developer Workstation Logout & Deregistration")
	fmt.Println("================================================================================")
	if serverContacted {
		fmt.Printf("  [✓] Central Control Plane Session Revoked: %s\n", serverURL)
	} else if serverURL != "" {
		fmt.Printf("  [!] Remote Server Notice: Control plane unreachable (%s); deregistered locally.\n", serverURL)
	}
	if creds.UserEmail != "" {
		fmt.Printf("  [✓] Authenticated Identity: %s (%s)\n", creds.UserEmail, creds.IdPProvider)
	}
	if creds.InstanceID != "" {
		fmt.Printf("  [✓] Workstation Instance:   %s\n", creds.InstanceID)
	}
	fmt.Printf("  [✓] Removed credentials:    %s\n", credsFile)
	fmt.Println("  [✓] Workstation is now logged out. Run 'bap login' to re-authenticate.")
	fmt.Println("================================================================================")
	return nil
}
