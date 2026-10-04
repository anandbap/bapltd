package cmd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"bap-edge/internal/attest"
	"bap-edge/internal/config"
	"bap-edge/internal/httptransport"
)

type oidcDiscoveryConfig struct {
	Enabled         bool     `json:"enabled"`
	Provider        string   `json:"provider"`
	IssuerURL       string   `json:"issuer_url"`
	ClientID        string   `json:"client_id"`
	VerificationURI string   `json:"verification_uri"`
	Scopes          []string `json:"scopes"`
	TenantID        string   `json:"tenant_id"`
	AllowedDomains  []string `json:"allowed_domains"`
}

type oidcDeviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type oidcDeviceTokenResponse struct {
	Status       string    `json:"status"`
	Error        string    `json:"error,omitempty"`
	UserEmail    string    `json:"user_email"`
	Department   string    `json:"department"`
	Groups       []string  `json:"groups"`
	AgentID      string    `json:"agent_id"`
	AppID        string    `json:"app_id"`
	InstanceID   string    `json:"instance_id"`
	SessionToken string    `json:"session_token"`
	Provider     string    `json:"provider"`
}

// RunLogin executes the RFC 8628 OAuth 2.0 / OIDC Device Authorization Flow
// to bind the edge agent session to the engineer's corporate identity (Okta / Entra ID).
func RunLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	epCfg := config.ResolveEndpoints()
	serverURL := fs.String("server", epCfg.ControlPlaneURL, "bap-controlplane URL")
	providerFlag := fs.String("provider", "", "Enterprise OIDC provider ('entra', 'okta', or 'generic')")
	userEmailFlag := fs.String("email", "", "Corporate user email (for testing or interactive simulation)")
	deptFlag := fs.String("department", "Engineering", "Corporate department claim (e.g. Finance, Engineering)")
	groupsFlag := fs.String("groups", "developers,ai-assist-users", "Comma-separated group memberships")
	verifyNow := fs.Bool("verify-now", false, "Immediately complete MFA approval on control plane (for automation/CI)")
	configPath := fs.String("config", DefaultCredentialsPath(), "Path to store enrolled credentials")
	caCertPath := fs.String("ca-cert", os.Getenv("BAP_CA_CERT"), "Path to custom CA certificate for HTTPS verification")
	insecureTLS := fs.Bool("insecure", false, "Skip TLS certificate verification (development only)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// 1. Build HTTP client
	httpClient := httptransport.New(10 * time.Second)
	if *insecureTLS {
		httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			Timeout: 10 * time.Second,
		}
	} else if *caCertPath != "" {
		if caData, err := os.ReadFile(*caCertPath); err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(caData) {
				httpClient = &http.Client{
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{RootCAs: pool},
					},
					Timeout: 10 * time.Second,
				}
			}
		}
	}

	// 2. Discover server OIDC configuration
	provider := *providerFlag
	if provider == "" {
		if epCfg.OIDC.Provider != "" {
			provider = epCfg.OIDC.Provider
		} else {
			// Query control plane /api/v1/auth/oidc/config
			cfgURL := fmt.Sprintf("%s/api/v1/auth/oidc/config", *serverURL)
			if resp, err := httpClient.Get(cfgURL); err == nil {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					var disc oidcDiscoveryConfig
					if json.NewDecoder(resp.Body).Decode(&disc) == nil && disc.Provider != "" {
						provider = disc.Provider
					}
				}
			}
		}
	}
	if provider == "" {
		provider = "entra"
	}

	// 3. Compute binary hash for attestation
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to determine executable path: %w", err)
	}
	binHash, err := attest.ComputeFileSHA256(exePath)
	if err != nil {
		return fmt.Errorf("failed to compute binary hash for %q: %w", exePath, err)
	}
	hostname, _ := os.Hostname()

	// 4. Initiate Device Authorization Flow (RFC 8628)
	deviceCodeURL := fmt.Sprintf("%s/api/v1/auth/oidc/device-code", *serverURL)
	codeReqBody, _ := json.Marshal(map[string]interface{}{
		"client_id":   "bap-edge-cli",
		"scope":       "openid profile email groups",
		"provider":    provider,
		"hostname":    hostname,
		"binary_hash": binHash,
		"app_id":      "claude-code-workstation",
	})

	resp, err := httpClient.Post(deviceCodeURL, "application/json", bytes.NewReader(codeReqBody))
	if err != nil {
		return fmt.Errorf("failed to connect to control plane at %s: %w", deviceCodeURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("control plane device authorization initiation failed (%d): %s", resp.StatusCode, string(bodyBytes))
	}

	var codeResp oidcDeviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&codeResp); err != nil {
		return fmt.Errorf("failed to parse device code response: %w", err)
	}

	idpLabel := "Microsoft Entra ID"
	if strings.EqualFold(provider, "okta") {
		idpLabel = "Okta Workforce Identity Cloud"
	} else if strings.EqualFold(provider, "generic") {
		idpLabel = "Corporate OpenID Connect (OIDC)"
	}

	fmt.Println()
	fmt.Println("===========================================================================")
	fmt.Printf("   BAP Enterprise Identity Provider Federation (RFC 8628 Device Flow)\n")
	fmt.Println("===========================================================================")
	fmt.Printf(" Corporate IdP: %s (MFA Enforced)\n", idpLabel)
	fmt.Println(" To authenticate your local agent session:")
	fmt.Printf("   1. Open your browser and navigate to:\n")
	fmt.Printf("      %s\n", codeResp.VerificationURI)
	fmt.Printf("   2. Enter the user code:\n")
	fmt.Printf("      %s\n", codeResp.UserCode)
	if codeResp.VerificationURIComplete != "" {
		fmt.Printf("   (Direct Link: %s)\n", codeResp.VerificationURIComplete)
	}
	fmt.Println("===========================================================================")
	fmt.Println("[*] Waiting for corporate MFA authorization...")

	// 5. If --verify-now is specified (e.g. CI/scripting/testing), trigger instant verification
	if *verifyNow {
		verifyURL := fmt.Sprintf("%s/api/v1/auth/oidc/device-verify", *serverURL)
		email := *userEmailFlag
		if email == "" {
			email = "developer@corp.internal"
		}
		var groupsList []string
		for _, g := range strings.Split(*groupsFlag, ",") {
			if trimmed := strings.TrimSpace(g); trimmed != "" {
				groupsList = append(groupsList, trimmed)
			}
		}
		verifyBody, _ := json.Marshal(map[string]interface{}{
			"user_code":   codeResp.UserCode,
			"user_email":  email,
			"department":  *deptFlag,
			"groups":      groupsList,
			"provider":    provider,
		})
		vResp, vErr := httpClient.Post(verifyURL, "application/json", bytes.NewReader(verifyBody))
		if vErr == nil {
			vResp.Body.Close()
		}
	}

	// 6. Poll device token endpoint per RFC 8628 section 3.5
	tokenURL := fmt.Sprintf("%s/api/v1/auth/oidc/device-token", *serverURL)
	tokenReqBody, _ := json.Marshal(map[string]string{
		"device_code": codeResp.DeviceCode,
	})

	interval := time.Duration(codeResp.Interval) * time.Second
	if interval < 500*time.Millisecond {
		interval = 1 * time.Second
	}
	deadline := time.Now().Add(time.Duration(codeResp.ExpiresIn) * time.Second)

	var tokenResp oidcDeviceTokenResponse
	authenticated := false

	for time.Now().Before(deadline) {
		time.Sleep(interval)

		tResp, tErr := httpClient.Post(tokenURL, "application/json", bytes.NewReader(tokenReqBody))
		if tErr != nil {
			continue
		}

		if tResp.StatusCode == http.StatusOK {
			if err := json.NewDecoder(tResp.Body).Decode(&tokenResp); err == nil && tokenResp.Status == "authorized" {
				authenticated = true
				tResp.Body.Close()
				break
			}
		}

		var errObj map[string]string
		_ = json.NewDecoder(tResp.Body).Decode(&errObj)
		tResp.Body.Close()

		if errObj["error"] == "expired_token" || errObj["error"] == "access_denied" {
			return fmt.Errorf("device authentication failed: %s", errObj["error"])
		}
	}

	if !authenticated {
		return fmt.Errorf("device authentication timed out waiting for approval")
	}

	// 7. Store credentials in ~/.ltd/credentials.json
	creds := StoredCredentials{
		ServerURL:    *serverURL,
		AgentID:      tokenResp.AgentID,
		AppID:        tokenResp.AppID,
		InstanceID:   tokenResp.InstanceID,
		BinaryHash:   binHash,
		SessionToken: tokenResp.SessionToken,
		AuthMode:     "oidc",
		UserEmail:    tokenResp.UserEmail,
		Department:   tokenResp.Department,
		Groups:       tokenResp.Groups,
		IdPProvider:  provider,
		EnrolledAt:   time.Now(),
	}

	if err := os.MkdirAll(filepath.Dir(*configPath), 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	credsData, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize credentials: %w", err)
	}

	if err := os.WriteFile(*configPath, credsData, 0600); err != nil {
		return fmt.Errorf("failed to write credentials to %s: %w", *configPath, err)
	}

	fmt.Println()
	fmt.Printf("[✓] Corporate Identity Verified via %s\n", idpLabel)
	fmt.Printf("    User Email:  %s\n", tokenResp.UserEmail)
	fmt.Printf("    Department:  %s\n", tokenResp.Department)
	fmt.Printf("    Groups:      %v\n", tokenResp.Groups)
	fmt.Printf("    Session ID:  %s\n", tokenResp.InstanceID)
	fmt.Printf("[✓] Enrolled credentials saved to: %s\n", *configPath)
	fmt.Println("[✓] Local agent session is now bound to your corporate identity and ready for Cedar governance.")
	return nil
}
