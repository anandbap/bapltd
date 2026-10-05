package config

import (
	"bap-edge/internal/state"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// OIDCConfig defines client-side and discovered Enterprise IdP parameters.
type OIDCConfig struct {
	Enabled         bool     `json:"enabled"`
	Provider        string   `json:"provider,omitempty"`
	IssuerURL       string   `json:"issuer_url,omitempty"`
	ClientID        string   `json:"client_id,omitempty"`
	VerificationURI string   `json:"verification_uri,omitempty"`
	Scopes          []string `json:"scopes,omitempty"`
	TenantID        string   `json:"tenant_id,omitempty"`
	AllowedDomains  []string `json:"allowed_domains,omitempty"`
}

// EndpointsConfig holds central host and endpoint URLs for BAP services.
type EndpointsConfig struct {
	ControlPlaneURL string     `json:"controlplane_url"`
	GatewayURL      string     `json:"gateway_url"`
	EnvoyURL        string     `json:"envoy_url"`
	TrustDomain     string     `json:"trust_domain"`
	Environment     string     `json:"environment,omitempty"`
	EnforcementMode string     `json:"enforcement_mode,omitempty"`
	ConfigSource    string     `json:"config_source,omitempty"`
	OIDC            OIDCConfig `json:"oidc,omitempty"`
}

const (
	DefaultControlPlaneURL = "http://localhost:8080"
	DefaultGatewayURL      = "http://localhost:9090"
	DefaultEnvoyURL        = "http://localhost:10000"
	DefaultTrustDomain     = "bap.internal"
)

// ResolveEndpoints returns the active configuration by checking:
// 1. Environment variables (BAP_SERVER_URL, BAP_CONTROL_PLANE_URL, BAP_GATEWAY_URL, etc.)
// 2. Local repository / directory bap-config.json (walking up to 4 levels)
// 3. User home directory (~/.bap/config.json or ~/.ltd/credentials.json)
// 4. System-wide corporate path (%PROGRAMDATA%\BAP\config.json or /etc/bap/config.json)
// 5. Default local fallback (localhost:8080 / localhost:9090)
func ResolveEndpoints() EndpointsConfig {
	cfg := EndpointsConfig{
		ControlPlaneURL: DefaultControlPlaneURL,
		GatewayURL:      DefaultGatewayURL,
		EnvoyURL:        DefaultEnvoyURL,
		TrustDomain:     DefaultTrustDomain,
		Environment:     "development",
		EnforcementMode: "enforce",
		ConfigSource:    "default_fallback",
	}

	// 1. Try configuration files in priority order
	configFiles := getCandidateConfigFilePaths()
	for _, path := range configFiles {
		if fileCfg, err := loadConfigFile(path); err == nil {
			if fileCfg.ControlPlaneURL != "" {
				cfg.ControlPlaneURL = strings.TrimRight(fileCfg.ControlPlaneURL, "/")
			}
			if fileCfg.GatewayURL != "" {
				cfg.GatewayURL = strings.TrimRight(fileCfg.GatewayURL, "/")
			}
			if fileCfg.EnvoyURL != "" {
				cfg.EnvoyURL = strings.TrimRight(fileCfg.EnvoyURL, "/")
			}
			if fileCfg.TrustDomain != "" {
				cfg.TrustDomain = fileCfg.TrustDomain
			}
			if fileCfg.Environment != "" {
				cfg.Environment = fileCfg.Environment
			}
			if fileCfg.EnforcementMode != "" {
				cfg.EnforcementMode = strings.ToLower(strings.TrimSpace(fileCfg.EnforcementMode))
			}
			cfg.ConfigSource = path
			break
		}
	}

	// 2. Check credentials.json if control plane URL is still default
	if cfg.ControlPlaneURL == DefaultControlPlaneURL {
		if credsURL := loadServerURLFromCredentials(); credsURL != "" {
			cfg.ControlPlaneURL = credsURL
			cfg.ConfigSource = "user_credentials"
		}
	}

	// 3. Environment variable overrides (Highest Precedence)
	if envCP := getFirstEnv("BAP_SERVER_URL", "BAP_CONTROL_PLANE_URL", "LTD_SERVER_URL"); envCP != "" {
		cfg.ControlPlaneURL = strings.TrimRight(envCP, "/")
		cfg.ConfigSource = "environment_variable"
	}
	if envGW := getFirstEnv("BAP_GATEWAY_URL", "LTD_GATEWAY_URL"); envGW != "" {
		cfg.GatewayURL = strings.TrimRight(envGW, "/")
	}
	if envEnvoy := getFirstEnv("BAP_ENVOY_URL"); envEnvoy != "" {
		cfg.EnvoyURL = strings.TrimRight(envEnvoy, "/")
	}
	if envTD := getFirstEnv("BAP_TRUST_DOMAIN"); envTD != "" {
		cfg.TrustDomain = envTD
	}
	if envEnv := getFirstEnv("BAP_ENV"); envEnv != "" {
		cfg.Environment = envEnv
	}
	if envMode := getFirstEnv("BAP_ENFORCEMENT_MODE", "BAP_MODE"); envMode != "" {
		cfg.EnforcementMode = strings.ToLower(strings.TrimSpace(envMode))
	}
	if envOIDCProvider := getFirstEnv("BAP_OIDC_PROVIDER"); envOIDCProvider != "" {
		cfg.OIDC.Provider = envOIDCProvider
		cfg.OIDC.Enabled = true
	}
	if envOIDCClient := getFirstEnv("BAP_OIDC_CLIENT_ID"); envOIDCClient != "" {
		cfg.OIDC.ClientID = envOIDCClient
		cfg.OIDC.Enabled = true
	}
	if envOIDCTenant := getFirstEnv("BAP_OIDC_TENANT_ID"); envOIDCTenant != "" {
		cfg.OIDC.TenantID = envOIDCTenant
	}
	if envOIDCIssuer := getFirstEnv("BAP_OIDC_ISSUER_URL"); envOIDCIssuer != "" {
		cfg.OIDC.IssuerURL = envOIDCIssuer
	}
	if cfg.EnforcementMode == "" {
		cfg.EnforcementMode = "enforce"
	}

	return cfg
}

func getFirstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func getCandidateConfigFilePaths() []string {
	var candidates []string

	// 1. Authoritative .bapstate config path
	candidates = append(candidates, state.ConfigPath())

	// Current working directory and parent search (up to 4 levels)
	cwd, err := os.Getwd()
	if err == nil {
		curr := cwd
		for i := 0; i < 4; i++ {
			candidates = append(candidates, filepath.Join(curr, ".bap", "bap-config.json"))
			candidates = append(candidates, filepath.Join(curr, ".bap", "config.json"))
			candidates = append(candidates, filepath.Join(curr, "bap-config.json"))
			parent := filepath.Dir(curr)
			if parent == curr {
				break
			}
			curr = parent
		}
	}

	// Executable directory
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates, filepath.Join(exeDir, "bap-config.json"))
		candidates = append(candidates, filepath.Join(exeDir, "..", "bap-config.json"))
	}

	// User home directory: ~/.bap/config.json and ~/.ltd/config.json
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".bap", "config.json"))
		candidates = append(candidates, filepath.Join(home, ".ltd", "config.json"))
	}

	// System-wide corporate path
	if runtime.GOOS == "windows" {
		if progData := os.Getenv("ProgramData"); progData != "" {
			candidates = append(candidates, filepath.Join(progData, "BAP", "config.json"))
			candidates = append(candidates, filepath.Join(progData, "BAP", "bap-config.json"))
		}
	} else {
		candidates = append(candidates, "/etc/bap/config.json")
		candidates = append(candidates, "/etc/bap/bap-config.json")
	}

	return candidates
}

func loadConfigFile(path string) (*EndpointsConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg EndpointsConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func loadServerURLFromCredentials() string {
	credsPath := state.CredentialsPath()
	data, err := os.ReadFile(credsPath)
	if err != nil {
		return ""
	}
	var creds struct {
		ServerURL string `json:"server_url"`
	}
	if err := json.Unmarshal(data, &creds); err == nil && creds.ServerURL != "" {
		return strings.TrimRight(creds.ServerURL, "/")
	}
	return ""
}

// SaveConfig writes the configuration to the specified path or defaults to .bapstate/config.json.
func SaveConfig(cfg EndpointsConfig, targetPath string) error {
	if targetPath == "" {
		targetPath = state.ConfigPath()
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil && filepath.Dir(targetPath) != "." {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(targetPath, data, 0644)
}
