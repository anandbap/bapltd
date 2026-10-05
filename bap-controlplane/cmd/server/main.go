package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"bap-controlplane/internal/api"
	"bap-controlplane/internal/audit"
	"bap-controlplane/internal/authz"
	"bap-controlplane/internal/otc"
	"bap-controlplane/internal/policy"
	"bap-controlplane/internal/registry"
	"bap-controlplane/internal/session"
	"bap-controlplane/internal/tlsutil"
	"bap-controlplane/pkg/types"
)

func main() {
	port := flag.Int("port", 8080, "Port for bapcontrolplane HTTP server")
	secretKey := flag.String("secret", "", "HMAC signing secret for tokens")
	adminToken := flag.String("admin-token", "", "Administrative secret token for control APIs (default: auto-generated or read from BAP_ADMIN_TOKEN)")
	allowRemoteAdmin := flag.Bool("allow-remote-admin", false, "Allow remote network callers to invoke admin APIs with valid token (default: false, localhost only)")
	grantTTL := flag.Int("ttl", 30, "Default grant TTL in minutes")
	policyPath := flag.String("policy", "", "Path to authoritative Cedar policy file")
	schemaPath := flag.String("schema", "", "Path to authoritative Cedar schema file")
	trustDomain := flag.String("trust-domain", "bap.internal", "SPIFFE Trust Domain for agent workload identities")
	useTLS := flag.Bool("tls", false, "Enable HTTPS/TLS")
	httpsFlag := flag.Bool("https", false, "Enable HTTPS (auto-generates dev certs if none provided)")
	autoTLS := flag.Bool("tls-auto", false, "Auto-generate self-signed TLS certificates for development")
	certPath := flag.String("tls-cert", "", "Path to TLS certificate PEM file")
	keyPath := flag.String("tls-key", "", "Path to TLS private key PEM file")
	dbPath := flag.String("db", "", "Path to SQLite database file for state persistence (default: bap-controlplane.db, 'memory' for in-memory)")
	allowedOrigins := flag.String("allowed-origins", os.Getenv("BAP_ALLOWED_ORIGINS"), "Comma-separated exact browser origins; same-origin only by default")
	demoMode := flag.Bool("demo-mode", false, "Enable destructive synthetic demo endpoints (or set BAP_DEMO_MODE=true)")
	mode := flag.String("mode", "dev", "Control plane environment mode: 'dev' (open self-service OTC token request) or 'prod' (strictly locked offline OTC, enterprise OIDC required)")
	oidcProvider := flag.String("oidc-provider", "entra", "Enterprise OIDC provider: 'entra', 'okta', or 'generic'")
	oidcIssuer := flag.String("oidc-issuer", "", "OIDC issuer / discovery URL")
	oidcClientID := flag.String("oidc-client-id", "", "OIDC application client ID")
	oidcTenantID := flag.String("oidc-tenant-id", "", "Microsoft Entra tenant ID or Okta org")
	oidcAllowedDomains := flag.String("oidc-allowed-domains", "", "Comma-separated corporate email domains permitted (e.g. corp.com,internal.org)")
	flag.Parse()
	if envPort := os.Getenv("PORT"); envPort != "" && *port == 8080 {
		if p, err := strconv.Atoi(envPort); err == nil && p > 0 {
			*port = p
		}
	} else if envPort := os.Getenv("BAP_PORT"); envPort != "" && *port == 8080 {
		if p, err := strconv.Atoi(envPort); err == nil && p > 0 {
			*port = p
		}
	}
	if envRemote := os.Getenv("BAP_ALLOW_REMOTE_ADMIN"); envRemote != "" {
		*allowRemoteAdmin = envRemote == "1" || strings.EqualFold(envRemote, "true")
	}
	if envDemo := strings.TrimSpace(os.Getenv("BAP_DEMO_MODE")); envDemo != "" {
		*demoMode = envDemo == "1" || strings.EqualFold(envDemo, "true")
	}
	if envMode := strings.TrimSpace(os.Getenv("BAP_MODE")); envMode != "" && *mode == "dev" {
		*mode = envMode
	}
	if envMode := strings.TrimSpace(os.Getenv("BAP_ENVIRONMENT")); envMode != "" && *mode == "dev" {
		*mode = envMode
	}
	if envProvider := strings.TrimSpace(os.Getenv("BAP_OIDC_PROVIDER")); envProvider != "" {
		*oidcProvider = envProvider
	}
	if envIssuer := strings.TrimSpace(os.Getenv("BAP_OIDC_ISSUER_URL")); envIssuer != "" {
		*oidcIssuer = envIssuer
	}
	if envClientID := strings.TrimSpace(os.Getenv("BAP_OIDC_CLIENT_ID")); envClientID != "" {
		*oidcClientID = envClientID
	}
	if envTenant := strings.TrimSpace(os.Getenv("BAP_OIDC_TENANT_ID")); envTenant != "" {
		*oidcTenantID = envTenant
	}
	if envDomains := strings.TrimSpace(os.Getenv("BAP_OIDC_ALLOWED_DOMAINS")); envDomains != "" {
		*oidcAllowedDomains = envDomains
	}
	if (*certPath == "") != (*keyPath == "") {
		log.Fatal("Both -tls-cert and -tls-key are required")
	}
	if *autoTLS && *certPath != "" {
		log.Fatal("Do not combine -tls-auto with certificate files")
	}
	if *certPath != "" {
		*useTLS = true
	}

	if *httpsFlag {
		*useTLS = true
	}
	if *useTLS && *certPath == "" && *keyPath == "" {
		*autoTLS = true
	}

	if envAdmin := os.Getenv("BAP_ADMIN_TOKEN"); envAdmin != "" && *adminToken == "" {
		*adminToken = envAdmin
	}
	// Check if an existing valid .bap-admin-token file exists on disk to persist across server restarts
	if *adminToken == "" {
		for _, tokenCandidate := range []string{".bap-admin-token", filepath.Join("..", ".bap-admin-token")} {
			if data, err := os.ReadFile(tokenCandidate); err == nil {
				trimmed := strings.TrimSpace(string(data))
				if strings.HasPrefix(trimmed, "bap_adm_") && len(trimmed) >= 16 {
					*adminToken = trimmed
					log.Printf("[bapcontrolplane] Reusing existing administrative credential from %s", tokenCandidate)
					break
				}
			}
		}
	}
	if *adminToken == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err == nil {
			*adminToken = "bap_adm_" + hex.EncodeToString(b)
		} else {
			log.Fatal("Unable to generate administrative credential securely")
		}
		log.Printf("[bapcontrolplane] Generated admin credential; retrieve it from the protected .bap-admin-token file")
	} else {
		log.Printf("[bapcontrolplane] Administrative security enabled with configured token")
	}
	if err := os.WriteFile(".bap-admin-token", []byte(*adminToken), 0600); err != nil {
		log.Fatalf("Cannot write admin credential file: %v", err)
	}

	if envSecret := os.Getenv("BAP_SECRET_KEY"); envSecret != "" {
		*secretKey = envSecret
	}
	if *secretKey == "ltd-service-bounded-authority-secret-key-32b!" {
		log.Fatal("The published demo signing secret is not permitted; configure BAP_SECRET_KEY")
	}
	if *secretKey == "" {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			log.Fatal("Unable to generate signing key securely")
		}
		*secretKey = hex.EncodeToString(key)
		log.Print("Using ephemeral signing key; configure BAP_SECRET_KEY for stable credentials across restart")
	}

	if envTD := os.Getenv("BAP_TRUST_DOMAIN"); envTD != "" {
		*trustDomain = envTD
	}

	regStore := registry.NewStore(*trustDomain)
	otcStore := otc.NewStore()
	minter := authz.NewTokenMinter(*secretKey, time.Duration(*grantTTL)*time.Minute)

	resolvedPolicy := *policyPath
	if resolvedPolicy == "" {
		candidates := []string{"bap-edge/policy.cedar", "./bap-edge/policy.cedar", "../bap-edge/policy.cedar", "../ltd-agent/policy.cedar", "./policy.cedar", "../policy.cedar"}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				resolvedPolicy = c
				break
			}
		}
	}
	resolvedSchema := *schemaPath
	if resolvedSchema == "" {
		candidates := []string{"bap-edge/schema.json", "./bap-edge/schema.json", "../bap-edge/schema.json", "../ltd-agent/schema.json", "./schema.json", "../schema.json"}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				resolvedSchema = c
				break
			}
		}
	}

	cedarContent, _ := os.ReadFile(resolvedPolicy)
	if len(cedarContent) == 0 {
		cedarContent = []byte("permit(principal, action, resource);")
	}
	schemaContent, _ := os.ReadFile(resolvedSchema)
	policyStore := policy.NewStore(string(cedarContent), string(schemaContent))
	auditStore := audit.NewStore()

	resolvedDB := *dbPath
	if resolvedDB == "" {
		resolvedDB = os.Getenv("BAP_DB_PATH")
	}
	if resolvedDB == "" {
		resolvedDB = "bap-controlplane.db"
	}

	sessionStore, err := session.NewStoreWithDB(resolvedDB)
	if err != nil {
		log.Printf("[bapcontrolplane] Warning: Failed to open SQLite DB %q (%v), falling back to in-memory store", resolvedDB, err)
		sessionStore = session.NewStore()
	} else if resolvedDB != ":memory:" && resolvedDB != "memory" {
		log.Printf("[bapcontrolplane] SQLite state persistence active: %s", resolvedDB)
	}

	server := api.NewServer(regStore, otcStore, minter, policyStore, auditStore, sessionStore)
	server.SetAdminSecurity(*adminToken, *allowRemoteAdmin)
	server.SetDemoMode(*demoMode)
	server.SetEnvironmentMode(*mode)

	oidcCfg := types.OIDCConfig{
		Enabled:         true,
		Provider:        *oidcProvider,
		IssuerURL:       *oidcIssuer,
		ClientID:        *oidcClientID,
		TenantID:        *oidcTenantID,
		Scopes:          []string{"openid", "profile", "email", "groups"},
		ClaimDepartment: "department",
		ClaimGroups:     "groups",
		ClaimEmail:      "email",
	}
	if *oidcAllowedDomains != "" {
		for _, domain := range strings.Split(*oidcAllowedDomains, ",") {
			trimmed := strings.TrimSpace(domain)
			if trimmed != "" {
				oidcCfg.AllowedDomains = append(oidcCfg.AllowedDomains, trimmed)
			}
		}
	}
	server.SetOIDCConfig(oidcCfg)

	if err := server.SetAllowedOrigins(strings.Split(*allowedOrigins, ",")); err != nil {
		log.Fatal(err)
	}

	addr := fmt.Sprintf(":%d", *port)
	proto := "http"
	if *useTLS || *autoTLS || *httpsFlag {
		proto = "https"
	}
	log.Printf("[bapcontrolplane] Central Control Plane for Bounded Authority Plane starting on %s://%s (Mode: %s)", proto, addr, strings.ToUpper(*mode))
	log.Printf("[bapcontrolplane] Trust Domain: %s (SPIFFE format: spiffe://%s/app/{app_id}/instance/{instance_id})", *trustDomain, *trustDomain)
	log.Printf("[bapcontrolplane] Features: Agent Registry, Multi-Instance Quotas, Binary Hash Attestation, Dynamic Policy Sync, Audit Ingestion, Session Lifecycle")

	srv := &http.Server{
		Addr:         addr,
		Handler:      server.Handler(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	if *useTLS || *autoTLS || *httpsFlag {
		// 1. Auto-discover provisioned controlplane-cert.pem if flags omitted
		if *certPath == "" && *keyPath == "" {
			for _, dir := range []string{".", "..", "../.."} {
				candCert := filepath.Join(dir, "controlplane-cert.pem")
				candKey := filepath.Join(dir, "controlplane-key.pem")
				if _, errC := os.Stat(candCert); errC == nil {
					if _, errK := os.Stat(candKey); errK == nil {
						*certPath = candCert
						*keyPath = candKey
						break
					}
				}
			}
		}

		// 2. If certificate and key are found, load them directly
		if *certPath != "" && *keyPath != "" {
			log.Printf("[bapcontrolplane] Loading TLS certificate from %s and key from %s", *certPath, *keyPath)
			if err := srv.ListenAndServeTLS(*certPath, *keyPath); err != nil && err != http.ErrServerClosed {
				log.Fatalf("[bapcontrolplane] Fatal TLS server error: %v", err)
			}
			return
		}

		// 3. Fallback: generate self-signed ephemeral certificates for rapid local dev
		log.Printf("[bapcontrolplane] Generating self-signed TLS certificates for development...")
		tlsCert, certPEM, keyPEM, err := tlsutil.GenerateSelfSignedCert([]string{"localhost", "127.0.0.1", "a.b.com"}, 365*24*time.Hour)
		if err != nil {
			log.Fatalf("[bapcontrolplane] Failed to generate self-signed cert: %v", err)
		}
		_ = tlsutil.SaveCertAndKey("controlplane-cert.pem", "controlplane-key.pem", certPEM, keyPEM)
		log.Printf("[bapcontrolplane] Exported dev cert to controlplane-cert.pem for client trust verification")
		srv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
		}
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[bapcontrolplane] Fatal TLS server error: %v", err)
		}
		return
	}

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("[bapcontrolplane] ERROR: Could not start server on %s: %v", addr, err)
		log.Printf("[bapcontrolplane] Note: Port %d is already in use by another running instance or process.", *port)
		log.Printf("[bapcontrolplane] Run 'powershell Get-NetTCPConnection -LocalPort %d' to check the occupying process.", *port)
		time.Sleep(1 * time.Second)
		os.Exit(1)
	}
}
