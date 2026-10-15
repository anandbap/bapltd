package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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

const usage = `bapcontrolplane - BAP Central Control Plane & Policy Authority
(Identity, Dynamic Policy Distribution, OTC Enrollment, and Audit Aggregation)

Usage:
  bapcontrolplane <command> [flags]

Available Commands:
  start     Start the Central Control Plane HTTP/TLS server
  stop      Gracefully terminate the running Central Control Plane instance
  status    Query status, health, port, uptime, and database metrics
  restart   Restart the running Central Control Plane instance
  enable    Initialize environment, admin tokens, and state stores
  serve     Run server in foreground (alias for 'start')
  help      Display help and usage information

Common Flags for 'start' / 'serve':
  --port <p>             Port for HTTP server (default: 8080 or $PORT)
  --detach, -d           Run as detached background process
  --mode <dev|prod>      Environment mode: 'dev' (open OTC) or 'prod' (strict OTC / OIDC)
  --db <path>            Path to SQLite database file (default: bap-controlplane.db)
  --secret <key>         HMAC signing secret for tokens (or $BAP_SECRET_KEY)
  --admin-token <token>  Administrative token for control APIs (or $BAP_ADMIN_TOKEN)
  --allow-remote-admin   Allow non-localhost callers with valid admin token
  --tls, --https         Enable HTTPS/TLS (auto-generates dev cert if none provided)
  --policy <path>        Path to authoritative Cedar policy file
  --schema <path>        Path to authoritative Cedar schema file

Examples:
  bapcontrolplane start --port 8080
  bapcontrolplane start --detach --port 8080
  bapcontrolplane status
  bapcontrolplane stop
  bapcontrolplane restart
  bapcontrolplane enable
`

func pidPath() string {
	if fi, err := os.Stat(".bapstate"); err == nil && fi.IsDir() {
		return filepath.Join(".bapstate", "bap-controlplane.pid")
	}
	home, err := os.UserHomeDir()
	if err == nil {
		homeBapstate := filepath.Join(home, ".bapstate")
		if fi, err := os.Stat(homeBapstate); err == nil && fi.IsDir() {
			return filepath.Join(homeBapstate, "bap-controlplane.pid")
		}
	}
	return "bap-controlplane.pid"
}

func readPID(p string) (int, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(0)
	}

	command := os.Args[1]
	args := os.Args[2:]

	switch command {
	case "help", "-h", "--help":
		fmt.Print(usage)
		os.Exit(0)
	case "start":
		runStart(args)
	case "stop":
		runStop(args)
	case "status":
		runStatus(args)
	case "restart":
		runRestart(args)
	case "enable":
		runEnable(args)
	case "serve", "run":
		runStart(args)
	default:
		// Strict backward compatibility: if flag is passed directly (e.g. `bapcontrolplane -port 8080`), default to start
		if strings.HasPrefix(command, "-") {
			runStart(os.Args[1:])
			return
		}
		fmt.Fprintf(os.Stderr, "Unknown command %q for bapcontrolplane\n\n%s", command, usage)
		os.Exit(1)
	}
}

func runStart(args []string) {
	fs := flag.NewFlagSet("bapcontrolplane start", flag.ExitOnError)
	port := fs.Int("port", 8080, "Port for bapcontrolplane HTTP server")
	detach := fs.Bool("detach", false, "Run as detached background daemon")
	fs.BoolVar(detach, "d", false, "Run as detached background daemon (shorthand)")
	fg := fs.Bool("foreground", false, "Run in foreground")
	fs.BoolVar(fg, "fg", false, "Run in foreground (shorthand)")
	secretKey := fs.String("secret", "", "HMAC signing secret for tokens")
	adminToken := fs.String("admin-token", "", "Administrative secret token for control APIs (default: auto-generated or read from BAP_ADMIN_TOKEN)")
	allowRemoteAdmin := fs.Bool("allow-remote-admin", false, "Allow remote network callers to invoke admin APIs with valid token (default: false, localhost only)")
	grantTTL := fs.Int("ttl", 30, "Default grant TTL in minutes")
	policyPath := fs.String("policy", "", "Path to authoritative Cedar policy file")
	schemaPath := fs.String("schema", "", "Path to authoritative Cedar schema file")
	trustDomain := fs.String("trust-domain", "bap.internal", "SPIFFE Trust Domain for agent workload identities")
	useTLS := fs.Bool("tls", false, "Enable HTTPS/TLS")
	httpsFlag := fs.Bool("https", false, "Enable HTTPS (auto-generates dev certs if none provided)")
	autoTLS := fs.Bool("tls-auto", false, "Auto-generate self-signed TLS certificates for development")
	certPath := fs.String("tls-cert", "", "Path to TLS certificate PEM file")
	keyPath := fs.String("tls-key", "", "Path to TLS private key PEM file")
	dbPath := fs.String("db", "", "Path to SQLite database file for state persistence (default: bap-controlplane.db, 'memory' for in-memory)")
	allowedOrigins := fs.String("allowed-origins", os.Getenv("BAP_ALLOWED_ORIGINS"), "Comma-separated exact browser origins; same-origin only by default")
	demoMode := fs.Bool("demo-mode", false, "Enable destructive synthetic demo endpoints (or set BAP_DEMO_MODE=true)")
	mode := fs.String("mode", "dev", "Control plane environment mode: 'dev' (open self-service OTC token request) or 'prod' (strictly locked offline OTC, enterprise OIDC required)")
	oidcProvider := fs.String("oidc-provider", "entra", "Enterprise OIDC provider: 'entra', 'okta', or 'generic'")
	oidcIssuer := fs.String("oidc-issuer", "", "OIDC issuer / discovery URL")
	oidcClientID := fs.String("oidc-client-id", "", "OIDC application client ID")
	oidcTenantID := fs.String("oidc-tenant-id", "", "Microsoft Entra tenant ID or Okta org")
	oidcAllowedDomains := fs.String("oidc-allowed-domains", "", "Comma-separated corporate email domains permitted (e.g. corp.com,internal.org)")

	_ = fs.Parse(args)

	if *detach && !*fg {
		exe, err := os.Executable()
		if err != nil {
			log.Fatalf("Failed to resolve executable path: %v", err)
		}
		var childArgs []string
		childArgs = append(childArgs, "start", "--fg")
		for _, a := range args {
			if a == "--detach" || a == "-detach" || a == "-d" || a == "--d" {
				continue
			}
			childArgs = append(childArgs, a)
		}
		cmd := exec.Command(exe, childArgs...)
		cmd.Dir = "."
		cmd.Stdout = nil
		cmd.Stderr = nil
		cmd.Stdin = nil
		cmd.SysProcAttr = getSysProcAttrDetached()
		if err := cmd.Start(); err != nil {
			log.Fatalf("Failed to start background bapcontrolplane: %v", err)
		}
		pPath := pidPath()
		_ = os.WriteFile(pPath, []byte(strconv.Itoa(cmd.Process.Pid)), 0644)
		_ = os.WriteFile("bap-controlplane.pid", []byte(strconv.Itoa(cmd.Process.Pid)), 0644)
		time.Sleep(300 * time.Millisecond)
		fmt.Printf("✅ BAP Control Plane launched in background (PID: %d on port %d)\n", cmd.Process.Pid, *port)
		fmt.Println("   Run 'bapcontrolplane status' to inspect health and metrics.")
		return
	}

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

	// Persist PID
	pPath := pidPath()
	_ = os.WriteFile(pPath, []byte(strconv.Itoa(os.Getpid())), 0644)
	_ = os.WriteFile("bap-controlplane.pid", []byte(strconv.Itoa(os.Getpid())), 0644)
	defer func() {
		_ = os.Remove(pPath)
		_ = os.Remove("bap-controlplane.pid")
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("[bapcontrolplane] Received shutdown signal. Gracefully stopping...")
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = os.Remove(pPath)
		_ = os.Remove("bap-controlplane.pid")
		os.Exit(0)
	}()

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
		log.Printf("[bapcontrolplane] Run 'bapcontrolplane stop' or check occupying process.", *port)
		time.Sleep(1 * time.Second)
		os.Exit(1)
	}
}

func runStop(args []string) {
	pid, err := readPID(pidPath())
	if err != nil || pid <= 0 || !isProcessAlive(pid) {
		pid, err = readPID("bap-controlplane.pid")
	}
	if err != nil || pid <= 0 || !isProcessAlive(pid) {
		fmt.Println("⚠️  BAP Control Plane is not currently running.")
		_ = os.Remove(pidPath())
		_ = os.Remove("bap-controlplane.pid")
		return
	}

	if err := killProcess(pid); err != nil {
		fmt.Printf("❌ Failed to terminate BAP Control Plane (PID %d): %v\n", pid, err)
		return
	}
	_ = os.Remove(pidPath())
	_ = os.Remove("bap-controlplane.pid")
	fmt.Printf("✅ BAP Control Plane (PID %d) stopped successfully.\n", pid)
}

func runStatus(args []string) {
	fs := flag.NewFlagSet("bapcontrolplane status", flag.ContinueOnError)
	port := fs.Int("port", 8080, "Port for bapcontrolplane HTTP server")
	jsonFlag := fs.Bool("json", false, "Output status as JSON")
	_ = fs.Parse(args)

	pid, _ := readPID(pidPath())
	if pid <= 0 {
		pid, _ = readPID("bap-controlplane.pid")
	}

	url := fmt.Sprintf("http://localhost:%d", *port)
	if envPort := os.Getenv("PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil && p > 0 {
			url = fmt.Sprintf("http://localhost:%d", p)
		}
	} else if envPort := os.Getenv("BAP_PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil && p > 0 {
			url = fmt.Sprintf("http://localhost:%d", p)
		}
	}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url + "/api/v1/health")
	if err != nil {
		resp, err = client.Get(url + "/health")
	}

	if err != nil {
		if *jsonFlag {
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
				"running": false,
				"error":   err.Error(),
			})
			return
		}
		fmt.Println("⚠️  BAP Control Plane is not currently running.")
		fmt.Printf("   No responsive server found on %s\n", url)
		fmt.Println("   Run 'bapcontrolplane start' to launch the central authority.")
		return
	}
	defer resp.Body.Close()

	var data map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&data)

	if *jsonFlag {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(data)
		return
	}

	fmt.Println("================================================================================")
	fmt.Println("  [BAP CONTROL PLANE] 🛡️  Central Authority Status & Metrics")
	fmt.Println("================================================================================")
	fmt.Printf("  Status:           ONLINE / HEALTHY (HTTP %d)\n", resp.StatusCode)
	if pid > 0 && isProcessAlive(pid) {
		fmt.Printf("  PID:              %d\n", pid)
	}
	fmt.Printf("  Endpoint:         %s\n", url)
	if statusVal, ok := data["status"]; ok {
		fmt.Printf("  Service Status:   %v\n", statusVal)
	}
	if modeVal, ok := data["mode"]; ok {
		fmt.Printf("  Environment Mode: %v\n", modeVal)
	}
	if tdVal, ok := data["trust_domain"]; ok {
		fmt.Printf("  Trust Domain:     %v\n", tdVal)
	}

	adminConfigured := false
	if tokenData, err := os.ReadFile(".bap-admin-token"); err == nil && len(strings.TrimSpace(string(tokenData))) > 0 {
		adminConfigured = true
	}
	if adminConfigured {
		fmt.Println("  Admin Security:   Configured (Active in .bap-admin-token)")
	} else {
		fmt.Println("  Admin Security:   Auto-generated / Ephemeral")
	}

	if dbPath, ok := data["db_path"]; ok {
		fmt.Printf("  Database Store:   %v\n", dbPath)
	}
	fmt.Println("================================================================================")
}

func runRestart(args []string) {
	fmt.Println("[*] Restarting BAP Control Plane...")
	runStop(nil)
	time.Sleep(500 * time.Millisecond)
	runStart(args)
}

func runEnable(args []string) {
	fmt.Println("================================================================================")
	fmt.Println("  [BAP CONTROL PLANE] 🚀 Initializing Central Authority & State Stores")
	fmt.Println("================================================================================")

	adminToken := ""
	if data, err := os.ReadFile(".bap-admin-token"); err == nil {
		trimmed := strings.TrimSpace(string(data))
		if strings.HasPrefix(trimmed, "bap_adm_") && len(trimmed) >= 16 {
			adminToken = trimmed
			fmt.Println("  • Admin Token:      Reusing existing credential in .bap-admin-token")
		}
	}
	if adminToken == "" {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		adminToken = "bap_adm_" + hex.EncodeToString(b)
		if err := os.WriteFile(".bap-admin-token", []byte(adminToken), 0600); err != nil {
			fmt.Printf("  ❌ Failed to write .bap-admin-token: %v\n", err)
		} else {
			fmt.Println("  • Admin Token:      Generated and saved to .bap-admin-token")
		}
	}

	stateDir := ".bapstate"
	if err := os.MkdirAll(stateDir, 0700); err == nil {
		fmt.Printf("  • State Directory:  Verified (%s)\n", stateDir)
	}

	policyCandidates := []string{"bap-edge/policy.cedar", "./policy.cedar"}
	foundPolicy := false
	for _, p := range policyCandidates {
		if _, err := os.Stat(p); err == nil {
			fmt.Printf("  • Cedar Policy:     Found (%s)\n", p)
			foundPolicy = true
			break
		}
	}
	if !foundPolicy {
		fmt.Println("  • Cedar Policy:     Using default embedded permissive policy")
	}

	fmt.Println("================================================================================")
	fmt.Println("✅ BAP Control Plane is enabled and ready to start.")
	fmt.Println("   Run 'bapcontrolplane start' to launch the server.")
}
