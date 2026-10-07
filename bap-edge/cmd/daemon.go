package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"bap-edge/internal/audit"
	"bap-edge/internal/config"
	"bap-edge/internal/httptransport"
	"bap-edge/internal/state"
)

// DaemonState stores configuration and live metadata for a running bap-daemon.
type DaemonState struct {
	PID           int                `json:"pid"`
	Port          int                `json:"port"`
	URL           string             `json:"url"`
	ServerURL     string             `json:"server_url"`
	Privilege     string             `json:"privilege"`     // "STANDARD_USER" or "ELEVATED_ADMIN"
	OperatingMode string             `json:"operating_mode"` // "DEGRADED" or "OPTIMAL"
	Capabilities  DaemonCapabilities `json:"capabilities"`
	StartedAt     time.Time          `json:"started_at"`
	AuthToken     string             `json:"auth_token"`
}

// DaemonCapabilities defines what enforcement capabilities are currently possible.
type DaemonCapabilities struct {
	IPCHub               bool `json:"ipc_hub"`
	BackgroundSpool      bool `json:"background_spool"`
	JobObjectContainment bool `json:"job_object_containment"`
	KernelEBPFETW        bool `json:"kernel_ebpf_etw"`
	KernelPacketFilter   bool `json:"kernel_packet_filter"`
}

// AttachedSession represents an active AI agent session managed through this daemon.
type AttachedSession struct {
	SessionID  string    `json:"session_id"`
	AppID      string    `json:"app_id"`
	PID        int       `json:"pid"`
	AttachedAt time.Time `json:"attached_at"`
}

// DaemonServer coordinates local IPC, background heartbeat, and spool flushing.
type DaemonServer struct {
	state        DaemonState
	mu           sync.RWMutex
	sessions     map[string]AttachedSession
	listener     net.Listener
	httpServer   *http.Server
	cpConnected  bool
	cpLatencyMs  int64
	messagesRecv int64
	transSuccess int64
	transFailed  int64
	stopCh       chan struct{}
}

func DaemonConfigPath() string {
	return filepath.Join(state.Dir(), "daemon.json")
}

func DaemonPidPath() string {
	return filepath.Join(state.Dir(), "bap-daemon.pid")
}

// ReadDaemonState loads the current daemon connection info if active.
func ReadDaemonState() (*DaemonState, error) {
	data, err := os.ReadFile(DaemonConfigPath())
	if err != nil {
		return nil, err
	}
	var ds DaemonState
	if err := json.Unmarshal(data, &ds); err != nil {
		return nil, err
	}
	if !isProcessAlive(ds.PID) {
		_ = os.Remove(DaemonConfigPath())
		_ = os.Remove(DaemonPidPath())
		return nil, fmt.Errorf("daemon PID %d is not running", ds.PID)
	}
	return &ds, nil
}

// NewDaemonServer initializes the server state and capability matrix.
func NewDaemonServer(serverURL string, port int) (*DaemonServer, error) {
	elevated := isElevated()
	privilege := "STANDARD_USER"
	operatingMode := "DEGRADED"
	caps := DaemonCapabilities{
		IPCHub:               true,
		BackgroundSpool:      true,
		JobObjectContainment: true,
		KernelEBPFETW:        false, // Disabled in degraded user mode
		KernelPacketFilter:   false, // Disabled without admin driver privileges
	}

	if elevated {
		privilege = "ELEVATED_ADMIN"
		operatingMode = "OPTIMAL"
		caps.KernelEBPFETW = true
		caps.KernelPacketFilter = true
	}

	tokenBytes := make([]byte, 16)
	_, _ = rand.Read(tokenBytes)
	authToken := hex.EncodeToString(tokenBytes)

	ds := DaemonState{
		PID:           os.Getpid(),
		Port:          port,
		ServerURL:     serverURL,
		Privilege:     privilege,
		OperatingMode: operatingMode,
		Capabilities:  caps,
		StartedAt:     time.Now().UTC(),
		AuthToken:     authToken,
	}

	return &DaemonServer{
		state:    ds,
		sessions: make(map[string]AttachedSession),
		stopCh:   make(chan struct{}),
	}, nil
}

// Start launches the local HTTP listener and background supervision loops.
func (s *DaemonServer) Start() error {
	addr := fmt.Sprintf("127.0.0.1:%d", s.state.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		// If port is 0 or taken, try an ephemeral loopback port
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return fmt.Errorf("failed to bind daemon IPC listener: %w", err)
		}
	}
	s.listener = ln
	tcpAddr := ln.Addr().(*net.TCPAddr)
	s.state.Port = tcpAddr.Port
	s.state.URL = fmt.Sprintf("http://127.0.0.1:%d", s.state.Port)

	// Persist daemon.json and bap-daemon.pid
	stateBytes, _ := json.MarshalIndent(s.state, "", "  ")
	_ = os.WriteFile(DaemonConfigPath(), stateBytes, 0600)
	_ = os.WriteFile(DaemonPidPath(), []byte(strconv.Itoa(s.state.PID)), 0600)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/api/v1/daemon/status", s.handleStatus)
	mux.HandleFunc("/api/v1/daemon/event", s.handleEvent)
	mux.HandleFunc("/api/v1/daemon/attach", s.handleAttach)
	mux.HandleFunc("/api/v1/daemon/detach", s.handleDetach)
	mux.HandleFunc("/api/v1/daemon/stop", s.handleStop)

	s.httpServer = &http.Server{
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	// Start background workers
	ctx, cancel := context.WithCancel(context.Background())
	go s.runHeartbeatWorker(ctx)
	go s.runSpoolWorker(ctx)
	go s.runSessionReconcileWorker(ctx)

	go func() {
		<-s.stopCh
		cancel()
		_ = s.httpServer.Shutdown(context.Background())
		_ = os.Remove(DaemonConfigPath())
		_ = os.Remove(DaemonPidPath())
	}()

	return s.httpServer.Serve(ln)
}

func (s *DaemonServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "healthy",
		"mode":   s.state.OperatingMode,
		"uptime": time.Since(s.state.StartedAt).String(),
	})
}

func (s *DaemonServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var sessionList []string
	for sid := range s.sessions {
		sessionList = append(sessionList, sid)
	}

	auditLogPath := audit.DefaultLogPath()
	offlineEntries, _ := audit.ReadEntries(auditLogPath)

	resp := map[string]any{
		"daemon": map[string]any{
			"pid":            s.state.PID,
			"port":           s.state.Port,
			"url":            s.state.URL,
			"uptime_seconds": int(time.Since(s.state.StartedAt).Seconds()),
			"privilege":      s.state.Privilege,
			"mode":           s.state.OperatingMode,
			"degraded":       s.state.OperatingMode == "DEGRADED",
			"capabilities":   s.state.Capabilities,
		},
		"control_plane": map[string]any{
			"url":        s.state.ServerURL,
			"connected":  s.cpConnected,
			"latency_ms": s.cpLatencyMs,
		},
		"agents_attached": map[string]any{
			"count":    len(s.sessions),
			"sessions": sessionList,
		},
		"telemetry": map[string]any{
			"messages_received":   atomic.LoadInt64(&s.messagesRecv),
			"transmitted_success": atomic.LoadInt64(&s.transSuccess),
			"transmissions_failed": atomic.LoadInt64(&s.transFailed),
			"spool_backlog":       len(offlineEntries),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *DaemonServer) handleEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var entry audit.AuditEntry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	atomic.AddInt64(&s.messagesRecv, 1)

	// Log locally to durable audit log
	_ = audit.Log(&entry, "")

	// Async transmit to central control plane
	go func(ent audit.AuditEntry) {
		ok, _, err := audit.Transmit(ent, s.state.ServerURL, "")
		if ok && err == nil {
			atomic.AddInt64(&s.transSuccess, 1)
		} else {
			atomic.AddInt64(&s.transFailed, 1)
		}
	}(entry)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":   "accepted",
		"event_id": entry.EventID,
	})
}

func (s *DaemonServer) handleAttach(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var sess AttachedSession
	if err := json.NewDecoder(r.Body).Decode(&sess); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sess.AttachedAt = time.Now().UTC()

	s.mu.Lock()
	s.sessions[sess.SessionID] = sess
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":     "attached",
		"session_id": sess.SessionID,
	})
}

func (s *DaemonServer) handleDetach(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	delete(s.sessions, req.SessionID)
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":     "detached",
		"session_id": req.SessionID,
	})
}

func (s *DaemonServer) handleStop(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "stopping"})
	go func() {
		time.Sleep(100 * time.Millisecond)
		close(s.stopCh)
	}()
}

func (s *DaemonServer) runHeartbeatWorker(ctx context.Context) {
	ticker := time.NewTicker(4 * time.Second)
	defer ticker.Stop()
	client := httptransport.New(2 * time.Second)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if s.state.ServerURL == "" {
				continue
			}
			start := time.Now()
			resp, err := client.Get(strings.TrimRight(s.state.ServerURL, "/") + "/health")
			if err == nil {
				s.mu.Lock()
				s.cpConnected = (resp.StatusCode == http.StatusOK)
				s.cpLatencyMs = time.Since(start).Milliseconds()
				s.mu.Unlock()
				_ = resp.Body.Close()
			} else {
				s.mu.Lock()
				s.cpConnected = false
				s.cpLatencyMs = 0
				s.mu.Unlock()
			}

			// Pulse active sessions
			s.mu.RLock()
			for _, sess := range s.sessions {
				pulsePayload := map[string]any{
					"session_id": sess.SessionID,
					"app_id":     sess.AppID,
					"pid":        sess.PID,
				}
				body, _ := json.Marshal(pulsePayload)
				_, _ = client.Post(strings.TrimRight(s.state.ServerURL, "/")+"/api/v1/sessions/heartbeat", "application/json", bytes.NewReader(body))
			}
			s.mu.RUnlock()
		}
	}
}

func (s *DaemonServer) runSpoolWorker(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !s.cpConnected || s.state.ServerURL == "" {
				continue
			}
			n, err := audit.FlushOfflineAudit(s.state.ServerURL, "")
			if err == nil && n > 0 {
				atomic.AddInt64(&s.transSuccess, int64(n))
			}
		}
	}
}

func (s *DaemonServer) runSessionReconcileWorker(ctx context.Context) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			for sid, sess := range s.sessions {
				if !isProcessAlive(sess.PID) {
					delete(s.sessions, sid)
					_ = os.Remove(sessionMarkerPath(sid))
				}
			}
			s.mu.Unlock()
		}
	}
}

// RunDaemon handles the 'daemon' CLI command tree.
func RunDaemon(args []string) error {
	if len(args) == 0 {
		return printDaemonUsage()
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "start", "run":
		return runDaemonStart(subArgs)
	case "status":
		return runDaemonStatus(subArgs)
	case "stop":
		return runDaemonStop(subArgs)
	default:
		return fmt.Errorf("unknown daemon command %q (use: start, status, stop)", sub)
	}
}

func printDaemonUsage() error {
	fmt.Println("Usage: bapedge daemon <command> [flags]")
	fmt.Println("\nCommands:")
	fmt.Println("  start     Start the BAP Edge daemon subsystem")
	fmt.Println("  status    Query status, capabilities, and telemetry of the active daemon")
	fmt.Println("  stop      Gracefully shut down the running daemon")
	return nil
}

func runDaemonStart(args []string) error {
	fs := flag.NewFlagSet("daemon start", flag.ContinueOnError)
	portFlag := fs.Int("port", 18446, "Local IPC port (default: 18446)")
	serverFlag := fs.String("server", "", "Central BAP control plane URL")
	fgFlag := fs.Bool("foreground", false, "Run in foreground (default: background)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Check if daemon is already running
	if existing, err := ReadDaemonState(); err == nil && existing != nil {
		fmt.Printf("⚠️  BAP Daemon is already running (PID: %d, Mode: %s, URL: %s)\n",
			existing.PID, existing.OperatingMode, existing.URL)
		return nil
	}

	serverURL := *serverFlag
	if serverURL == "" {
		ep := config.ResolveEndpoints()
		serverURL = ep.ControlPlaneURL
	}
	if serverURL == "" {
		serverURL = "http://localhost:8080"
	}

	if !*fgFlag {
		// Spawn as background detached process
		exe, _ := os.Executable()
		cmd := exec.Command(exe, "daemon", "start", "-foreground", "-port", strconv.Itoa(*portFlag), "-server", serverURL)
		cmd.Dir = "."
		cmd.Stdout = nil
		cmd.Stderr = nil
		cmd.Stdin = nil
		detachProcess(cmd)
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("failed to start background daemon: %w", err)
		}
		time.Sleep(500 * time.Millisecond)
		fmt.Printf("✅ BAP Daemon launched in background (PID: %d on port %d)\n", cmd.Process.Pid, *portFlag)
		fmt.Println("   Run 'bapedge daemon status' to inspect capability matrix.")
		return nil
	}

	server, err := NewDaemonServer(serverURL, *portFlag)
	if err != nil {
		return err
	}

	fmt.Println("================================================================================")
	fmt.Println("  [BAP DAEMON] 🛡️  Initializing Edge Daemon Subsystem")
	fmt.Println("================================================================================")
	fmt.Printf("  PID:              %d\n", server.state.PID)
	fmt.Printf("  Privilege Level:  %s\n", server.state.Privilege)
	fmt.Printf("  Operating Mode:   %s\n", server.state.OperatingMode)
	fmt.Printf("  Control Plane:    %s\n", server.state.ServerURL)
	fmt.Printf("  Capabilities:\n")
	fmt.Printf("    • IPC Hub:                 %v\n", server.state.Capabilities.IPCHub)
	fmt.Printf("    • Background Spooler:      %v\n", server.state.Capabilities.BackgroundSpool)
	fmt.Printf("    • Job Object Containment:  %v\n", server.state.Capabilities.JobObjectContainment)
	fmt.Printf("    • Kernel eBPF/ETW Probes:  %v\n", server.state.Capabilities.KernelEBPFETW)
	fmt.Printf("    • Kernel Packet Filtering: %v\n", server.state.Capabilities.KernelPacketFilter)
	fmt.Println("--------------------------------------------------------------------------------")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n[*] Received shutdown signal. Stopping daemon...")
		close(server.stopCh)
	}()

	return server.Start()
}

func runDaemonStatus(args []string) error {
	fs := flag.NewFlagSet("daemon status", flag.ContinueOnError)
	jsonFlag := fs.Bool("json", false, "Output status as JSON")

	if err := fs.Parse(args); err != nil {
		return err
	}

	ds, err := ReadDaemonState()
	if err != nil || ds == nil {
		if *jsonFlag {
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
				"daemon_running": false,
				"error":          "BAP Daemon is not running",
			})
			return nil
		}
		fmt.Println("⚠️  BAP Daemon is not currently running.")
		fmt.Println("   Run 'bapedge daemon start' to launch the background supervisor.")
		return nil
	}

	client := httptransport.New(2 * time.Second)
	resp, err := client.Get(ds.URL + "/api/v1/daemon/status")
	if err != nil {
		if *jsonFlag {
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
				"daemon_running": false,
				"error":          err.Error(),
			})
			return nil
		}
		return fmt.Errorf("failed to contact daemon at %s: %w", ds.URL, err)
	}
	defer resp.Body.Close()

	if *jsonFlag {
		var raw map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&raw)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(raw)
	}

	var statusData struct {
		Daemon struct {
			PID           int                `json:"pid"`
			Port          int                `json:"port"`
			URL           string             `json:"url"`
			UptimeSeconds int                `json:"uptime_seconds"`
			Privilege     string             `json:"privilege"`
			Mode          string             `json:"mode"`
			Degraded      bool               `json:"degraded"`
			Capabilities  DaemonCapabilities `json:"capabilities"`
		} `json:"daemon"`
		ControlPlane struct {
			URL       string `json:"url"`
			Connected bool   `json:"connected"`
			LatencyMs int64  `json:"latency_ms"`
		} `json:"control_plane"`
		AgentsAttached struct {
			Count    int      `json:"count"`
			Sessions []string `json:"sessions"`
		} `json:"agents_attached"`
		Telemetry struct {
			MessagesReceived    int64 `json:"messages_received"`
			TransmittedSuccess  int64 `json:"transmitted_success"`
			TransmissionsFailed int64 `json:"transmissions_failed"`
			SpoolBacklog        int   `json:"spool_backlog"`
		} `json:"telemetry"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&statusData); err != nil {
		return fmt.Errorf("failed to decode daemon response: %w", err)
	}

	uptime := time.Duration(statusData.Daemon.UptimeSeconds) * time.Second
	cpStatus := "OFFLINE / UNREACHABLE"
	if statusData.ControlPlane.Connected {
		cpStatus = fmt.Sprintf("CONNECTED / ONLINE (%dms latency)", statusData.ControlPlane.LatencyMs)
	}

	modeDesc := "OPTIMAL (Kernel-Enforced / Elevated)"
	if statusData.Daemon.Degraded {
		modeDesc = "DEGRADED (User-Mode Sandbox & IPC Hub - Non-Elevated)"
	}

	fmt.Println("================================================================================")
	fmt.Println("  [BAP DAEMON] 🛡️  Daemon Subsystem Status & Capability Inspection")
	fmt.Println("================================================================================")
	fmt.Printf("  Daemon PID:       %d (Uptime: %s)\n", statusData.Daemon.PID, uptime)
	fmt.Printf("  Privilege Level:  %s\n", statusData.Daemon.Privilege)
	fmt.Printf("  Operating Mode:   %s\n", modeDesc)
	fmt.Printf("  IPC Endpoint:     %s\n", statusData.Daemon.URL)

	fmt.Println("\n  CAPABILITY MATRIX:")
	fmt.Printf("    • IPC Pipe Hub:                     %s\n", formatCap(statusData.Daemon.Capabilities.IPCHub, "Active"))
	fmt.Printf("    • Background Spool Engine:          %s\n", formatCap(statusData.Daemon.Capabilities.BackgroundSpool, "Active"))
	fmt.Printf("    • Process Tree Supervision:         %s\n", formatCap(statusData.Daemon.Capabilities.JobObjectContainment, "Active (User-Mode)"))
	fmt.Printf("    • Kernel eBPF/ETW Tracepoints:      %s\n", formatCap(statusData.Daemon.Capabilities.KernelEBPFETW, "Requires Admin/Root"))
	fmt.Printf("    • Kernel Packet Filtering:          %s\n", formatCap(statusData.Daemon.Capabilities.KernelPacketFilter, "Requires Driver Privileges"))

	fmt.Println("\n  CONTROL PLANE CONNECTION:")
	fmt.Printf("    • Target URL:                       %s\n", statusData.ControlPlane.URL)
	fmt.Printf("    • Status:                           %s\n", cpStatus)

	fmt.Println("\n  ATTACHED AGENTS & IPC CLIENTS:")
	fmt.Printf("    • Connected Sessions:               %d active\n", statusData.AgentsAttached.Count)
	for _, sid := range statusData.AgentsAttached.Sessions {
		fmt.Printf("      - %s\n", sid)
	}

	fmt.Println("\n  TELEMETRY & TRANSMISSION METRICS:")
	fmt.Printf("    • Messages Received via IPC:        %d\n", statusData.Telemetry.MessagesReceived)
	fmt.Printf("    • Successfully Transmitted to CP:   %d\n", statusData.Telemetry.TransmittedSuccess)
	fmt.Printf("    • Failed Transmissions / Retrying:  %d\n", statusData.Telemetry.TransmissionsFailed)
	fmt.Printf("    • Spool Backlog Queued:             %d\n", statusData.Telemetry.SpoolBacklog)
	fmt.Println("================================================================================")
	return nil
}

func formatCap(active bool, note string) string {
	if active {
		return "ACTIVE (" + note + ")"
	}
	return "DISABLED (" + note + ")"
}

func runDaemonStop(args []string) error {
	ds, err := ReadDaemonState()
	if err != nil || ds == nil {
		fmt.Println("⚠️  BAP Daemon is not running.")
		return nil
	}

	client := httptransport.New(2 * time.Second)
	_, _ = client.Post(ds.URL+"/api/v1/daemon/stop", "application/json", strings.NewReader("{}"))
	time.Sleep(300 * time.Millisecond)

	_ = os.Remove(DaemonConfigPath())
	_ = os.Remove(DaemonPidPath())
	fmt.Printf("✅ BAP Daemon (PID %d) stopped successfully.\n", ds.PID)
	return nil
}
