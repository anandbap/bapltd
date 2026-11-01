package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"bap-edge/internal/config"
	"bap-edge/internal/state"
	"bap-edge/pkg/version"
)

var errRuntimeRunning = errors.New("runtime already running")

type SupervisorState struct {
	PID         int       `json:"pid"`
	Birth       string    `json:"process_birth"`
	Version     string    `json:"version"`
	Commit      string    `json:"git_commit"`
	Status      string    `json:"status"`
	CheckedAt   time.Time `json:"checked_at"`
	StartedAt   time.Time `json:"started_at"`
	Restarts    int       `json:"restarts"`
	NextAttempt time.Time `json:"next_attempt,omitempty"`
	Error       string    `json:"error,omitempty"`
}

func supervisorPath() string     { return filepath.Join(state.Dir(), "supervisor.json") }
func daemonPausePath() string    { return filepath.Join(state.Dir(), "daemon.paused") }
func supervisorStopPath() string { return filepath.Join(state.Dir(), "supervisor.stop") }
func writeRuntimeState(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".runtime-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	_ = f.Chmod(0600)
	_, err = f.Write(body)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(tmp, path)
}
func readSupervisorState() (*SupervisorState, error) {
	body, err := os.ReadFile(supervisorPath())
	if err != nil {
		return nil, err
	}
	var st SupervisorState
	if err = json.Unmarshal(body, &st); err != nil {
		return nil, err
	}
	if !isProcessAlive(st.PID) || st.Birth != "" && processBirth(st.PID) != st.Birth {
		return nil, errors.New("supervisor process identity is stale")
	}
	return &st, nil
}
func daemonResponsive(ds *DaemonState) bool {
	if ds == nil || !strings.HasPrefix(ds.URL, "http://127.0.0.1:") {
		return false
	}
	client := &http.Client{Timeout: 600 * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Get(ds.URL + "/health")
	if err != nil {
		return false
	}
	defer response.Body.Close()
	var health struct {
		PID   int    `json:"pid"`
		Birth string `json:"process_birth"`
	}
	return response.StatusCode == 200 && json.NewDecoder(response.Body).Decode(&health) == nil && health.PID == ds.PID && (ds.ProcessBirth == "" || health.Birth == ds.ProcessBirth)
}

type supervisorController struct {
	state    SupervisorState
	failures int
}

func (c *supervisorController) step(now time.Time, paused, alive, healthy bool, launch func() error) {
	c.state.CheckedAt = now
	c.state.Error = ""
	if paused {
		c.state.Status = "paused"
		return
	}
	if healthy {
		c.state.Status = "monitoring"
		c.failures = 0
		c.state.NextAttempt = time.Time{}
		return
	}
	if alive {
		c.state.Status = "unresponsive"
		c.state.Error = "daemon process exists but readiness failed; inspect before restarting"
		return
	}
	if now.Before(c.state.NextAttempt) {
		c.state.Status = "backoff"
		return
	}
	c.state.Restarts++
	c.state.Status = "starting"
	if err := launch(); err != nil {
		c.state.Status = "retrying"
		c.state.Error = "daemon launch failed"
	}
	c.failures++
	delay := time.Second * time.Duration(1<<min(c.failures-1, 5))
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}
	c.state.NextAttempt = now.Add(delay)
}

func runDaemonSupervise(args []string) error {
	flags := flag.NewFlagSet("daemon supervise", flag.ContinueOnError)
	foreground := flags.Bool("foreground", false, "Run supervisor in foreground")
	stop := flags.Bool("stop", false, "Stop supervisor without terminating the daemon")
	server := flags.String("server", "", "Reporting server (master enrollment remains authoritative)")
	root := flags.String("state-dir", "", "Explicit local state directory for logon startup")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *root != "" {
		if !filepath.IsAbs(*root) {
			return errors.New("state directory must be absolute")
		}
		if err := os.Setenv("BAP_STATE_DIR", *root); err != nil {
			return err
		}
		if filepath.Clean(state.Dir()) != filepath.Clean(*root) {
			return errors.New("state directory was initialized differently; use the configured BAP_STATE_DIR")
		}
	}
	if *stop {
		if err := writeRuntimeState(supervisorStopPath(), map[string]bool{"stop": true}); err != nil {
			return err
		}
		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := readSupervisorState(); err != nil {
				return nil
			}
			time.Sleep(50 * time.Millisecond)
		}
		return errors.New("supervisor did not stop before deadline")
	}
	if existing, err := readSupervisorState(); err == nil {
		if time.Since(existing.CheckedAt) > 10*time.Second {
			return errors.New("supervisor process exists but monitoring is stale; inspect before restarting")
		}
		fmt.Printf("Supervisor already running (PID %d, %s)\n", existing.PID, existing.Status)
		return nil
	}
	if !*foreground {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if strings.HasSuffix(exe, ".test.exe") || strings.HasSuffix(exe, ".test") {
			return errors.New("background supervisor unavailable inside a test runner")
		}
		if err = os.Remove(supervisorStopPath()); err != nil && !os.IsNotExist(err) {
			return err
		}
		command := exec.Command(exe, "daemon", "supervise", "-foreground", "-server", *server)
		command.Dir = state.Dir()
		detachProcess(command)
		if err = command.Start(); err != nil {
			return err
		}
		_ = command.Process.Release()
		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := readSupervisorState(); err == nil {
				return nil
			}
			time.Sleep(50 * time.Millisecond)
		}
		return errors.New("supervisor did not become ready")
	}
	release, err := acquireRuntimeLock("supervisor")
	if errors.Is(err, errRuntimeRunning) {
		return nil
	}
	if err != nil {
		return err
	}
	defer release()
	control := supervisorController{state: SupervisorState{PID: os.Getpid(), Birth: processBirth(os.Getpid()), Version: version.Version, Commit: version.GitCommit, StartedAt: time.Now().UTC(), Status: "starting"}}
	defer os.Remove(supervisorPath())
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var child *exec.Cmd
	for {
		if _, err := os.Stat(supervisorStopPath()); err == nil {
			return nil
		}
		_, pauseErr := os.Stat(daemonPausePath())
		paused := pauseErr == nil
		ds, _ := ReadDaemonState()
		healthy := daemonResponsive(ds)
		alive := ds != nil
		if child != nil && isProcessAlive(child.Process.Pid) {
			alive = true
		}
		control.step(time.Now().UTC(), paused, alive, healthy, func() error {
			exe, err := os.Executable()
			if err != nil {
				return err
			}
			target := config.ReportingEndpoint(*server)
			if target == "" {
				target = config.ResolveEndpoints().ControlPlaneURL
			}
			command := exec.Command(exe, "daemon", "start", "-foreground", "-server", target)
			command.Dir = state.Dir()
			detachProcess(command)
			if err = command.Start(); err != nil {
				return err
			}
			child = command
			go func() { _ = command.Wait() }()
			return nil
		})
		if err := writeRuntimeState(supervisorPath(), control.state); err != nil {
			return fmt.Errorf("supervisor status could not be persisted: %w", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
