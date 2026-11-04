package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	discoverymeta "bap-edge/internal/discovery"
	"bap-edge/internal/httptransport"
	"bap-edge/internal/state"
)

func discoveryRoot() string { return filepath.Join(state.Dir(), "discovery") }
func (s *DaemonServer) requestDiscovery(epoch int64) {
	select {
	case s.discoveryRequests <- epoch:
	default:
	}
}

func collectDiscovery(epoch int64) discoverymeta.Report {
	home, _ := os.UserHomeDir()
	workspace, _ := os.Getwd()
	sources := discoverymeta.Sources(home, workspace)
	// Installer-owned explicit roots make discovery independent of whichever
	// directory the background daemon happens to start in. Never recurse home.
	var registered struct {
		Roots []string `json:"roots"`
	}
	rootPath := filepath.Join(state.Dir(), "discovery-roots.json")
	rootStatus := "complete"
	if st, err := os.Lstat(rootPath); os.IsNotExist(err) {
		rootStatus = "unsupported"
	} else if err != nil || !st.Mode().IsRegular() || st.Size() > 8192 {
		rootStatus = "error"
	} else {
		if body, err := os.ReadFile(rootPath); err != nil || json.Unmarshal(body, &registered) != nil {
			rootStatus = "error"
		} else {
			for i, root := range registered.Roots {
				if i >= 8 {
					rootStatus = "error"
					break
				}
				if filepath.IsAbs(root) && filepath.Dir(root) != root {
					sources = append(sources, discoverymeta.Sources("", root)...)
				} else {
					rootStatus = "error"
				}
			}
		}
	}
	r := discoverymeta.Collect(sources, epoch)
	r.Scopes = append(r.Scopes, discoverymeta.Scope{ID: "workspace-registration", Status: rootStatus})
	if rootStatus != "complete" {
		r.Status = "partial"
	}
	processes, err := listAgentProcesses()
	scope := discoverymeta.Scope{ID: "agent-processes", Status: "complete"}
	if err != nil {
		scope.Status = "error"
		r.Status = "partial"
	} else {
		for _, p := range processes {
			app := agentApp(p.Name)
			if app == "" {
				continue
			}
			if p.Birth == "" || len(r.Observations) >= 512 {
				scope.Status = "error"
				r.Status = "partial"
				continue
			}
			r.Observations = append(r.Observations, discoverymeta.Observation{Key: "process-" + discoverymeta.ID(fmt.Sprint(p.PID), p.Birth), Scope: scope.ID, Kind: "agent_process", Name: app, Client: app, Evidence: "running", ObservedAt: time.Now().UTC(), PID: p.PID, Birth: p.Birth})
		}
	}
	r.Scopes = append(r.Scopes, scope)

	// BAP-806: Agent Plugin Discovery Scope
	pluginScope := discoverymeta.Scope{ID: "agent-plugins", Status: "complete"}
	claudeRec := InspectClaudePlugin(workspace)
	if claudeRec.PluginInstalled {
		r.Observations = append(r.Observations, discoverymeta.Observation{
			Key:        "plugin-" + discoverymeta.ID(claudeRec.Client, claudeRec.PluginName),
			Scope:      pluginScope.ID,
			Kind:       "agent_plugin",
			Name:       claudeRec.PluginName,
			Client:     claudeRec.Client,
			Evidence:   string(claudeRec.State),
			ObservedAt: time.Now().UTC(),
		})
	}
	copilotRec := InspectCopilotPlugin(workspace)
	if copilotRec.PluginInstalled {
		r.Observations = append(r.Observations, discoverymeta.Observation{
			Key:        "plugin-" + discoverymeta.ID(copilotRec.Client, copilotRec.PluginName),
			Scope:      pluginScope.ID,
			Kind:       "agent_plugin",
			Name:       copilotRec.PluginName,
			Client:     copilotRec.Client,
			Evidence:   string(copilotRec.State),
			ObservedAt: time.Now().UTC(),
		})
	}
	antigravityRec := InspectAntigravityPlugin(workspace)
	if antigravityRec.PluginInstalled {
		r.Observations = append(r.Observations, discoverymeta.Observation{
			Key:        "plugin-" + discoverymeta.ID(antigravityRec.Client, antigravityRec.PluginName),
			Scope:      pluginScope.ID,
			Kind:       "agent_plugin",
			Name:       antigravityRec.PluginName,
			Client:     antigravityRec.Client,
			Evidence:   string(antigravityRec.State),
			ObservedAt: time.Now().UTC(),
		})
	}
	opencodeRec := InspectOpenCodePlugin(workspace)
	if opencodeRec.PluginInstalled {
		r.Observations = append(r.Observations, discoverymeta.Observation{
			Key:        "plugin-" + discoverymeta.ID(opencodeRec.Client, opencodeRec.PluginName),
			Scope:      pluginScope.ID,
			Kind:       "agent_plugin",
			Name:       opencodeRec.PluginName,
			Client:     opencodeRec.Client,
			Evidence:   string(opencodeRec.State),
			ObservedAt: time.Now().UTC(),
		})
	}
	codexRec := InspectCodexPlugin(workspace)
	if codexRec.PluginInstalled {
		r.Observations = append(r.Observations, discoverymeta.Observation{
			Key:        "plugin-" + discoverymeta.ID(codexRec.Client, codexRec.PluginName),
			Scope:      pluginScope.ID,
			Kind:       "agent_plugin",
			Name:       codexRec.PluginName,
			Client:     codexRec.Client,
			Evidence:   string(codexRec.State),
			ObservedAt: time.Now().UTC(),
		})
	}
	r.Scopes = append(r.Scopes, pluginScope)

	r.CompletedAt = time.Now().UTC()
	return r
}

func replayDiscovery(root string) error {
	files, err := os.ReadDir(filepath.Join(root, "retained"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Join(root, "pending"), 0700); err != nil {
		return err
	}
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		if err = os.Rename(filepath.Join(root, "retained", f.Name()), filepath.Join(root, "pending", f.Name())); err != nil {
			return err
		}
	}
	return nil
}

// Upload at most 16 files per pass. A slow or unavailable control plane never
// holds the execution broker, native hook, heartbeat, or process watcher.
func flushDiscovery(ctx context.Context, root, server string) error {
	files, err := os.ReadDir(filepath.Join(root, "pending"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	client := httptransport.New(2 * time.Second)
	count := 0
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		if count >= 16 {
			return nil
		}
		count++
		path := filepath.Join(root, "pending", file.Name())
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var report discoverymeta.Report
		if len(body) > 1<<20 || json.Unmarshal(body, &report) != nil {
			return fmt.Errorf("invalid local discovery journal")
		}
		req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(server, "/")+"/api/v1/discovery/shadow-it/scan", bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		var ack struct {
			Status, RunID string
			Durable       bool
		}
		var wire struct {
			Status  string `json:"status"`
			RunID   string `json:"run_id"`
			Durable bool   `json:"durable"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&wire)
		resp.Body.Close()
		ack.Status, ack.RunID, ack.Durable = wire.Status, wire.RunID, wire.Durable
		if err != nil || resp.StatusCode != 200 || ack.Status != "acknowledged" || ack.RunID != report.RunID {
			return fmt.Errorf("discovery report not acknowledged")
		}
		if ack.Durable {
			err = os.Remove(path)
		} else {
			dir := filepath.Join(root, "retained")
			if err = os.MkdirAll(dir, 0700); err == nil {
				err = os.Rename(path, filepath.Join(dir, file.Name()))
			}
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *DaemonServer) runDiscoveryWorker(ctx context.Context) {
	root := discoveryRoot()
	_ = replayDiscovery(root)
	// Five minutes plus per-process jitter; retry delivery independently every 5s.
	period := time.NewTicker(5*time.Minute + time.Duration(os.Getpid()%30)*time.Second)
	defer period.Stop()
	retry := time.NewTicker(5 * time.Second)
	defer retry.Stop()
	lastEpoch := int64(-1)
	collect := s.discoveryCollect
	if collect == nil {
		collect = collectDiscovery
	}
	serverEpoch := ""
	scan := true
	epoch := int64(0)
	for {
		if scan {
			report := collect(epoch)
			queueErr := discoverymeta.Queue(root, report)
			s.mu.Lock()
			s.discoveryProgress = map[string]any{"scan_epoch": epoch, "scan_status": report.Status, "completed_at": report.CompletedAt, "delivery_state": "pending"}
			if queueErr != nil {
				s.discoveryProgress["delivery_state"] = "local_queue_failed"
			}
			s.mu.Unlock()
			if queueErr == nil {
				lastEpoch = epoch
			}
			scan = false
		}
		if s.state.ServerURL != "" {
			err := flushDiscovery(ctx, root, s.state.ServerURL)
			s.mu.Lock()
			next := map[string]any{}
			for k, v := range s.discoveryProgress {
				next[k] = v
			}
			if next["delivery_state"] != "local_queue_failed" {
				next["delivery_state"] = "last_pass_acknowledged"
				if err != nil {
					next["delivery_state"] = "retrying"
				}
			}
			s.discoveryProgress = next
			s.mu.Unlock()
		}
		select {
		case <-ctx.Done():
			return
		case epoch = <-s.discoveryRequests:
			scan = epoch > lastEpoch
		case <-period.C:
			scan = true
		case <-retry.C:
			current := httptransport.ControlPlaneEpoch(s.state.ServerURL)
			if current != "" && current != serverEpoch {
				if replayDiscovery(root) == nil {
					serverEpoch = current
				}
				scan = true
			}
		}
	}
}
