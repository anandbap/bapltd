// Package discovery collects bounded metadata without inspecting credentials,
// command arguments, process environments, tool inputs, or tool results.
package discovery

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Scope struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}
type Observation struct {
	Key         string    `json:"key"`
	Scope       string    `json:"scope"`
	Kind        string    `json:"kind"`
	Name        string    `json:"name"`
	Client      string    `json:"client"`
	Evidence    string    `json:"evidence"`
	ObservedAt  time.Time `json:"observed_at"`
	PID         int       `json:"pid,omitempty"`
	Birth       string    `json:"birth,omitempty"`
	OperationID string    `json:"operation_id,omitempty"`
	Outcome     string    `json:"outcome,omitempty"`
}
type Report struct {
	Version      int           `json:"version"`
	RunID        string        `json:"run_id"`
	Epoch        int64         `json:"epoch"`
	StartedAt    time.Time     `json:"started_at"`
	CompletedAt  time.Time     `json:"completed_at"`
	Status       string        `json:"status"`
	Scopes       []Scope       `json:"scopes"`
	Observations []Observation `json:"observations"`
}

func ID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:16])
}
func NewReport(epoch int64) Report {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return Report{Version: 1, RunID: hex.EncodeToString(b), Epoch: epoch, StartedAt: time.Now().UTC(), Status: "complete", Scopes: []Scope{}, Observations: []Observation{}}
}
func Label(s string) string {
	// Only conventional identifier characters leave the workstation. A hash
	// preserves stable identity when a local config uses an unsafe display name.
	if len(s) > 0 && len(s) <= 100 {
		good := true
		for _, r := range s {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-", r)) {
				good = false
				break
			}
		}
		if good && !strings.HasPrefix(s, "eyJ") {
			return s
		}
	}
	return "asset-" + ID(s)[:12]
}

type ConfigSource struct{ Path, Client string }

// Sources are explicit known locations, never recursive home-directory scans.
// Auth-bearing .claude.json, .env and credential stores are deliberately absent.
func Sources(home, workspace string) []ConfigSource {
	out := []ConfigSource{}
	if workspace != "" {
		for _, p := range []struct{ path, client string }{{".mcp.json", "claude-code"}, {".vscode/mcp.json", "vscode"}, {".cursor/mcp.json", "cursor"}, {".claude/mcp.json", "claude-code"}} {
			out = append(out, ConfigSource{filepath.Join(workspace, filepath.FromSlash(p.path)), p.client})
		}
	}
	if home != "" {
		out = append(out, ConfigSource{filepath.Join(home, ".cursor", "mcp.json"), "cursor"}, ConfigSource{filepath.Join(home, ".claude", "mcp.json"), "claude-code"})
	}
	return out
}
func readConfig(source ConfigSource) (map[string]json.RawMessage, error) {
	// Reject symlinks/reparse traversal in every ancestor, not just the final file.
	for p := source.Path; ; p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if err != nil {
			if os.IsNotExist(err) {
				return map[string]json.RawMessage{}, nil
			}
			return nil, err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("linked scope")
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	f, err := os.Open(source.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > 256*1024 {
		return nil, fmt.Errorf("invalid config size or type")
	}
	var root struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
		Servers    map[string]json.RawMessage `json:"servers"`
	}
	reader := bufio.NewReader(io.LimitReader(f, 256*1024+1))
	if prefix, _ := reader.Peek(3); bytes.Equal(prefix, []byte{0xef, 0xbb, 0xbf}) {
		_, _ = reader.Discard(3)
	}
	d := json.NewDecoder(reader)
	if err = d.Decode(&root); err != nil {
		return nil, err
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("trailing config")
	}
	if root.MCPServers == nil {
		root.MCPServers = root.Servers
	}
	return root.MCPServers, nil
}
func Collect(sources []ConfigSource, epoch int64) Report {
	r := NewReport(epoch)
	seen := map[string]bool{}
	for _, src := range sources {
		scope := "config-" + ID(filepath.Clean(src.Path))
		if seen[scope] {
			continue
		}
		seen[scope] = true
		result := Scope{ID: scope, Status: "complete"}
		servers, err := readConfig(src)
		if err != nil {
			result.Status = "error"
			r.Status = "partial"
		} else {
			names := make([]string, 0, len(servers))
			for name := range servers {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				if len(r.Observations) >= 450 {
					result.Status = "error"
					r.Status = "partial"
					break
				}
				var server map[string]json.RawMessage
				if json.Unmarshal(servers[name], &server) != nil {
					result.Status = "error"
					r.Status = "partial"
					continue
				}
				if _, ok := server["command"]; !ok {
					if _, ok := server["url"]; !ok {
						result.Status = "error"
						r.Status = "partial"
						continue
					}
				}
				r.Observations = append(r.Observations, Observation{Key: "mcp-" + ID(src.Path, name), Scope: scope, Kind: "mcp_config", Name: Label(name), Client: Label(src.Client), Evidence: "configured", ObservedAt: time.Now().UTC()})
			}
		}
		r.Scopes = append(r.Scopes, result)
	}
	if len(r.Scopes) == 0 {
		r.Scopes = append(r.Scopes, Scope{ID: "configuration", Status: "unsupported"})
		r.Status = "partial"
	}
	r.CompletedAt = time.Now().UTC()
	return r
}

// Queue uses an atomic, synced rename. A successful non-durable server ACK moves
// reports to retained history rather than deleting the workstation's only copy.
func Queue(root string, r Report) error {
	dir := filepath.Join(root, "pending")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".report-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(body)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, filepath.Join(dir, Label(r.RunID)+".json"))
}
