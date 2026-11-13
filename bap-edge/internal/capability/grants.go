package capability

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"bap-edge/pkg/types"
)

type FilesystemCapability struct {
	Path string `json:"path"`
	Mode string `json:"mode"` // read | write | delete
}
type NetworkCapability struct {
	Host string `json:"host"`
	Port string `json:"port"`
}

// Set is the effect-level representation of one already verified TaskGrant.
// Conversion does not authenticate a grant, consume a use, or install authority.
type Set struct {
	GrantID     string                 `json:"grant_id"`
	Session     string                 `json:"session"`
	Filesystem  []FilesystemCapability `json:"filesystem,omitempty"`
	Network     []NetworkCapability    `json:"network,omitempty"`
	Processes   []string               `json:"processes,omitempty"`
	Environment []string               `json:"environment,omitempty"`
	ExpiresAt   time.Time              `json:"expires_at"`
}

// FromTaskGrant fails closed for command grants whose effects cannot be
// represented. A CLI permission is never silently turned into filesystem rw or
// network access. Requested scopes are ignored: only granted scopes count.
func FromTaskGrant(g types.TaskGrant, workspace string, now time.Time) (Set, error) {
	var out Set
	if g.GrantID == "" || g.SessionID == "" || g.IsBurned || g.RemainingUses <= 0 || !g.ExpiresAt.After(now) || g.IssuedAt.After(now) {
		return out, fmt.Errorf("grant must be identified, active, unburned and unexpired")
	}
	ws, err := filepath.Abs(workspace)
	if err != nil || strings.TrimSpace(workspace) == "" || isFSRoot(ws) || IsMasked(ws) {
		return out, fmt.Errorf("invalid workspace")
	}
	out = Set{GrantID: g.GrantID, Session: g.SessionID, ExpiresAt: g.ExpiresAt}
	if len(g.AllowedActions) == 0 || len(g.AllowedResources) == 0 {
		return Set{}, fmt.Errorf("empty capability scope")
	}
	seen := map[string]bool{}
	for _, action := range g.AllowedActions {
		mode := ""
		switch action {
		case "fs:read":
			mode = "read"
		case "fs:write":
			mode = "write"
		case "fs:delete":
			mode = "delete"
		case "net:connect":
		default:
			return Set{}, fmt.Errorf("action %q has no lossless capability mapping", action)
		}
		for _, resource := range g.AllowedResources {
			if mode != "" {
				path := ""
				if resource == "workspace://current" {
					path = ws
				} else if strings.HasPrefix(resource, "file://") {
					raw := strings.TrimPrefix(resource, "file://")
					decoded, e := url.PathUnescape(raw)
					if e != nil {
						return Set{}, e
					}
					if !filepath.IsAbs(decoded) {
						return Set{}, fmt.Errorf("file resource must be absolute")
					}
					path = filepath.Clean(decoded)
				} else {
					return Set{}, fmt.Errorf("resource %q cannot be mapped to %s", resource, action)
				}
				if isFSRoot(path) || IsMasked(path) || strings.ContainsAny(path, "*?") {
					return Set{}, fmt.Errorf("unsafe filesystem capability %q", path)
				}
				key := mode + "\x00" + path
				if !seen[key] {
					seen[key] = true
					out.Filesystem = append(out.Filesystem, FilesystemCapability{path, mode})
				}
			} else {
				if !strings.HasPrefix(resource, "https://") && !strings.HasPrefix(resource, "http://") {
					return Set{}, fmt.Errorf("network capability requires an explicit HTTP(S) destination")
				}
				u, e := url.Parse(resource)
				if e != nil || u.User != nil || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
					return Set{}, fmt.Errorf("invalid host capability %q", resource)
				}
				host := strings.ToLower(u.Hostname())
				port := u.Port()
				if port == "" {
					if u.Scheme == "https" {
						port = "443"
					} else {
						port = "80"
					}
				}
				if e := ValidateEgressPattern(host + ":" + port); e != nil {
					return Set{}, e
				}
				if net.ParseIP(host) != nil || strings.ContainsAny(host, "*/\\") {
					return Set{}, fmt.Errorf("network capability requires an exact DNS host")
				}
				key := host + ":" + port
				if !seen[key] {
					seen[key] = true
					out.Network = append(out.Network, NetworkCapability{host, port})
				}
			}
		}
	}
	sort.Slice(out.Filesystem, func(i, j int) bool {
		if out.Filesystem[i].Path != out.Filesystem[j].Path {
			return out.Filesystem[i].Path < out.Filesystem[j].Path
		}
		return out.Filesystem[i].Mode < out.Filesystem[j].Mode
	})
	sort.Slice(out.Network, func(i, j int) bool {
		return out.Network[i].Host+":"+out.Network[i].Port < out.Network[j].Host+":"+out.Network[j].Port
	})
	return out, nil
}
