// Package capability is BAP's enforcement boundary description (ADR-001: enforce effects, not commands).
//
// A Profile says what an agent process can TOUCH: which directories it can write, which it can only read,
// which hosts it can reach, which environment variables it can see. It says nothing about which commands
// the agent may type, so it does not need a parser per shell, language or tool. The profile is rendered
// into an OS-native isolation spec (container, bubblewrap, Seatbelt) that the kernel enforces.
package capability

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Profile is the declarative boundary for one agent run. The zero value is the safest one: workspace
// write, no network, no secrets.
type Profile struct {
	Workspace   string   `json:"workspace"`              // read-write
	ReadOnly    []string `json:"read_only,omitempty"`    // visible, not writable (toolchains, caches)
	ExtraWrite  []string `json:"extra_write,omitempty"`  // human-trusted writable dirs (bap trust)
	EgressAllow []string `json:"egress_allow,omitempty"` // host patterns reachable through the egress proxy
	EnvAllow    []string `json:"env_allow,omitempty"`    // environment variable names passed through
	ProxyAddr   string   `json:"proxy_addr,omitempty"`   // egress proxy the sandbox is pointed at
	Image       string   `json:"image,omitempty"`        // container image (docker provider)
}

// DefaultEnvAllow is the environment an agent gets: enough to build, nothing that looks like a credential.
var DefaultEnvAllow = []string{"PATH", "HOME", "USER", "LANG", "TERM", "TMPDIR", "GOPATH", "GOCACHE", "GOFLAGS", "NODE_ENV"}

// MaskedPaths are never visible inside the sandbox, whatever the profile says. They are masked by
// construction (nothing to parse): the kernel simply does not show them.
var MaskedPaths = []string{"~/.ssh", "~/.aws", "~/.azure", "~/.config/gcloud", "~/.kube", "~/.docker/config.json", "~/.gnupg", "~/.netrc", "~/.npmrc", "~/.git-credentials"}

// ImmutableDenyHosts can never be added to an egress allowlist by anyone or any learning loop: cloud
// metadata endpoints and link-local ranges are the classic credential-theft path.
var ImmutableDenyHosts = []string{"169.254.169.254", "metadata.google.internal", "169.254.170.2", "fd00:ec2::254", "metadata.azure.com"}

// ErrImmutable is returned when a change would open an immutable-deny target.
var ErrImmutable = fmt.Errorf("target is in the immutable deny tier")

// IsImmutableDenyHost reports whether host is never allowed.
func IsImmutableDenyHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimSuffix(h, ".")
	for _, d := range ImmutableDenyHosts {
		if h == d {
			return true
		}
	}
	return strings.HasPrefix(h, "169.254.")
}

// New returns the safest profile for a workspace.
func New(workspace string) Profile {
	return Profile{Workspace: workspace, EnvAllow: append([]string(nil), DefaultEnvAllow...)}
}

// Validate rejects profiles that would defeat the boundary.
func (p Profile) Validate() error {
	if strings.TrimSpace(p.Workspace) == "" {
		return fmt.Errorf("profile has no workspace")
	}
	if isFSRoot(p.Workspace) {
		return fmt.Errorf("workspace %q is a filesystem root", p.Workspace)
	}
	for _, w := range append([]string{p.Workspace}, p.ExtraWrite...) {
		if IsMasked(w) {
			return fmt.Errorf("%q is a credential location and can never be writable: %w", w, ErrImmutable)
		}
	}
	for _, h := range p.EgressAllow {
		if err := ValidateEgressPattern(h); err != nil {
			return err
		}
	}
	for _, e := range p.EnvAllow {
		if LooksLikeSecretEnv(e) {
			return fmt.Errorf("environment variable %q looks like a credential and cannot be passed through", e)
		}
	}
	return nil
}

// ValidateEgressPattern checks one allowlist entry: host or *.host, optional :port, never an immutable
// target, never a bare wildcard.
func ValidateEgressPattern(pat string) error {
	host := strings.ToLower(strings.TrimSpace(pat))
	if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host[i:], "]") {
		host = host[:i]
	}
	if host == "" || host == "*" || host == "*." {
		return fmt.Errorf("egress pattern %q would allow every host", pat)
	}
	if IsImmutableDenyHost(strings.TrimPrefix(host, "*.")) {
		return fmt.Errorf("egress pattern %q: %w", pat, ErrImmutable)
	}
	return nil
}

// MatchEgress reports whether host:port is permitted by the patterns.
func MatchEgress(patterns []string, host string, port string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if IsImmutableDenyHost(host) {
		return false
	}
	for _, raw := range patterns {
		pat := strings.ToLower(strings.TrimSpace(raw))
		pport := ""
		if i := strings.LastIndex(pat, ":"); i > 0 && !strings.Contains(pat[i:], "]") {
			pat, pport = pat[:i], pat[i+1:]
		}
		if pport != "" && port != "" && pport != port {
			continue
		}
		if strings.HasPrefix(pat, "*.") {
			if strings.HasSuffix(host, pat[1:]) && host != pat[2:] || host == pat[2:] {
				return true
			}
			continue
		}
		if host == pat {
			return true
		}
	}
	return false
}

// LooksLikeSecretEnv is a name heuristic used only to REFUSE passing a variable through. It is a safety
// net on an allowlist (default is deny), not a classifier the boundary depends on.
func LooksLikeSecretEnv(name string) bool {
	n := strings.ToUpper(name)
	for _, k := range []string{"SECRET", "TOKEN", "PASSWORD", "PASSWD", "API_KEY", "APIKEY", "ACCESS_KEY", "PRIVATE_KEY", "CREDENTIAL", "AWS_", "AZURE_", "GOOGLE_APPLICATION", "SSH_AUTH"} {
		if strings.Contains(n, k) {
			return true
		}
	}
	return false
}

// IsMasked reports whether a path lies inside a masked credential location.
func IsMasked(p string) bool {
	norm := "/" + strings.ToLower(strings.Trim(strings.ReplaceAll(filepath.ToSlash(p), "\\", "/"), "/"))
	for _, m := range MaskedPaths {
		leaf := strings.ToLower(strings.TrimPrefix(m, "~/"))
		if strings.Contains(norm+"/", "/"+leaf+"/") {
			return true
		}
	}
	base := norm[strings.LastIndex(norm, "/")+1:]
	return base == ".env" || strings.HasPrefix(base, ".env.") || base == "id_rsa" || base == "id_ed25519" || strings.HasSuffix(base, ".pem")
}

func isFSRoot(p string) bool {
	c := filepath.ToSlash(filepath.Clean(p))
	return c == "/" || c == "." || (len(c) == 3 && c[1] == ':' && c[2] == '/') || (len(c) == 2 && c[1] == ':')
}

// AddEgress returns a copy with host added after validation. Used by the learning loop and `egress allow`.
func (p Profile) AddEgress(pat string) (Profile, error) {
	if err := ValidateEgressPattern(pat); err != nil {
		return p, err
	}
	for _, e := range p.EgressAllow {
		if strings.EqualFold(e, pat) {
			return p, nil
		}
	}
	p.EgressAllow = append(append([]string(nil), p.EgressAllow...), strings.ToLower(pat))
	sort.Strings(p.EgressAllow)
	return p, p.Validate()
}

// Load reads a profile JSON file. A missing file yields the safest default for workspace.
func Load(path, workspace string) (Profile, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return New(workspace), nil
	}
	if err != nil {
		return Profile{}, err
	}
	var p Profile
	if err := json.Unmarshal(b, &p); err != nil {
		return Profile{}, fmt.Errorf("profile %s: %w", path, err)
	}
	if p.Workspace == "" {
		p.Workspace = workspace
	}
	if len(p.EnvAllow) == 0 {
		p.EnvAllow = append([]string(nil), DefaultEnvAllow...)
	}
	return p, p.Validate()
}

// Save writes the profile atomically.
func (p Profile) Save(path string) error {
	if err := p.Validate(); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(p, "", "  ")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
