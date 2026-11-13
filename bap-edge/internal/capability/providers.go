package capability

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Providers render a Profile into the isolation spec of an OS-native mechanism. The kernel (or container
// runtime) enforces it; BAP does not interpret the command. Rendering is pure and unit-tested; actually
// executing under each provider requires that provider installed (docker / bwrap / sandbox-exec).

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.ToSlash(filepath.Join(h, p[2:]))
		}
	}
	return filepath.ToSlash(p)
}

func envPassthrough(p Profile) []string {
	names := append([]string(nil), p.EnvAllow...)
	sort.Strings(names)
	var out []string
	for _, n := range names {
		if !LooksLikeSecretEnv(n) {
			out = append(out, n)
		}
	}
	return out
}

// DockerArgs renders `docker run` arguments. The container has no route out except the egress proxy: the
// caller must attach it to an --internal network that only the proxy sidecar also joins (network is
// returned in the spec so the CLI can create it). Credential locations are simply never mounted.
func DockerArgs(p Profile, network string, argv []string) ([]string, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if p.Image == "" {
		return nil, fmt.Errorf("docker provider needs profile.image")
	}
	ws := filepath.ToSlash(p.Workspace)
	args := []string{"run", "--rm", "-i", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
		"--pids-limit=512", "--memory=4g", "--tmpfs", "/tmp:rw,noexec,nosuid,size=512m",
		"--network", network, "-w", "/workspace", "-v", ws + ":/workspace:rw"}
	for _, ro := range p.ReadOnly {
		args = append(args, "-v", expandHome(ro)+":"+expandHome(ro)+":ro")
	}
	for _, w := range p.ExtraWrite {
		args = append(args, "-v", expandHome(w)+":"+expandHome(w)+":rw")
	}
	if p.ProxyAddr != "" {
		for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
			args = append(args, "-e", k+"=http://"+p.ProxyAddr)
		}
		args = append(args, "-e", "NO_PROXY=")
	}
	for _, e := range envPassthrough(p) {
		args = append(args, "-e", e) // value inherited from the launcher only if set there
	}
	args = append(args, p.Image)
	return append(args, argv...), nil
}

// BwrapArgs renders bubblewrap arguments (Linux). Network namespace is unshared; the sandbox reaches the
// proxy through a unix socket bridge or a host-side forward the CLI provides at ProxyAddr.
func BwrapArgs(p Profile, argv []string) ([]string, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	ws := filepath.ToSlash(p.Workspace)
	args := []string{"--unshare-all", "--die-with-parent", "--new-session",
		"--ro-bind", "/usr", "/usr", "--ro-bind-try", "/lib", "/lib", "--ro-bind-try", "/lib64", "/lib64",
		"--ro-bind-try", "/bin", "/bin", "--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf",
		"--ro-bind-try", "/etc/ssl", "/etc/ssl", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
		"--bind", ws, ws, "--chdir", ws, "--clearenv"}
	for _, ro := range p.ReadOnly {
		args = append(args, "--ro-bind-try", expandHome(ro), expandHome(ro))
	}
	for _, w := range p.ExtraWrite {
		args = append(args, "--bind-try", expandHome(w), expandHome(w))
	}
	// The network namespace is NEVER shared: sharing it would hand the sandbox the whole network and make
	// the proxy advisory. The only way out is a unix socket to the egress proxy ("unix:/path"), bind-mounted
	// in; an in-sandbox forwarder (socat/BAP shim) turns it into HTTP(S)_PROXY. Without one: no network.
	if sock := strings.TrimPrefix(p.ProxyAddr, "unix:"); sock != p.ProxyAddr && sock != "" {
		args = append(args, "--bind", sock, "/run/bap-egress.sock", "--setenv", "BAP_EGRESS_SOCKET", "/run/bap-egress.sock")
		if p.ShimPath != "" { // the BAP binary relays loopback:3128 -> the socket, then execs the command
			args = append(args, "--ro-bind", p.ShimPath, "/bap-shim")
			argv = append([]string{"/bap-shim", "__shim", "--socket", "/run/bap-egress.sock", "--"}, argv...)
		}
	}
	for _, e := range envPassthrough(p) {
		if v, ok := os.LookupEnv(e); ok {
			args = append(args, "--setenv", e, v)
		}
	}
	args = append(args, "--")
	return append(args, argv...), nil
}

// SeatbeltProfile renders a macOS sandbox-exec (SBPL) profile: default deny, workspace write, masked
// credential dirs explicitly denied, network limited to the loopback proxy.
func SeatbeltProfile(p Profile) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("(version 1)\n(deny default)\n(allow process-exec)\n(allow process-fork)\n(allow signal (target self))\n")
	b.WriteString("(allow sysctl-read)\n(allow mach-lookup)\n(allow file-read* (subpath \"/usr\") (subpath \"/bin\") (subpath \"/System\") (subpath \"/Library\") (subpath \"/private/etc\") (subpath \"/dev\"))\n")
	fmt.Fprintf(&b, "(allow file-read* file-write* (subpath %q))\n", filepath.ToSlash(p.Workspace))
	fmt.Fprintf(&b, "(allow file-read* file-write* (subpath \"/private/tmp\") (subpath \"/private/var/folders\"))\n")
	for _, ro := range p.ReadOnly {
		fmt.Fprintf(&b, "(allow file-read* (subpath %q))\n", expandHome(ro))
	}
	for _, w := range p.ExtraWrite {
		fmt.Fprintf(&b, "(allow file-read* file-write* (subpath %q))\n", expandHome(w))
	}
	for _, m := range MaskedPaths { // explicit denies win over any broader allow
		fmt.Fprintf(&b, "(deny file-read* file-write* (subpath %q))\n", expandHome(m))
	}
	if p.ProxyAddr != "" {
		fmt.Fprintf(&b, "(allow network-outbound (remote ip %q))\n", p.ProxyAddr)
	}
	return b.String(), nil
}
