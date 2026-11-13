package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"bap-edge/internal/appcontainer"
	"bap-edge/internal/capability"
	"bap-edge/internal/egress"
)

// runAppContainer is the Windows provider: no admin, no Docker, no WSL. The command runs in an
// AppContainer that can see only the workspace (plus the tool binaries it needs), has no network, and
// reaches the world only through the BAP egress proxy over a unix socket (relay shim inside).
func runAppContainer(p capability.Profile, argv []string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(p.Workspace))))
	name := "bap.ws." + hex.EncodeToString(sum[:6])

	runDir := filepath.Join(os.TempDir(), fmt.Sprintf("bap-run-%d", os.Getpid()))
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return err
	}
	defer os.RemoveAll(runDir)
	sock := filepath.Join(runDir, "egress.sock")
	px := egress.New(p, effectLog(), "run")
	px.AllowPrivate = allowPrivateEgressForTest
	stop, err := egress.ServeUnix(px, sock)
	if err != nil {
		return fmt.Errorf("egress proxy: %w", err)
	}
	defer stop()

	readable := []string{self}
	if exe, lerr := exec.LookPath(argv[0]); lerr == nil {
		readable = append(readable, filepath.Dir(exe))
	}
	for _, r := range p.ReadOnly {
		readable = append(readable, expandHomeLocal(r))
	}
	env := []string{"TEMP=" + p.Workspace, "TMP=" + p.Workspace}
	for _, n := range capability.EnvPassthrough(p) {
		if v, ok := os.LookupEnv(n); ok && v != "" {
			env = append(env, n+"="+v)
		}
	}
	code, err := appcontainer.Run(appcontainer.Options{
		Name: name, Dir: p.Workspace, Env: env,
		Argv:     append([]string{self, "__shim", "--socket", sock, "--"}, argv...),
		Writable: []string{p.Workspace, runDir}, // workspace + the proxy socket dir only
		Readable: readable,
	})
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("sandboxed command exited with status %d", code)
	}
	return nil
}

// allowPrivateEgressForTest lets the end-to-end test use a loopback origin; never set in production.
var allowPrivateEgressForTest bool

func expandHomeLocal(p string) string {
	if strings.HasPrefix(p, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, p[2:])
		}
	}
	return p
}
