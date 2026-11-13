//go:build windows

package appcontainer

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMain doubles as the in-container helper: the test binary re-launches itself inside the AppContainer
// and records what the contained process could and could not do.
func TestMain(m *testing.M) {
	if len(os.Args) >= 6 && os.Args[1] == "-bapac" {
		ws := os.Args[2]
		os.Setenv("BAP_AC_OUTSIDE", os.Args[3])
		os.Setenv("BAP_AC_TCP", os.Args[4])
		os.Setenv("BAP_AC_UNIX", os.Args[5])
		var out []string
		if err := os.WriteFile(filepath.Join(ws, "wrote.txt"), []byte("x"), 0o600); err == nil {
			out = append(out, "ws_write=ok")
		} else {
			out = append(out, "ws_write="+err.Error())
		}
		if _, err := os.ReadFile(os.Getenv("BAP_AC_OUTSIDE")); err == nil {
			out = append(out, "outside_read=ok")
		} else {
			out = append(out, "outside_read=denied")
		}
		if c, err := net.Dial("tcp", os.Getenv("BAP_AC_TCP")); err == nil {
			c.Close()
			out = append(out, "tcp=ok")
		} else {
			out = append(out, "tcp=denied")
		}
		if c, err := net.Dial("unix", os.Getenv("BAP_AC_UNIX")); err == nil {
			c.Close()
			out = append(out, "unix=ok")
		} else {
			out = append(out, "unix=denied:"+err.Error())
		}
		if ln, err := net.Listen("tcp", "127.0.0.1:0"); err != nil {
			out = append(out, "loopback_listen=denied")
		} else {
			if c, err := net.Dial("tcp", ln.Addr().String()); err == nil {
				c.Close()
				out = append(out, "loopback_self=ok")
			} else {
				out = append(out, "loopback_self=denied")
			}
			ln.Close()
		}
		_ = os.WriteFile(filepath.Join(ws, "result.txt"), []byte(strings.Join(out, "\n")), 0o600)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestAppContainerBoundaryWithoutAdmin(t *testing.T) {
	base := t.TempDir()
	ws := filepath.Join(base, "ws")
	secretDir := filepath.Join(base, "secret")
	for _, d := range []string{ws, secretDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	secret := filepath.Join(secretDir, "creds.txt")
	_ = os.WriteFile(secret, []byte("hunter2"), 0o600)

	// A host-side TCP listener the contained process must NOT be able to reach.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	// A host-side unix socket inside the granted workspace: the deliberate way out (the egress proxy).
	sock := filepath.Join(ws, "egress.sock")
	ul, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	defer ul.Close()
	go func() {
		for {
			c, err := ul.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	exe, _ := os.Executable()
	code, err := Run(Options{Name: "bap.test.boundary", Argv: []string{exe, "-bapac", ws, secret, l.Addr().String(), sock}, Dir: ws, Env: []string{"SystemRoot=" + os.Getenv("SystemRoot"), "TEMP=" + ws, "TMP=" + ws},
		Writable: []string{ws}, Readable: []string{exe}})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	b, rerr := os.ReadFile(filepath.Join(ws, "result.txt"))
	if rerr != nil {
		t.Fatalf("contained process left no result (exit %d): %v", code, rerr)
	}
	res := string(b)
	t.Logf("contained process saw:\n%s", res)
	for _, want := range []string{"ws_write=ok", "outside_read=denied", "tcp=denied", "unix=ok", "loopback_self=ok"} {
		if !strings.Contains(res, want) {
			t.Errorf("want %q in:\n%s", want, res)
		}
	}
}
