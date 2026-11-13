//go:build windows

package cmd

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"bap-edge/internal/capability"
	"bap-edge/internal/egress"
	"bap-edge/internal/learn"
)

// TestMain lets this test binary play two roles inside the sandbox: the egress relay shim
// (`__shim`) and a tiny HTTP client (`-bapclient`) that reports what it could reach.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "__shim" {
		sock, rest := "", os.Args[2:]
		if len(rest) >= 2 && rest[0] == "--socket" {
			sock, rest = rest[1], rest[2:]
		}
		if len(rest) > 0 && rest[0] == "--" {
			rest = rest[1:]
		}
		code, _ := egress.RunShim(sock, rest)
		os.Exit(code)
	}
	if len(os.Args) > 3 && os.Args[1] == "-bapclient" {
		var out []string
		// 1. Direct connection, ignoring the proxy: the sandbox has no network of its own.
		if c, err := net.Dial("tcp", os.Args[3]); err == nil {
			c.Close()
			out = append(out, "direct=reachable")
		} else {
			out = append(out, "direct=blocked")
		}
		// 2. Through HTTP_PROXY, which the shim sets: this is the only way out.
		for _, u := range strings.Split(os.Args[4], ",") {
			// Go never proxies loopback destinations by default, so use the proxy from the environment explicitly.
			pu, _ := url.Parse(os.Getenv("HTTP_PROXY"))
			resp, err := (&http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}).Get(u)
			if err != nil {
				out = append(out, "GET "+u+" err")
				continue
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			out = append(out, fmt.Sprintf("GET %s %d %s", u, resp.StatusCode, strings.ReplaceAll(strings.TrimSpace(string(b)), "\n", " ")))
		}
		_ = os.WriteFile(filepath.Join(os.Args[2], "client.txt"), []byte(strings.Join(out, "\n")), 0o600)
		os.Exit(0)
	}
	if d, err := os.MkdirTemp("", "bapstate"); err == nil {
		os.Setenv("BAP_STATE_DIR", d)
	}
	os.Exit(m.Run())
}

func TestBapRunAppContainerEndToEnd(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("origin-ok")) }))
	defer origin.Close()
	oh, _, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	ws := t.TempDir()
	prof, err := capability.New(ws).AddEgress(oh) // allow the origin host only
	if err != nil {
		t.Fatal(err)
	}
	allowPrivateEgressForTest = true
	defer func() { allowPrivateEgressForTest = false }()

	self, _ := os.Executable()
	err = runAppContainer(prof, []string{self, "-bapclient", ws, strings.TrimPrefix(origin.URL, "http://"),
		origin.URL + "/,http://blocked.example/steal"})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	b, rerr := os.ReadFile(filepath.Join(ws, "client.txt"))
	if rerr != nil {
		t.Fatalf("sandboxed client left no result: %v", rerr)
	}
	res := string(b)
	t.Logf("sandboxed process saw:\n%s", res)
	for _, want := range []string{"direct=blocked", "/ 200 origin-ok", "blocked.example/steal 403", "bap egress allow blocked.example"} {
		if !strings.Contains(res, want) {
			t.Errorf("want %q in:\n%s", want, res)
		}
	}
	ev, _ := effectLog().ReadAll()
	var denied bool
	for _, e := range ev {
		denied = denied || (e.Verdict == "deny" && strings.HasPrefix(e.Target, "blocked.example"))
	}
	if !denied {
		t.Errorf("the block must be recorded as an effect event for the learning loop: %+v", ev)
	}
	_ = learn.Event{}
}
