package egress

import (
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
	"bap-edge/internal/learn"
)

// The sandbox's only path out: loopback relay inside -> unix socket -> proxy outside. A client that
// honours HTTP_PROXY goes through policy; there is no other route to test because the sandbox has no
// network namespace (rendered and asserted in the capability tests).
func TestRelayToUnixSocketEnforcesPolicyEndToEnd(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer origin.Close()
	oh, _, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	dir, err := os.MkdirTemp("", "bap")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "e.sock")

	log := learn.NewLog(filepath.Join(dir, "e.jsonl"))
	prof, _ := capability.New(dir).AddEgress(oh)
	p := New(prof, log, "s")
	p.AllowPrivate = true
	stop, err := ServeUnix(p, sock)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	defer stop()

	l, err := Relay("127.0.0.1:0", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	pu, _ := url.Parse("http://" + l.Addr().String())
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}

	resp, err := c.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(b) != "ok" {
		t.Fatalf("allowlisted via relay: %d %q", resp.StatusCode, b)
	}
	resp, err = c.Get("http://blocked.example/x")
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != 403 || !strings.Contains(string(b), "bap egress allow blocked.example") {
		t.Fatalf("blocked via relay: %d %q", resp.StatusCode, b)
	}
	if ev, _ := log.ReadAll(); len(ev) != 2 {
		t.Errorf("both decisions logged: %+v", ev)
	}
}

func TestRunShimRequiresACommand(t *testing.T) {
	if code, err := RunShim("x", nil); err == nil || code == 0 {
		t.Error("shim with no command must fail")
	}
}
