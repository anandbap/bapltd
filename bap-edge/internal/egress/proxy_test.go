package egress

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"bap-edge/internal/capability"
	"bap-edge/internal/learn"
)

func proxiedClient(t *testing.T, p *Proxy) *http.Client {
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}}
}

func TestAllowlistedDestinationPassesAndOthersAreBlockedWithGuidance(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("hello")) }))
	defer origin.Close()
	oh, op, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	log := learn.NewLog(filepath.Join(t.TempDir(), "e.jsonl"))
	prof, _ := capability.New(t.TempDir()).AddEgress(oh + ":" + op)
	p := New(prof, log, "sess1")
	p.AllowPrivate = true // the test origin is on loopback
	c := proxiedClient(t, p)

	resp, err := c.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(b) != "hello" {
		t.Fatalf("allowlisted request must pass: %d %q", resp.StatusCode, b)
	}

	resp, err = c.Get("http://pastebin.example/exfil")
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(b), "bap egress allow pastebin.example") {
		t.Fatalf("blocked request must be 403 with the exact next step: %d %q", resp.StatusCode, b)
	}

	ev, _ := log.ReadAll()
	var allow, deny int
	for _, e := range ev {
		if e.Verdict == "allow" {
			allow++
		} else if e.Verdict == "deny" && strings.HasPrefix(e.Target, "pastebin.example") {
			deny++
		}
	}
	if allow != 1 || deny != 1 {
		t.Errorf("every decision must be recorded as an effect event: %+v", ev)
	}
}

func TestMetadataEndpointIsBlockedEvenIfSomeoneAllowlistsIt(t *testing.T) {
	p := New(capability.Profile{Workspace: "w", EgressAllow: []string{"169.254.169.254"}}, nil, "s")
	if ok, why := p.Decide("169.254.169.254", "80"); ok || !strings.Contains(why, "never reachable") {
		t.Errorf("metadata must be immutable-denied: %v %q", ok, why)
	}
}

func TestPrivateAddressRefusedAtDialTime(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer origin.Close()
	oh, op, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))
	prof, _ := capability.New(t.TempDir()).AddEgress(oh)
	_ = op
	p := New(prof, nil, "s") // AllowPrivate=false: an allowlisted name resolving to loopback is SSRF
	resp, err := proxiedClient(t, p).Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(string(b), "non-public") {
		t.Fatalf("private destination must be refused: %d %q", resp.StatusCode, b)
	}
}

func TestLiveApprovalAllowsOnceAndIsRecordedAsHumanEvidence(t *testing.T) {
	log := learn.NewLog(filepath.Join(t.TempDir(), "e.jsonl"))
	p := New(capability.New(t.TempDir()), log, "s")
	p.Approve = func(host, _ string) bool { return host == "api.example.com" }
	if ok, _ := p.Decide("api.example.com", "443"); !ok {
		t.Fatal("approved host must be allowed")
	}
	if ok, _ := p.Decide("other.example.com", "443"); ok {
		t.Fatal("unapproved host must stay blocked")
	}
	ev, _ := log.ReadAll()
	if len(ev) != 2 || !ev[0].HumanApproved || ev[1].HumanApproved {
		t.Errorf("human approval must be recorded as evidence: %+v", ev)
	}
}

func TestSetAllowTakesEffectWithoutRestart(t *testing.T) {
	p := New(capability.New(t.TempDir()), nil, "s")
	if ok, _ := p.Decide("crates.io", "443"); ok {
		t.Fatal("blocked first")
	}
	p.SetAllow([]string{"crates.io"})
	if ok, _ := p.Decide("crates.io", "443"); !ok {
		t.Fatal("allowed after human approval")
	}
}
