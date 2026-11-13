package capability

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestEgressMatching(t *testing.T) {
	pats := []string{"github.com", "*.pypi.org", "registry.npmjs.org:443"}
	cases := []struct {
		host, port string
		want       bool
	}{
		{"github.com", "443", true}, {"api.github.com", "443", false}, {"pypi.org", "443", true},
		{"files.pypi.org", "443", true}, {"evilpypi.org", "443", false}, {"registry.npmjs.org", "443", true},
		{"registry.npmjs.org", "80", false}, {"169.254.169.254", "80", false}, {"pastebin.com", "443", false},
	}
	for _, c := range cases {
		if got := MatchEgress(pats, c.host, c.port); got != c.want {
			t.Errorf("%s:%s = %v, want %v", c.host, c.port, got, c.want)
		}
	}
}

func TestImmutableTargetsCanNeverBeAllowed(t *testing.T) {
	p := New(t.TempDir())
	for _, h := range []string{"169.254.169.254", "*.metadata.google.internal", "169.254.1.1", "*"} {
		if _, err := p.AddEgress(h); err == nil {
			t.Errorf("%q must be refused", h)
		}
	}
	if _, err := p.AddEgress("169.254.169.254"); !errors.Is(err, ErrImmutable) {
		t.Errorf("want ErrImmutable, got %v", err)
	}
	if MatchEgress([]string{"169.254.169.254"}, "169.254.169.254", "80") {
		t.Error("metadata must never match even if listed")
	}
}

func TestValidateRefusesCredentialWritesAndSecretEnv(t *testing.T) {
	p := New(t.TempDir())
	p.ExtraWrite = []string{"/home/u/.ssh"}
	if err := p.Validate(); err == nil {
		t.Error("writable .ssh must be refused")
	}
	p = New(t.TempDir())
	p.EnvAllow = append(p.EnvAllow, "AWS_SECRET_ACCESS_KEY")
	if err := p.Validate(); err == nil {
		t.Error("secret env passthrough must be refused")
	}
	if err := New("/").Validate(); err == nil {
		t.Error("filesystem root workspace must be refused")
	}
}

func TestSaveLoadRoundTripAndMissingFileIsSafest(t *testing.T) {
	ws := t.TempDir()
	path := filepath.Join(t.TempDir(), "profile.json")
	p, err := Load(path, ws)
	if err != nil || len(p.EgressAllow) != 0 || p.Workspace != ws {
		t.Fatalf("missing file must give the safest default: %+v %v", p, err)
	}
	p, _ = p.AddEgress("github.com")
	if err := p.Save(path); err != nil {
		t.Fatal(err)
	}
	q, err := Load(path, ws)
	if err != nil || len(q.EgressAllow) != 1 || q.EgressAllow[0] != "github.com" {
		t.Fatalf("round trip: %+v %v", q, err)
	}
}

func TestProvidersRenderWithoutCredentialsOrOpenNetwork(t *testing.T) {
	p := New(t.TempDir())
	p.Image = "golang:1.24"
	p.ProxyAddr = "bap-egress:3128"
	d, err := DockerArgs(p, "bap-internal", []string{"go", "test", "./..."})
	if err != nil {
		t.Fatal(err)
	}
	j := strings.Join(d, " ")
	for _, must := range []string{"--read-only", "--cap-drop=ALL", "--network bap-internal", "HTTPS_PROXY=http://bap-egress:3128", "golang:1.24 go test ./..."} {
		if !strings.Contains(j, must) {
			t.Errorf("docker args missing %q: %s", must, j)
		}
	}
	if strings.Contains(j, ".ssh") || strings.Contains(j, ".aws") || strings.Contains(j, "--network host") {
		t.Errorf("credentials or host network leaked into docker args: %s", j)
	}
	p.Image = ""
	if _, err := DockerArgs(p, "n", nil); err == nil {
		t.Error("docker without an image must fail loudly")
	}

	b, err := BwrapArgs(New(t.TempDir()), []string{"sh"})
	if err != nil || !strings.Contains(strings.Join(b, " "), "--unshare-all") || !strings.Contains(strings.Join(b, " "), "--clearenv") {
		t.Errorf("bwrap must unshare everything and clear env: %v %v", b, err)
	}
	pp := New(t.TempDir())
	pp.ProxyAddr = "unix:/run/user/1000/bap-egress.sock"
	bp, _ := BwrapArgs(pp, []string{"sh"})
	if strings.Contains(strings.Join(bp, " "), "--share-net") || !strings.Contains(strings.Join(bp, " "), "BAP_EGRESS_SOCKET") {
		t.Errorf("even with a proxy the network namespace must stay unshared; only the socket is bound: %v", bp)
	}
	if strings.Contains(strings.Join(b, " "), "--share-net") {
		t.Error("with no proxy the network namespace must stay unshared")
	}

	sb, err := SeatbeltProfile(New(t.TempDir()))
	if err != nil || !strings.Contains(sb, "(deny default)") || !strings.Contains(sb, ".ssh") || strings.Contains(sb, "network-outbound") {
		t.Errorf("seatbelt must default-deny, mask credentials and open no network: %s %v", sb, err)
	}
}
