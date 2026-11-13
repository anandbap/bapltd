// Package egress is the network half of BAP's enforcement boundary. The sandbox has no route to the
// internet except this proxy; the proxy decides by DESTINATION, not by which tool or command made the
// request, so curl, pip, a Go binary or a Python one-liner are all treated identically.
package egress

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"bap-edge/internal/capability"
	"bap-edge/internal/learn"
)

// Approver is consulted for a destination that is not allowlisted. It must return quickly: a request that
// cannot be decided in time is denied with guidance, never left hanging (the agent must not spin).
type Approver func(host, port string) bool

// Proxy is an allowlisting forward proxy (HTTP and CONNECT).
type Proxy struct {
	mu           sync.RWMutex
	allow        []string
	Session      string
	Project      string
	Log          *learn.Log
	Approve      Approver // optional live approval
	AllowPrivate bool     // tests only: permit loopback/private destinations
	Dial         func(ctx context.Context, network, addr string) (net.Conn, error)
}

func New(p capability.Profile, log *learn.Log, session string) *Proxy {
	return &Proxy{allow: append([]string(nil), p.EgressAllow...), Log: log, Session: session, Project: p.Workspace,
		Dial: (&net.Dialer{Timeout: 10 * time.Second}).DialContext}
}

// SetAllow swaps the allowlist atomically (a human approved something while the agent runs).
func (p *Proxy) SetAllow(patterns []string) {
	p.mu.Lock()
	p.allow = append([]string(nil), patterns...)
	p.mu.Unlock()
}

func (p *Proxy) allowed(host, port string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return capability.MatchEgress(p.allow, host, port)
}

func (p *Proxy) record(host, port, verdict string, human bool) {
	if p.Log != nil {
		_ = p.Log.Append(learn.Event{Kind: "egress", Mode: "connect", Target: net.JoinHostPort(host, port), Verdict: verdict, Session: p.Session, Project: p.Project, Source: "egress-proxy", Observed: true, HumanApproved: human})
	}
}

// Decide returns (allowed, reason). Reasons are prescriptive: they tell the developer the exact next step.
func (p *Proxy) Decide(host, port string) (bool, string) {
	host = strings.ToLower(strings.Trim(host, "[]"))
	if capability.IsImmutableDenyHost(host) {
		p.record(host, port, "deny", false)
		return false, fmt.Sprintf("BAP egress: %s is a cloud-metadata / link-local address and is never reachable from an agent sandbox.", host)
	}
	if p.allowed(host, port) {
		p.record(host, port, "allow", false)
		return true, ""
	}
	if p.Approve != nil && p.Approve(host, port) {
		p.record(host, port, "allow", true)
		return true, ""
	}
	p.record(host, port, "deny", false)
	return false, fmt.Sprintf("BAP egress: %s:%s is not on this workspace's allowlist. Developer: run `bap egress allow %s` (or `bap learn` to review what the agent has been blocked on). Agent: do not retry; ask the developer.", host, port, host)
}

// guardedDial refuses to connect to a private/loopback/link-local address even if DNS says the allowed
// name points there (DNS-rebinding / SSRF into the developer's network).
func (p *Proxy) guardedDial(ctx context.Context, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if !p.AllowPrivate && (ip.IP.IsLoopback() || ip.IP.IsPrivate() || ip.IP.IsLinkLocalUnicast() || ip.IP.IsLinkLocalMulticast() || ip.IP.IsUnspecified()) {
			return nil, fmt.Errorf("BAP egress: %s resolves to non-public address %s; refused", host, ip.IP)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no address for %s", host)
	}
	return p.Dial(ctx, "tcp", net.JoinHostPort(ips[0].IP.String(), port))
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.serveConnect(w, r)
		return
	}
	p.serveForward(w, r)
}

func splitHostPort(hostport, defPort string) (string, string) {
	if h, pt, err := net.SplitHostPort(hostport); err == nil {
		return h, pt
	}
	return strings.Trim(hostport, "[]"), defPort
}

func (p *Proxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	host, port := splitHostPort(r.Host, "443")
	if ok, why := p.Decide(host, port); !ok {
		http.Error(w, why, http.StatusForbidden)
		return
	}
	up, err := p.guardedDial(r.Context(), net.JoinHostPort(host, port))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		up.Close()
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	c, _, err := hj.Hijack()
	if err != nil {
		up.Close()
		return
	}
	_, _ = c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	go func() { defer up.Close(); defer c.Close(); _, _ = io.Copy(up, c) }()
	go func() { defer up.Close(); defer c.Close(); _, _ = io.Copy(c, up) }()
}

func (p *Proxy) serveForward(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() {
		http.Error(w, "BAP egress is a forward proxy; use it via HTTP_PROXY/HTTPS_PROXY", http.StatusBadRequest)
		return
	}
	host, port := splitHostPort(r.URL.Host, "80")
	if ok, why := p.Decide(host, port); !ok {
		http.Error(w, why, http.StatusForbidden)
		return
	}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) { return p.guardedDial(ctx, addr) }}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.Header.Del("Proxy-Connection")
	resp, err := tr.RoundTrip(out)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}
