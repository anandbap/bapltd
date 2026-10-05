package dashboardui

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

//go:embed web
var assets embed.FS

// AssetsFS returns the embedded web assets filesystem.
func AssetsFS() fs.FS {
	web, _ := fs.Sub(assets, "web")
	return web
}

// Handler serves the dashboard and forwards API requests over the transport
// configured by the dashboard process. The browser never connects directly to
// the control plane, keeping TLS trust and optional client authentication in
// the server-to-server hop.
func Handler(controlPlane *url.URL, transport http.RoundTripper, allowRemoteAdmin bool) http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(controlPlane)
	proxy.Transport = transport
	originalDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		originalDirector(r)
		r.Host = controlPlane.Host
		if r.Header.Get("Origin") != "" {
			r.Header.Set("Origin", controlPlane.Scheme+"://"+controlPlane.Host)
		}
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "control plane unavailable", http.StatusBadGateway)
	}

	web, _ := fs.Sub(assets, "web")
	files := http.StripPrefix("/dashboard/", http.FileServer(http.FS(web)))
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/dashboard/", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard/", http.StatusTemporaryRedirect)
	})
	mux.Handle("/dashboard/", files)

	// BAP-210: Consolidate the CIO Cockpit - redirect legacy inspector routes
	redirectCockpit := func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard/", http.StatusFound)
	}
	mux.HandleFunc("/inspector", redirectCockpit)
	mux.HandleFunc("/inspector.html", redirectCockpit)
	mux.HandleFunc("/inspector_v2", redirectCockpit)
	mux.HandleFunc("/inspector_v2.html", redirectCockpit)
	mux.HandleFunc("/dashboard-config", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"control_plane_url": controlPlane.String()})
	})
	mux.Handle("/api/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowRemoteAdmin && isAdminPath(r.URL.Path) && !isLoopback(r.RemoteAddr) {
			http.Error(w, "remote administrative dashboard access is disabled", http.StatusForbidden)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	mux.HandleFunc("/dashboard-health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","service":"bapdashboard"}`))
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		if strings.HasPrefix(r.URL.Path, "/inspector") {
			w.Header().Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://www.gstatic.com; style-src 'self' 'unsafe-inline'; connect-src 'self' *; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		} else {
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; connect-src 'self' *; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		}
		mux.ServeHTTP(w, r)
	})
}

func isAdminPath(path string) bool {
	return strings.HasPrefix(path, "/api/v1/control/") ||
		strings.HasPrefix(path, "/api/v1/admin/") ||
		path == "/api/v1/sessions/reset" ||
		path == "/api/v1/sessions/revoke" ||
		path == "/api/v1/agents/pre-register" ||
		path == "/api/v1/agents/revoke" ||
		path == "/api/v1/apps/revoke" ||
		strings.HasPrefix(path, "/api/v1/demo/")
}

func isLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}
