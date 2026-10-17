package api

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"

	"bap-controlplane/internal/dashboardui"
)

func (s *Server) registerControlPlaneRoutes() {
	// BAP-210 & Agent Watch V2: Mount Mission Control, Trust Command & Capability Atlas
	webFS := dashboardui.AssetsFS()
	files := http.StripPrefix("/dashboard/", http.FileServer(http.FS(webFS)))

	setAuthCookie := func(w http.ResponseWriter, r *http.Request) {
		if isLoopbackAddress(r.RemoteAddr) && s.adminToken != "" {
			http.SetCookie(w, &http.Cookie{
				Name:     "bap_admin_token",
				Value:    s.adminToken,
				Path:     "/",
				SameSite: http.SameSiteLaxMode,
				HttpOnly: false,
			})
		}
	}

	serveV2 := func(w http.ResponseWriter, r *http.Request) {
		setAuthCookie(w, r)
		v2Data, err := fs.ReadFile(webFS, "v2.html")
		if err != nil {
			http.Error(w, "v2 asset unavailable", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(v2Data)
	}

	serveV1 := func(w http.ResponseWriter, r *http.Request) {
		setAuthCookie(w, r)
		v1Data, err := fs.ReadFile(webFS, "index.html")
		if err != nil {
			http.Error(w, "legacy asset unavailable", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(v1Data)
	}

	s.mux.HandleFunc("/dashboard/v2", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard/v2/", http.StatusTemporaryRedirect)
	})
	s.mux.HandleFunc("/dashboard/v2/", func(w http.ResponseWriter, r *http.Request) {
		serveV2(w, r)
	})
	s.mux.HandleFunc("/dashboard/legacy", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard/?v=legacy", http.StatusTemporaryRedirect)
	})
	s.mux.HandleFunc("/dashboard/legacy/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard/?v=legacy", http.StatusTemporaryRedirect)
	})

	s.mux.HandleFunc("/dashboard/", func(w http.ResponseWriter, r *http.Request) {
		setAuthCookie(w, r)
		if r.URL.Path == "/dashboard/" {
			if r.URL.Query().Get("v") == "legacy" || r.URL.Query().Get("v") == "v1" {
				serveV1(w, r)
			} else {
				serveV2(w, r)
			}
			return
		}
		files.ServeHTTP(w, r)
	})
	s.mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard/", http.StatusFound)
	})

	s.mux.HandleFunc("/dashboard-config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		mode := "production"
		if s.demoMode {
			mode = "demo"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"control_plane_url": fmt.Sprintf("%s://%s", scheme, r.Host),
			"environment":       mode,
			"demo_mode":         s.demoMode,
		})
	})

	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if strings.Contains(r.Header.Get("Accept"), "text/html") {
			http.Redirect(w, r, "/dashboard/", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"service":      "bapcontrolplane",
			"status":       "ok",
			"dashboard":    "/dashboard/",
			"inspector":    "/dashboard/",
			"inspector_v2": "/dashboard/",
		})
	})

	// BAP-210: Consolidate the CIO Cockpit - redirect legacy inspector routes
	redirectCockpit := func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard/", http.StatusFound)
	}
	s.mux.HandleFunc("/inspector", redirectCockpit)
	s.mux.HandleFunc("/inspector.html", redirectCockpit)
	s.mux.HandleFunc("/inspector_v2", redirectCockpit)
	s.mux.HandleFunc("/inspector_v2.html", redirectCockpit)

	s.mux.HandleFunc("/assets/admin-client.js", func(w http.ResponseWriter, r *http.Request) {
		candidates := []string{
			"internal/api/web/admin-client.js",
			"bap-controlplane/internal/api/web/admin-client.js",
			"../internal/api/web/admin-client.js",
			"../bap-controlplane/internal/api/web/admin-client.js",
		}
		for _, c := range candidates {
			if data, err := os.ReadFile(c); err == nil {
				w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(data)
				return
			}
		}
		http.NotFound(w, r)
	})
}

func (s *Server) handleInspectorHTML(filename string, title string) http.HandlerFunc {
	candidates := []string{
		filename,
		"../" + filename,
		"../../" + filename,
		"bap-controlplane/" + filename,
		"../bap-controlplane/" + filename,
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		for _, candidate := range candidates {
			if data, err := os.ReadFile(candidate); err == nil {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				if r.Method != http.MethodHead {
					if isLoopbackAddress(r.RemoteAddr) && s.adminToken != "" {
						html := string(data)
						tokenMeta := `<meta name="bap-admin-token" content="` + s.adminToken + `">` + "\n</head>"
						html = strings.Replace(html, "</head>", tokenMeta, 1)
						_, _ = w.Write([]byte(html))
					} else {
						_, _ = w.Write(data)
					}
				}
				return
			}
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><title>` + title + `</title></head><body style="font-family:sans-serif;background:#0f172a;color:#fff;padding:2rem;"><h2>` + title + `</h2><p>File <code>` + filename + `</code> was not found in working directories.</p></body></html>`))
	}
}
