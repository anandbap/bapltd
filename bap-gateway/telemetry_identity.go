package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"bap-gateway/internal/httptransport"
)

func sendPEPTelemetry(server string, data []byte) error {
	token := os.Getenv("BAP_TELEMETRY_TOKEN")
	if len(token) < 32 {
		return fmt.Errorf("gateway telemetry identity is not configured; retained locally")
	}
	origin, err := url.Parse(server)
	if err != nil {
		return err
	}
	local := origin.Hostname() == "localhost" || origin.Hostname() == "127.0.0.1" || origin.Hostname() == "::1"
	if !local && (origin.Scheme != "https" || os.Getenv("BAP_INSECURE_SKIP_VERIFY") == "1") {
		return fmt.Errorf("gateway telemetry requires verified HTTPS")
	}
	client := httptransport.New(2 * time.Second)
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != origin.Scheme || req.URL.Host != origin.Host {
			req.Header.Del("Authorization")
			return fmt.Errorf("authenticated cross-origin redirect refused")
		}
		if len(via) >= 10 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	}
	req, err := http.NewRequest("POST", strings.TrimRight(server, "/")+"/api/v1/audit/ingest", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != 200 {
		return fmt.Errorf("gateway telemetry refused (HTTP %d)", resp.StatusCode)
	}
	return nil
}
