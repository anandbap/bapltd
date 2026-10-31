package api

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
)

// A gateway collector identity is scoped to ingestion, never session lifecycle
// or execution. Provision and rotate it through the deployment secret manager.
func (s *Server) SetTelemetrySecurity(token string) error {
	if token != "" && len(token) < 32 {
		return fmt.Errorf("BAP_TELEMETRY_TOKEN must contain at least 32 characters")
	}
	s.telemetryToken = token
	return nil
}
func (s *Server) isTelemetryCaller(r *http.Request) bool {
	return s.telemetryToken != "" && strings.HasPrefix(r.Header.Get("Authorization"),"Bearer ") && subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")), []byte(s.telemetryToken)) == 1
}
