package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGatewayTelemetryUsesScopedCredential(t *testing.T) {
	const key = "synthetic-collector-credential-32-characters"
	t.Setenv("BAP_TELEMETRY_TOKEN", key)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+key {
			t.Error("missing collector proof")
		}
		w.WriteHeader(200)
	}))
	defer server.Close()
	if err := sendPEPTelemetry(server.URL, []byte(`[]`)); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BAP_TELEMETRY_TOKEN", "")
	if err := sendPEPTelemetry(server.URL, []byte(`[]`)); err == nil {
		t.Fatal("anonymous gateway audit was sent")
	}
}
