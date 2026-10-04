package httptransport

import (
	"crypto/tls"
	"crypto/x509"
	"embed"
	"net/http"
	"os"
	"sync"
	"time"
)

//go:embed certs
var certsFS embed.FS

// New shares the BAP_CA_CERT trust setting across every request in a process.
// It loads optional embedded certificates, system certificates, environment PEM secrets, and runtime paths.
func New(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: &caTransport{}}
}

type caTransport struct {
	once      sync.Once
	transport *http.Transport
	err       error
}

func (t *caTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.once.Do(func() {
		t.transport = http.DefaultTransport.(*http.Transport).Clone()

		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}

		// 1. Append optional compiled-in Root CA if provided in private build (certs/embedded_ca.crt)
		if caData, err := certsFS.ReadFile("certs/embedded_ca.crt"); err == nil && len(caData) > 0 {
			roots.AppendCertsFromPEM(caData)
		}

		// 2. Append CA certificate from raw environment secret string (e.g. GitHub Secret / Vault / Intune)
		if pemStr := os.Getenv("BAP_CA_CERT_PEM"); pemStr != "" {
			roots.AppendCertsFromPEM([]byte(pemStr))
		}

		// 2. Also check runtime BAP_CA_CERT or local files if provided
		path := os.Getenv("BAP_CA_CERT")
		if path == "" {
			for _, cand := range []string{"bap-root-ca.crt", "controlplane-cert.pem", "../bap-root-ca.crt", "../controlplane-cert.pem", "../../controlplane-cert.pem"} {
				if _, err := os.Stat(cand); err == nil {
					path = cand
					break
				}
			}
		}
		if path != "" {
			if pem, err := os.ReadFile(path); err == nil {
				roots.AppendCertsFromPEM(pem)
			}
		}

		t.transport.TLSClientConfig = &tls.Config{
			RootCAs:    roots,
			MinVersion: tls.VersionTLS12,
		}
	})
	if t.err != nil {
		return nil, t.err
	}
	return t.transport.RoundTrip(r)
}
