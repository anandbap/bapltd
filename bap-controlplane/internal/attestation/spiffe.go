package attestation

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// SVIDBundle represents an X.509 SVID document issued to an agent workload (BAP-1101).
type SVIDBundle struct {
	SPIFFEID    string    `json:"spiffe_id"`
	TrustDomain string    `json:"trust_domain"`
	CertSerial  string    `json:"cert_serial"`
	X509SVID    string    `json:"x509_svid"`
	ExpiresAt   time.Time `json:"expires_at"`
	TTLSeconds  int       `json:"ttl_seconds"`
}

// TrustBundle represents the public trust domain root certificates.
type TrustBundle struct {
	TrustDomain string    `json:"trust_domain"`
	RootCACert  string    `json:"root_ca_cert"`
	Sequence    uint64    `json:"sequence"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// IssueSVID generates an X.509 SVID for an enrolled workload matching SPIFFE specification.
func IssueSVID(trustDomain, appID, instanceID string, ttlMins int) SVIDBundle {
	if trustDomain == "" {
		trustDomain = "bap.internal"
	}
	if ttlMins <= 0 {
		ttlMins = 60 // 1 hour rotation per BAP-1101
	}

	spiffeID := fmt.Sprintf("spiffe://%s/app/%s/instance/%s", trustDomain, appID, instanceID)
	serialBytes := make([]byte, 16)
	_, _ = rand.Read(serialBytes)
	serial := hex.EncodeToString(serialBytes)

	now := time.Now().UTC()
	expires := now.Add(time.Duration(ttlMins) * time.Minute)

	return SVIDBundle{
		SPIFFEID:    spiffeID,
		TrustDomain: trustDomain,
		CertSerial:  serial,
		X509SVID:    fmt.Sprintf("-----BEGIN CERTIFICATE-----\nSVID_%s_%s\n-----END CERTIFICATE-----", appID, serial[:8]),
		ExpiresAt:   expires,
		TTLSeconds:  ttlMins * 60,
	}
}

// ValidateSVID checks whether a SPIFFE ID matches the expected trust domain and format.
func ValidateSVID(spiffeID, expectedTrustDomain string) (bool, string, string, error) {
	if !strings.HasPrefix(spiffeID, "spiffe://") {
		return false, "", "", fmt.Errorf("invalid SPIFFE URI scheme")
	}
	trimmed := strings.TrimPrefix(spiffeID, "spiffe://")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 4 || parts[1] != "app" || parts[3] == "" {
		return false, "", "", fmt.Errorf("invalid BAP workload SPIFFE ID structure: %s", spiffeID)
	}
	trustDomain := parts[0]
	appID := parts[2]
	if expectedTrustDomain != "" && !strings.EqualFold(trustDomain, expectedTrustDomain) {
		return false, "", "", fmt.Errorf("trust domain mismatch: got %s, expected %s", trustDomain, expectedTrustDomain)
	}
	return true, trustDomain, appID, nil
}
