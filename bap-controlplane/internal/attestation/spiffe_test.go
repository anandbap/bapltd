package attestation

import (
	"strings"
	"testing"
	"time"
)

func TestSPIFFESVIDLifecycleAndRotation(t *testing.T) {
	// 1. Issue SVID
	bundle := IssueSVID("bap.internal", "financial-reconciler", "desktop-01", 5)
	if !strings.HasPrefix(bundle.SPIFFEID, "spiffe://bap.internal/app/financial-reconciler/instance/desktop-01") {
		t.Fatalf("unexpected SPIFFE ID: %s", bundle.SPIFFEID)
	}
	if bundle.TTLSeconds != 300 {
		t.Fatalf("expected 300s TTL, got %d", bundle.TTLSeconds)
	}

	// 2. Validate SVID
	valid, domain, appID, err := ValidateSVID(bundle.SPIFFEID, "bap.internal")
	if !valid || err != nil {
		t.Fatalf("expected SVID validation to pass, got valid=%v, err=%v", valid, err)
	}
	if domain != "bap.internal" || appID != "financial-reconciler" {
		t.Fatalf("unexpected domain/appID: %s / %s", domain, appID)
	}

	// 3. Subject Mapping (BAP-703)
	subject, err := SVIDToAuthSubject(bundle.SPIFFEID)
	if err != nil {
		t.Fatalf("failed to map SVID to auth subject: %v", err)
	}
	if subject != "workload:bap.internal:financial-reconciler:desktop-01" {
		t.Fatalf("unexpected subject mapping: %s", subject)
	}

	// 4. Rotation (BAP-703)
	rotated, err := RotateSVID(bundle, 300)
	if err != nil {
		t.Fatalf("failed to rotate SVID: %v", err)
	}
	if rotated.CertSerial == bundle.CertSerial {
		t.Fatalf("expected new cert serial upon rotation, got identical: %s", rotated.CertSerial)
	}
	if rotated.SPIFFEID != bundle.SPIFFEID {
		t.Fatalf("expected SPIFFE ID to persist across rotation, got %s", rotated.SPIFFEID)
	}

	// 5. Expiration check
	if IsSVIDExpired(rotated) {
		t.Fatalf("freshly rotated SVID should not be expired")
	}
	expiredBundle := bundle
	expiredBundle.ExpiresAt = time.Now().UTC().Add(-10 * time.Minute)
	if !IsSVIDExpired(expiredBundle) {
		t.Fatalf("expected expired bundle to return true for IsSVIDExpired")
	}
}
