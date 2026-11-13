package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"bap-edge/internal/authz"
	"bap-edge/internal/config"
	"bap-edge/internal/policystore"
)

func init() {
	authz.ReadExemptProvider = managedReadExempt
	// Policy sync is authenticated with the enrolled workstation credential (OTC or OIDC).
	policystore.CredentialProvider = func() string {
		data, err := os.ReadFile(DefaultCredentialsPath())
		if err != nil {
			return ""
		}
		var creds StoredCredentials
		if json.Unmarshal(data, &creds) != nil {
			return ""
		}
		return creds.SessionToken
	}
}

// pinPolicyEnrollment stores the trust anchor from an authenticated OTC/OIDC enrollment.
// Re-enrolling (e.g. after a control-plane key loss) is the one authenticated way to replace a pin.
func pinPolicyEnrollment(keyID, publicKey, assetID string) {
	if keyID == "" || publicKey == "" {
		return // older control plane: falls back to first-contact pinning at the first sync
	}
	if err := policystore.New(policystore.DefaultPolicyDir()).PinEnrollment(keyID, publicKey, assetID); err != nil {
		fmt.Fprintf(os.Stderr, "[BAP] warning: could not pin the control plane policy key: %v\n", err)
	}
}

// managedReadExempt resolves the control-plane-owned zsp_read_exempt setting from the
// verified signed policy state of this machine.
//
//   - Enrolled machine, state verifies: the signed value (an admin can turn reads back into
//     grant-required for this one asset, or the whole fleet).
//   - Enrolled machine, state tampered / missing / unverifiable: false. Nothing is exempt.
//   - Machine never enrolled with a signing control plane (no signed state): the
//     developer-friendly default (true).
func managedReadExempt() bool {
	store := policystore.New(policystore.DefaultPolicyDir())
	// Short-lived invocations (hooks, `bapedge check`) refresh a stale cache themselves, so an
	// admin change reaches this machine within seconds even with no daemon running. If the
	// control plane is unreachable the last signed rules simply stay in force.
	if store.Managed() {
		store.RefreshIfStale(config.ResolveEndpoints().ControlPlaneURL, policystore.DefaultMaxStaleness, 800*time.Millisecond)
	}
	_, _, st, err := store.Current()
	if err != nil {
		if errors.Is(err, policystore.ErrPolicyTampered) || errors.Is(err, policystore.ErrDigestMismatch) || store.Managed() {
			return false
		}
		return true
	}
	if st.SigAlg == "" {
		return true // unmanaged / legacy cache: no signed setting exists
	}
	return st.ZSPReadExempt
}
