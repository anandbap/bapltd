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
	authz.ApprovedEffectsProvider = managedApprovedEffects
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
//
// token is the credential this enrollment just received. It is used explicitly for the first sync
// because credentials may have been saved somewhere other than the default path (`--config`).
func pinPolicyEnrollment(keyID, publicKey, assetID, serverURL, token string) {
	if keyID == "" || publicKey == "" {
		return // older control plane: falls back to first-contact pinning at the first sync
	}
	store := policystore.New(policystore.DefaultPolicyDir())
	prev, hadPrev := store.LoadPin()
	if err := store.PinEnrollment(keyID, publicKey, assetID, serverURL); err != nil {
		fmt.Fprintf(os.Stderr, "[BAP] warning: could not pin the control plane policy key: %v\n", err)
		return
	}
	// Pinning makes this a managed machine, which only trusts signed rules, so the signed rules must
	// arrive in the same step. If they cannot (control plane unreachable, wrong asset, rejected
	// bundle) the pin is undone: a machine pinned without signed rules fails closed on everything,
	// which is a worse outcome than staying as it was and retrying at the next sync.
	store.SetAuthToken(token)
	if _, _, err := store.SyncWithServer(serverURL, "", 8*time.Second); err != nil {
		if hadPrev {
			_ = store.RestorePin(prev)
		} else {
			store.RemovePin()
		}
		fmt.Fprintf(os.Stderr, "[BAP] warning: enrolled, but the first signed policy sync failed (%v); policy pinning will be retried at the next sync\n", err)
	}
}

// managedApprovedEffects returns the effects an administrator approved for this machine, only from
// a verified, signed state of an enrolled machine. Anything else (unenrolled, tampered, unverifiable,
// no approvals) means nothing is approved, so this can only ever narrow friction, never widen trust.
func managedApprovedEffects() []string {
	store := policystore.New(policystore.DefaultPolicyDir())
	if !store.Managed() {
		return nil
	}
	// Same freshness rule as the read exemption: an approval reaches this machine within seconds.
	store.RefreshIfStale(config.ResolveEndpoints().ControlPlaneURL, policystore.DefaultMaxStaleness, 800*time.Millisecond)
	_, _, st, err := store.Current()
	if err != nil || st.SigAlg == "" {
		return nil
	}
	return st.ApprovedEffects
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
