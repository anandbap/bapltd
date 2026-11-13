package policystore

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
)

// ResolveAssetID returns the stable identity of the underlying machine, the unit that policy
// is scoped to. It is derived from the OS machine identifier (Windows MachineGuid,
// /etc/machine-id, macOS IOPlatformUUID), NOT from environment variables, usernames or the
// registered agent, so re-registering a client or changing USERNAME cannot move a machine
// out of the rules that apply to it.
//
// BAP_ASSET_ID overrides the value for tests and containers without a machine id.
func ResolveAssetID() string {
	if v := strings.TrimSpace(os.Getenv("BAP_ASSET_ID")); v != "" {
		return v
	}
	id := machineID()
	if id == "" {
		host, _ := os.Hostname()
		id = "hostname:" + strings.ToLower(host)
	}
	sum := sha256.Sum256([]byte("bap-asset-v1:" + strings.ToLower(strings.TrimSpace(id))))
	return "asset-" + hex.EncodeToString(sum[:8])
}
