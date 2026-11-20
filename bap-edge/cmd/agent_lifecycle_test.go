package cmd

import (
	"testing"
)

func TestAllCodingClientsHaveSharedLifecycleAndIndependentLayerCoverage(t *testing.T) {
	for _, client := range []string{"codex", "agy", "copilot", "opencode"} {
		t.Run(client, func(t *testing.T) {
			spec, ok := governedAgent(client)
			if !ok || spec.Client == "" || len(spec.Executables) == 0 || len(spec.WindowsScripts) == 0 || len(spec.POSIXScripts) == 0 {
				t.Fatal("missing shared lifecycle", spec)
			}
			layers := GetClientDefenseLayers(t.TempDir(), client)
			if len(layers) != 5 || layers[0].Status != "NOT_OBSERVED" {
				t.Fatal("missing hook invented native coverage", layers)
			}
			if layers[1].Status != "READY" {
				t.Fatal("broker depends on native hook", layers[1])
			}
			if layers[4].Status != "NOT_OBSERVED" {
				t.Fatal("configuration invented attestation", layers[4])
			}
		})
	}
}

func TestAnotherClientsInstalledPluginDoesNotProveThisClientsHook(t *testing.T) {
	// A source tree containing all plugin templates does not establish callback
	// invocation for any supported client.
	for _, client := range []string{"claude-code", "codex", "antigravity", "copilot", "opencode"} {
		layers := GetClientDefenseLayers(t.TempDir(), client)
		if layers[0].Status == "ACTIVE" || layers[0].Status == "PARTICIPATED" {
			t.Fatal(client, layers[0])
		}
	}
}
