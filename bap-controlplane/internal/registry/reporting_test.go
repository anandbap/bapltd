package registry

import (
	"bap-controlplane/pkg/types"
	"testing"
	"time"
)

func TestAdministrativeCleanupDoesNotInventCheckins(t *testing.T) {
	for _, action := range []string{"end", "purge", "reset"} {
		t.Run(action, func(t *testing.T) {
			s := NewStore("test")
			a, _ := s.PreRegister(types.PreRegisterRequest{AppID: "bap-workstation", OwnerEmail: "person@example.test"})
			s.Enroll(a.AgentID, "hash", "", "host", "windows", "amd64", "station")
			old := time.Now().Add(-time.Hour)
			s.mu.Lock()
			s.agents[a.AgentID].LastHeartbeatAt = &old
			s.mu.Unlock()
			switch action {
			case "end":
				s.EndSessionAgent("bap-workstation", "station")
			case "purge":
				s.PurgeStale(time.Minute)
			case "reset":
				s.Reset()
			}
			checks := s.ReportingCheckins([]string{"station"})
			if len(checks["station"]) != 1 || !checks["station"][0].At.Equal(old) || checks["station"][0].Active {
				t.Fatal(checks)
			}
		})
	}
}
