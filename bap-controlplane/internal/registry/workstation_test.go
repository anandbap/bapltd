package registry

import (
	"sync"
	"testing"
	"time"

	"bap-controlplane/pkg/types"
)

func workstationFixture() types.RegisteredAgent {
	return types.RegisteredAgent{
		AppID: "workstation-laptop", Hostname: "dev-laptop",
		UserEmail: "alice@example.test", EnrolledBinaryHash: "release-one",
		PermittedScopes: []string{"cli:exec"}, Groups: []string{"developers"},
	}
}

func TestWorkstationReloginPreservesIdentityAndRefreshesMetadata(t *testing.T) {
	s := NewStore("test")
	req := workstationFixture()
	first, err := s.EnrollWorkstation(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Deregister(first.AgentID); err != nil {
		t.Fatal(err)
	}
	req.EnrolledBinaryHash = "release-two"
	req.AppID = "workstation-desktop"
	req.DeviceType = "desktop"
	req.UserEmail = "ALICE@example.test"
	req.Hostname = "DEV-LAPTOP"
	req.Groups = []string{"engineering"}
	second, err := s.EnrollWorkstation(req)
	if err != nil {
		t.Fatal(err)
	}
	if first.AgentID != second.AgentID || first.InstanceID != second.InstanceID ||
		first.SPIFFEID != second.SPIFFEID || !first.CreatedAt.Equal(second.CreatedAt) {
		t.Fatal("relogin replaced the workstation identity")
	}
	if len(s.List()) != 1 || second.Status != types.StatusActive || second.RevokedAt != nil ||
		second.EnrolledBinaryHash != "release-two" || second.DeviceType != "desktop" || second.Groups[0] != "engineering" {
		t.Fatal("relogin did not refresh the canonical workstation")
	}
	if s.WorkstationBlocked(second.InstanceID, second.AppID, true) {
		t.Fatal("re-enrolled workstation is still blocked")
	}
}

func TestConcurrentWorkstationEnrollmentCreatesOneRecord(t *testing.T) {
	s := NewStore("test")
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.EnrollWorkstation(workstationFixture()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if len(s.List()) != 1 {
		t.Fatal("concurrent login created duplicates")
	}
}

func TestWorkstationLoginCannotClearAdministrativeRestrictions(t *testing.T) {
	for _, status := range []types.AgentStatus{types.StatusRevoked, types.StatusQuarantined} {
		t.Run(string(status), func(t *testing.T) {
			s := NewStore("test")
			a, err := s.EnrollWorkstation(workstationFixture())
			if err != nil {
				t.Fatal(err)
			}
			if status == types.StatusRevoked {
				err = s.Revoke(a.AgentID)
			} else {
				_, err = s.QuarantineTarget(a.AgentID, "test")
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.EnrollWorkstation(workstationFixture()); err == nil {
				t.Fatal("login cleared an administrative restriction")
			}
		})
	}
}

func TestWorkstationLoginKeepsDistinctOwnersHostsAndApps(t *testing.T) {
	for _, field := range []string{"owner", "host", "app", "missing-host"} {
		t.Run(field, func(t *testing.T) {
			s := NewStore("test")
			req := workstationFixture()
			if _, err := s.EnrollWorkstation(req); err != nil {
				t.Fatal(err)
			}
			switch field {
			case "owner":
				req.UserEmail = "bob@example.test"
			case "host":
				req.Hostname = "other-laptop"
			case "app":
				req.AppID = "unrelated-service"
			case "missing-host":
				req.Hostname = ""
			}
			if _, err := s.EnrollWorkstation(req); err != nil {
				t.Fatal(err)
			}
			if len(s.List()) != 2 {
				t.Fatal("distinct workstation registrations merged")
			}
		})
	}
}

func TestWorkstationLoginSupersedesHistoricalDuplicates(t *testing.T) {
	s := NewStore("test")
	req := workstationFixture()
	first, err := s.EnrollWorkstation(req)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := s.PreRegister(types.PreRegisterRequest{AppID: req.AppID, OwnerEmail: req.UserEmail})
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err = s.EnrollWithClaims(duplicate.AgentID, "old-binary", "", req.Hostname, "windows", "amd64", "old-instance",
		req.UserEmail, "", nil, "oidc", "google")
	if err != nil {
		t.Fatal(err)
	}
	// Establish age explicitly: Windows clock resolution can give adjacent
	// registrations equal timestamps, invoking the agent-ID tie breaker.
	s.mu.Lock()
	s.agents[duplicate.AgentID].CreatedAt = first.CreatedAt.Add(time.Second)
	s.mu.Unlock()
	current, err := s.EnrollWorkstation(req)
	if err != nil {
		t.Fatal(err)
	}
	if current.AgentID != first.AgentID {
		t.Fatalf("expected oldest registration %s, got %s", first.AgentID, current.AgentID)
	}
	if listed, visible := len(s.List()), len(s.ListVisible(time.Hour, nil)); listed != 1 || visible != 1 {
		t.Fatalf("historical duplicate remains visible: listed=%d visible=%d", listed, visible)
	}
	old, err := s.Get(duplicate.AgentID)
	if err != nil || old.SupersededBy != current.AgentID || old.Status != types.StatusDeregistered {
		t.Fatal("duplicate identity was not retained as a tombstone")
	}
	if !s.WorkstationBlocked("old-instance", req.AppID, false) {
		t.Fatal("superseded identity can still report")
	}
	// An old client retry must not create another visible workstation row.
	s.EnsureSessionAgent(req.AppID, "old-instance", "", req.UserEmail, req.Hostname)
	if len(s.List()) != 1 {
		t.Fatal("old session recreated a duplicate")
	}
}

func TestWorkstationDuplicateTimestampTieIsDeterministic(t *testing.T) {
	s := NewStore("test")
	req := workstationFixture()
	created := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	s.mu.Lock()
	for _, id := range []string{"agent-b", "agent-a"} {
		s.agents[id] = &types.RegisteredAgent{
			AgentID: id, AppID: req.AppID, Hostname: req.Hostname,
			UserEmail: req.UserEmail, InstanceID: id + "-instance",
			Status: types.StatusActive, CreatedAt: created,
		}
	}
	s.mu.Unlock()
	// Repeat selection to cover map iteration order and already-superseded
	// records without relying on wall-clock precision or randomly generated IDs.
	for i := 0; i < 20; i++ {
		current, err := s.EnrollWorkstation(req)
		if err != nil {
			t.Fatal(err)
		}
		if current.AgentID != "agent-a" || len(s.List()) != 1 {
			t.Fatalf("timestamp tie selected an inconsistent primary: %s", current.AgentID)
		}
	}
}

func TestWorkstationLoginPromotesRecoveredIdentity(t *testing.T) {
	s := NewStore("test")
	req := workstationFixture()
	recovered := s.EnsureSessionAgent(req.AppID, "recovered-instance", "", req.UserEmail, req.Hostname)
	current, err := s.EnrollWorkstation(req)
	if err != nil {
		t.Fatal(err)
	}
	if current.AgentID != recovered.AgentID || current.RecoveryOnly || len(current.PermittedScopes) == 0 || len(s.List()) != 1 {
		t.Fatal("verified login did not promote the recovered workstation")
	}
}
