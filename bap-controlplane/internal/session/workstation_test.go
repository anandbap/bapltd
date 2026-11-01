package session

import (
	"path/filepath"
	"testing"
)

func TestVerifiedWorkstationLoginClearsOnlyLogoutPlaceholders(t *testing.T) {
	s := NewStore()
	if err := s.RevokeSession("station", "Deregistered via logout"); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeSession("instance", "Administrator revoked workstation"); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearWorkstationLogout("station", "instance"); err != nil {
		t.Fatal(err)
	}
	if s.IsRevoked("station") {
		t.Fatal("synthetic logout placeholder survived new login")
	}
	if !s.IsRevoked("instance") {
		t.Fatal("login cleared an administrative revocation")
	}
	actual, err := s.Start(SessionStartRequest{SessionID: "execution", AppID: "claude-code", InstanceID: "station"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeSession(actual.SessionID, "Deregistered via logout"); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearWorkstationLogout(actual.SessionID, ""); err != nil {
		t.Fatal(err)
	}
	if !s.IsRevoked(actual.SessionID) {
		t.Fatal("login cleared a real execution session revocation")
	}
}

func TestWorkstationLogoutPlaceholderCleanupPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	s, err := NewStoreWithDB(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeSession("station", "Deregistered via logout"); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeSession("admin-block", "Administrative revocation"); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearWorkstationLogout("station", "admin-block"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewStoreWithDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.IsRevoked("station") || !reopened.IsRevoked("admin-block") {
		t.Fatal("logout cleanup or administrative block did not survive reload")
	}
}
