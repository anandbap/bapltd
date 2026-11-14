package policy

import (
	"fmt"
	"time"
)

// SetMaxPolicyAge is deployment configuration, not a client preference. Zero preserves legacy
// compatibility; pilot production config should explicitly choose a bounded offline budget.
func (s *Store) SetMaxPolicyAge(age time.Duration) error {
	if age != 0 && (age < time.Minute || age > 7*24*time.Hour) {
		return fmt.Errorf("policy max age must be between 1m and 168h")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxPolicyAge = age
	return nil
}

func (s *Store) PolicyLeaseRequired() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.maxPolicyAge > 0
}
