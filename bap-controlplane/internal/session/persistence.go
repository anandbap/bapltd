package session

import "database/sql"

// PersistenceDB shares the configured store transaction pool with supporting
// projections. The session store retains connection ownership.
func (s *Store) PersistenceDB() *sql.DB { return s.db }
