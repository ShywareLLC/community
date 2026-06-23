package reconcile

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
)

// MemoryStore implements Store using an in-process map.
// State is not persisted. Create one instance per test and discard it —
// isolation is free with `new(MemoryStore)` or `&MemoryStore{}`.
//
// Consistent with MemoryLedgerInterface on the JS side: zero dependencies,
// no server required, suitable for unit tests and local dev.
type MemoryStore struct {
	mu      sync.RWMutex
	entries map[string]string // "pollID:identityHash" → submissionID
}

func (s *MemoryStore) key(pollID, identityHash string) string {
	return pollID + ":" + identityHash
}

func (s *MemoryStore) init() {
	if s.entries == nil {
		s.entries = make(map[string]string)
	}
}

func (s *MemoryStore) RecordSubmission(_ context.Context, pollID, identityHash, submissionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	s.entries[s.key(pollID, identityHash)] = submissionID
	return nil
}

func (s *MemoryStore) GetSubmissionID(_ context.Context, pollID, identityHash string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.entries[s.key(pollID, identityHash)]
	if !ok {
		return "", fmt.Errorf("memory reconcile store lookup poll=%s: %w", pollID, sql.ErrNoRows)
	}
	return v, nil
}

func (s *MemoryStore) RevealBallotEvidence(_ context.Context, pollID, identityHash string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.entries[s.key(pollID, identityHash)]
	if !ok {
		return "", fmt.Errorf("memory reconcile store reveal-evidence poll=%s: %w", pollID, sql.ErrNoRows)
	}
	return v, nil
}

func (s *MemoryStore) DeleteSubmission(_ context.Context, pollID, identityHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, s.key(pollID, identityHash))
	return nil
}

// Ensure MemoryStore satisfies Store at compile time.
var _ Store = (*MemoryStore)(nil)
