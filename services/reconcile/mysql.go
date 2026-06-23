package reconcile

import (
	"context"
	"database/sql"
	"fmt"
)

// MySQLStore implements Store using any MySQL-compatible database as the
// off-chain linkage backend (MySQL, MariaDB, PlanetScale, TiDB, Aurora MySQL, etc.).
// Pass any *sql.DB opened with a MySQL-compatible driver (go-sql-driver/mysql, etc.).
//
// Schema (run once):
//
//	CREATE TABLE IF NOT EXISTS receipt_store (
//	  poll_id       VARCHAR(255) NOT NULL,
//	  identity_hash VARCHAR(255) NOT NULL,
//	  ballot_id     VARCHAR(255) NOT NULL,
//	  PRIMARY KEY (poll_id, identity_hash)
//	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
//
// Required module dep:
//
//	go get github.com/go-sql-driver/mysql@latest
//	import _ "github.com/go-sql-driver/mysql"
type MySQLStore struct {
	db *sql.DB
}

// NewMySQLStore creates a MySQLStore backed by db.
func NewMySQLStore(db *sql.DB) *MySQLStore {
	return &MySQLStore{db: db}
}

func (s *MySQLStore) RecordSubmission(ctx context.Context, pollID, identityHash, submissionID string) error {
	const q = `
		INSERT INTO receipt_store (poll_id, identity_hash, ballot_id)
		VALUES (?, ?, ?)
		ON DUPLICATE KEY UPDATE ballot_id = VALUES(ballot_id)`
	if _, err := s.db.ExecContext(ctx, q, pollID, identityHash, submissionID); err != nil {
		return fmt.Errorf("mysql reconcile store upsert: %w", err)
	}
	return nil
}

func (s *MySQLStore) GetSubmissionID(ctx context.Context, pollID, identityHash string) (string, error) {
	const q = `SELECT ballot_id FROM receipt_store WHERE poll_id = ? AND identity_hash = ?`
	var submissionID string
	if err := s.db.QueryRowContext(ctx, q, pollID, identityHash).Scan(&submissionID); err != nil {
		return "", fmt.Errorf("mysql reconcile store lookup poll=%s: %w", pollID, err)
	}
	return submissionID, nil
}

func (s *MySQLStore) RevealBallotEvidence(ctx context.Context, pollID, identityHash string) (string, error) {
	const q = `SELECT ballot_id FROM receipt_store WHERE poll_id = ? AND identity_hash = ?`
	var ballotID string
	if err := s.db.QueryRowContext(ctx, q, pollID, identityHash).Scan(&ballotID); err != nil {
		return "", fmt.Errorf("mysql reconcile store reveal-evidence poll=%s: %w", pollID, err)
	}
	return ballotID, nil
}

func (s *MySQLStore) DeleteSubmission(ctx context.Context, pollID, identityHash string) error {
	const q = `DELETE FROM receipt_store WHERE poll_id = ? AND identity_hash = ?`
	if _, err := s.db.ExecContext(ctx, q, pollID, identityHash); err != nil {
		return fmt.Errorf("mysql reconcile store delete poll=%s: %w", pollID, err)
	}
	return nil
}
