// Package reconcile implements the reconciling authority's off-chain linkage store.
//
// The reconciling authority is the architectural component defined by Claim 52
// (Reconcile-Kernel): it holds read access to the protected off-chain linkage
// store but lacks canonical write authority over distributed-ledger state. This
// separation is enforced by substrate — the reconciling authority's credentials
// authorize reads from the CockroachDB linkage store but carry no BFT validator
// key and cannot broadcast transactions to the consensus engine.
//
// The linkage store maps {poll_id, identity_hash} → ballot_id. This mapping
// is written at cast time (by the API server after a successful broadcast) and
// read at withdrawal, direction-change, or reveal-evidence time, enabling:
//   - credential-free withdrawal (Claim 65, Vote-Reconcile)
//   - credential-free direction change (Claim 65, Vote-Reconcile): the voter
//     re-authenticates biometrically, the server re-derives identity_hash using
//     the same derivation as at cast time, and supplies ballot_id to the state
//     machine without the voter ever retaining a receipt on their device.
//   - reveal-evidence (Claim [NEW-65a], Vote-Reconcile): an authorized third
//     party (court, auditor) co-authenticated by the eligibility authority and
//     reconciling authority obtains the direction-free ballot_id for a
//     participant, without ballot direction being returned at any step.
//
// Privacy invariant: rows are keyed by identity_hash, not by plaintext voter
// identity. The linkage from person to identity_hash lives in the IDV provider;
// neither the reconciling authority nor the IDV can complete attribution alone.
// The store exposes no enumerable domain and defines no batch export or
// composition primitive; successive reads do not, within the system's defined
// operation set, accumulate into a global mapping.
package reconcile

import (
	"context"
	"database/sql"
	"fmt"
)

// Store is the interface the reconciling authority exposes to the API server.
// Implementations must be keyed by {poll_id, identity_hash} and must lack
// canonical write authority over the distributed ledger.
//
// The typed action set supported by this interface corresponds to the
// Vote-Reconcile typed action set {presence-check, withdraw} (Claim 65) plus
// the reveal-evidence extension (Claim [NEW-65a]):
//   - GetSubmissionID: presence-check / withdraw prerequisite
//   - RevealBallotEvidence: reveal-evidence (direction-free; requires dual auth)
//   - RecordSubmission: internal write at cast time (upsert; idempotent on retry)
//   - DeleteSubmission: withdraw (called after bilateral L1/L2 deletion confirmed)
type Store interface {
	// RecordSubmission writes or replaces the ballot_id for a participant on a
	// poll. Called after each successful ballot broadcast. Uses upsert semantics
	// (ON CONFLICT DO UPDATE) so that a direction change atomically overwrites
	// the prior ballot_id — the linkage store always reflects the latest cast
	// submission. Idempotent on transient retry after confirmed on-chain
	// acceptance: re-running with the same ballot_id is a no-op.
	RecordSubmission(ctx context.Context, pollID, identityHash, submissionID string) error

	// GetSubmissionID returns the current ballot_id for a participant on a poll.
	// Returns an error wrapping sql.ErrNoRows when no record exists —
	// the caller interprets this as the participant not having cast on this poll.
	// Used for presence-check and as a prerequisite for withdraw and reveal-evidence.
	GetSubmissionID(ctx context.Context, pollID, identityHash string) (string, error)

	// RevealBallotEvidence returns the direction-free ballot_id for a participant
	// on a poll, for use in lawful authority-gated attribution (court order,
	// regulatory audit). The returned ballot_id identifies the participant's
	// anonymous submission record (List 1) without carrying ballot direction or
	// any field from which ballot direction is derivable (Claim [NEW-65a]).
	//
	// IMPORTANT: The caller is responsible for:
	//   1. Verifying dual co-authorization from eligibility authority and
	//      reconciling authority before invoking this method.
	//   2. Committing a reveal-evidence event record to canonical state keyed
	//      by a reveal-event nonce (not the ballot_id) immediately after
	//      returning the ballot_id to the authorized party, so that the
	//      aggregate count of reveal-evidence invocations is publicly auditable.
	//   3. Never returning ballot direction, protocol payload, or any field
	//      from which submission direction is derivable as part of this response.
	//
	// Returns an error wrapping sql.ErrNoRows when no record exists.
	RevealBallotEvidence(ctx context.Context, pollID, identityHash string) (ballotID string, err error)

	// DeleteSubmission removes the linkage record when a participant withdraws.
	// Should be called after the state machine confirms bilateral L1/L2 deletion.
	DeleteSubmission(ctx context.Context, pollID, identityHash string) error
}

// PostgresStore implements Store using any Postgres-compatible database as the
// off-chain linkage backend (CockroachDB, pg, RDS, Aurora, Supabase, Neon, etc.).
// It is the production reconciling authority for recoverable-posture deployments.
// Pass any *sql.DB opened with a Postgres-compatible driver (pgx, lib/pq, etc.).
//
// Schema (run once):
//
//	CREATE TABLE IF NOT EXISTS receipt_store (
//	  poll_id       TEXT NOT NULL,
//	  identity_hash TEXT NOT NULL,
//	  ballot_id     TEXT NOT NULL,
//	  PRIMARY KEY (poll_id, identity_hash)
//	);
type PostgresStore struct {
	db *sql.DB
}

// NewPostgresStore creates a PostgresStore backed by db.
func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

func (s *PostgresStore) RecordSubmission(ctx context.Context, pollID, identityHash, submissionID string) error {
	const q = `
		INSERT INTO receipt_store (poll_id, identity_hash, ballot_id)
		VALUES ($1, $2, $3)
		ON CONFLICT (poll_id, identity_hash) DO UPDATE SET ballot_id = excluded.ballot_id`
	if _, err := s.db.ExecContext(ctx, q, pollID, identityHash, submissionID); err != nil {
		return fmt.Errorf("reconcile store upsert: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetSubmissionID(ctx context.Context, pollID, identityHash string) (string, error) {
	const q = `SELECT ballot_id FROM receipt_store WHERE poll_id = $1 AND identity_hash = $2`
	var submissionID string
	if err := s.db.QueryRowContext(ctx, q, pollID, identityHash).Scan(&submissionID); err != nil {
		return "", fmt.Errorf("reconcile store lookup poll=%s: %w", pollID, err)
	}
	return submissionID, nil
}

func (s *PostgresStore) RevealBallotEvidence(ctx context.Context, pollID, identityHash string) (string, error) {
	// RevealBallotEvidence returns the direction-free ballot_id only.
	// Caller must verify dual co-authorization and commit a reveal-evidence
	// event record to canonical state before returning to the requesting party.
	const q = `SELECT ballot_id FROM receipt_store WHERE poll_id = $1 AND identity_hash = $2`
	var ballotID string
	if err := s.db.QueryRowContext(ctx, q, pollID, identityHash).Scan(&ballotID); err != nil {
		return "", fmt.Errorf("reconcile store reveal-evidence poll=%s: %w", pollID, err)
	}
	return ballotID, nil
}

func (s *PostgresStore) DeleteSubmission(ctx context.Context, pollID, identityHash string) error {
	const q = `DELETE FROM receipt_store WHERE poll_id = $1 AND identity_hash = $2`
	if _, err := s.db.ExecContext(ctx, q, pollID, identityHash); err != nil {
		return fmt.Errorf("reconcile store delete poll=%s: %w", pollID, err)
	}
	return nil
}
