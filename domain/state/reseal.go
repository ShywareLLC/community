package state

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/ShywareLLC/community/protocol/tx"
	"github.com/ShywareLLC/community/protocol/types"
)

// migrationSigMessage returns the canonical message the voter's device signs for a
// partition-migration transaction:
//
//	"migrate:" + ballotID + ":" + pollID
//
// The "migrate:" prefix prevents BallotCast and BallotUpdate device signatures from
// being replayed as migration transactions (Claim 47(a)).
func migrationSigMessage(ballotID, pollID string) []byte {
	return []byte("migrate:" + ballotID + ":" + pollID)
}

// validateResealVote validates a TxTypeResealVote (partition migration) transaction.
//
// Preconditions (Claim 47):
//  1. The poll must exist.
//  2. The ballot_id must identify an L1 record in the counted partition (PartitionID
//     is "" or "public") that has not already been migrated (Superseded == false).
//  3. voter_pub_key must match the VoterPubKey stored in the VoteRecord at cast time.
//  4. migration_sig must be a valid Ed25519 signature over
//     "migrate:" + BallotID + ":" + PollID using the registered voter key (Claim 47(a)).
func (s *State) validateResealVote(transaction *tx.Tx) error {
	var data tx.ResealVoteData
	if err := transaction.UnmarshalData(&data); err != nil {
		return fmt.Errorf("reseal vote: invalid payload: %w", err)
	}

	poll, exists := s.polls[data.PollID]
	if !exists {
		return &types.ErrorInvalidPoll{Message: fmt.Sprintf("poll %s does not exist", data.PollID)}
	}
	if poll.Status == "closed" {
		return &types.ErrorInvalidPoll{Message: fmt.Sprintf("poll %s is closed", data.PollID)}
	}

	voteKey := voteStoreKey(data.PollID, data.BallotID)
	vote, exists := s.voteDirections[voteKey]
	if !exists {
		return fmt.Errorf("reseal vote: ballot_id %s not found in poll %s", data.BallotID, data.PollID)
	}
	if vote.Superseded {
		return fmt.Errorf("reseal vote: ballot_id %s has already been superseded", data.BallotID)
	}
	if vote.PartitionID == "sealed" {
		return fmt.Errorf("reseal vote: ballot_id %s is already in the sealed partition", data.BallotID)
	}

	// Verify that the requesting voter_pub_key matches the key registered at cast time
	// by recomputing the domain-separated hash and comparing to VoterPubKeyHash in L1.
	// The raw voter_pub_key is supplied in the migration transaction by the participant
	// (who generated the keypair) and never read from canonical state, preserving the
	// field-exclusivity condition of Claim 1 (Claim 47 — participant-initiated).
	if vote.VoterPubKeyHash == "" {
		return fmt.Errorf("reseal vote: no voter_pub_key_hash registered for ballot_id %s (cast before partition-migration support)", data.BallotID)
	}
	migrationAuthInput := "partition-migration-auth:" + data.VoterPubKey + ":" + data.PollID
	migrationAuthHash := sha256.Sum256([]byte(migrationAuthInput))
	if hex.EncodeToString(migrationAuthHash[:]) != vote.VoterPubKeyHash {
		return fmt.Errorf("reseal vote: voter_pub_key mismatch for ballot_id %s", data.BallotID)
	}

	// Decode and verify the migration signature over "migrate:" + BallotID + ":" + PollID.
	pubKeyBytes, err := hex.DecodeString(data.VoterPubKey)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("reseal vote: voter_pub_key must be a 64-char hex-encoded Ed25519 public key")
	}
	msg := migrationSigMessage(data.BallotID, data.PollID)
	if !ed25519.Verify(ed25519.PublicKey(pubKeyBytes), msg, data.MigrationSig) {
		return fmt.Errorf("reseal vote: migration signature invalid for ballot_id %s in poll %s", data.BallotID, data.PollID)
	}

	return nil
}

// executeResealVote implements participant-initiated partition migration (Claim 47).
//
// Effects (Claim 47(c) and (d)):
//   - Marks the source L1 record as migrated to the sealed partition.
//   - The record is excluded from all subsequent tally computations and
//     counted-partition count-match aggregations.
//   - Poll.SealedCount is incremented — the sealed partition cardinality counter.
//   - The corresponding L2 entry (voterRegistry) is left unchanged — the participant
//     retains a structurally verifiable proof of participation (Claim 47(d)(ii)).
//   - The migration cannot be reversed by the operator or any authority (Claim 47(d)(iii)).
//   - After migration, canonical state observers cannot determine the protocol
//     payload of the migrated submission through the counted-partition tally (Claim 47(d)(i)).
func (s *State) executeResealVote(transaction *tx.Tx) ([]abcitypes.Event, error) {
	var data tx.ResealVoteData
	if err := transaction.UnmarshalData(&data); err != nil {
		return nil, fmt.Errorf("reseal vote: invalid payload: %w", err)
	}

	voteKey := voteStoreKey(data.PollID, data.BallotID)
	vote, exists := s.voteDirections[voteKey]
	if !exists || vote.Superseded || vote.PartitionID == "sealed" {
		// Should not reach here after successful validation, but guard defensively.
		return nil, fmt.Errorf("reseal vote: ballot_id %s is not eligible for migration", data.BallotID)
	}

	// Migrate the L1 record to the sealed partition.
	// The Choices field is preserved in state (the participant's direction is not
	// destroyed) but the record is excluded from all tally computations and
	// counted-partition count-match aggregations by the tally collector (tallies.go
	// filters out PartitionID == "sealed").
	vote.PartitionID = "sealed"
	// Choices are retained but no longer contribute to the public tally.
	// A coercer who seizes the device after migration cannot determine the
	// original direction from the counted-partition tally.

	// Increment the sealed-partition cardinality counter on the poll record.
	// This preserves the global invariant:
	//   |L2| == counted-partition-|L1| + SealedCount
	// Both sides of the invariant remain equal after migration.
	s.polls[data.PollID].SealedCount++

	s.dirty = true
	s.logger.Info("Partition migration committed",
		"scoping_id", data.PollID,
		"submission_id", data.BallotID,
		"sealed_count", s.polls[data.PollID].SealedCount,
	)

	return []abcitypes.Event{{
		Type: "partition_migrated",
		Attributes: []abcitypes.EventAttribute{
			{Key: "scoping_id", Value: data.PollID, Index: true},
			{Key: "submission_id", Value: data.BallotID, Index: true},
			// Emit the sealed_count so auditors can track sealed-partition growth
			// without reconstructing it from scanning all L1 records.
			{Key: "sealed_count", Value: fmt.Sprintf("%d", s.polls[data.PollID].SealedCount), Index: false},
		},
	}}, nil
}
