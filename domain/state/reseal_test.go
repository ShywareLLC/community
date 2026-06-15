package state

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/ShywareLLC/community/protocol/tx"
	"github.com/ShywareLLC/community/protocol/types"
)

// buildResealTx constructs a valid TxTypeResealVote envelope signed with voterPriv.
func buildResealTx(t *testing.T, pollID, ballotID string, voterPriv ed25519.PrivateKey) *tx.Tx {
	t.Helper()
	voterPub := voterPriv.Public().(ed25519.PublicKey)
	voterPubHex := hex.EncodeToString(voterPub)
	migSig := ed25519.Sign(voterPriv, migrationSigMessage(ballotID, pollID))
	data, err := json.Marshal(tx.ResealVoteData{
		PollID:       pollID,
		BallotID:     ballotID,
		VoterPubKey:  voterPubHex,
		MigrationSig: migSig,
		Timestamp:    time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("marshal reseal data: %v", err)
	}
	return &tx.Tx{Type: tx.TxTypeResealVote, Signature: []byte{1}, Data: data}
}

// injectOpenPollForReseal inserts a minimal open poll (no rescission keys needed).
func injectOpenPollForReseal(s *State, pollID string) {
	now := time.Now().Unix()
	s.polls[pollID] = &types.Poll{
		PollID:       pollID,
		Question:     "Test?",
		Options:      []string{"yes", "no"},
		VotingMethod: types.VotingMethodPlurality,
		StartTime:    now - 10,
		EndTime:      now + 3600,
		Status:       "open",
		CreatedAt:    now - 10,
	}
}

// castAndGetBallotID casts a ballot via the direct path and returns its ballot_id.
// Uses the Didit identity path from state_test helpers (requires a DiditVerifier).
// For reseal tests we inject the L1/L2 records directly to avoid the IDV dependency.
func injectCastBallotForReseal(s *State, pollID, ballotNonce string, choices []string, voterPriv ed25519.PrivateKey) string {
	voterPub := voterPriv.Public().(ed25519.PublicKey)
	voterPubHex := hex.EncodeToString(voterPub)
	ballotID := deriveBallotID(ballotNonce, choices, "")
	voteKey := voteStoreKey(pollID, ballotID)
	migrationAuthHash := sha256.Sum256([]byte("partition-migration-auth:" + voterPubHex + ":" + pollID))
	s.voteDirections[voteKey] = &types.VoteRecord{
		BallotID:        ballotID,
		Choices:         choices,
		PartitionID:     "",
		Superseded:      false,
		VoterPubKeyHash: hex.EncodeToString(migrationAuthHash[:]),
	}
	// Derive identity_hash the same way as the Didit verifier default:
	// sha256(voter_pub_key_bytes || poll_id)
	h := sha256.Sum256(append(voterPub, []byte(pollID)...))
	identityHash := hex.EncodeToString(h[:])
	registryKey := pollID + ":" + identityHash
	s.voterRegistry[registryKey] = &types.VoterRecord{IdentityHash: identityHash}
	return ballotID
}

// TestResealVoteMigratesPartition verifies the core partition-migration invariant:
// after migration, the VoteRecord is in the "sealed" partition, SealedCount == 1,
// the L2 entry is untouched, and the tally excludes the migrated ballot.
func TestResealVoteMigratesPartition(t *testing.T) {
	s := newTestState(t)
	_, voterPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	const pollID = "poll-reseal-1"
	injectOpenPollForReseal(s, pollID)
	ballotID := injectCastBallotForReseal(s, pollID, "nonce-001", []string{"yes"}, voterPriv)

	resealTx := buildResealTx(t, pollID, ballotID, voterPriv)
	if err := s.ValidateTx(resealTx); err != nil {
		t.Fatalf("ValidateTx: %v", err)
	}
	events, err := s.ExecuteTx(resealTx)
	if err != nil {
		t.Fatalf("ExecuteTx: %v", err)
	}

	// Event emitted.
	if len(events) == 0 || events[0].Type != "partition_migrated" {
		t.Fatalf("expected partition_migrated event, got %v", events)
	}

	// L1 record is now in "sealed" partition.
	voteKey := voteStoreKey(pollID, ballotID)
	vote, ok := s.voteDirections[voteKey]
	if !ok {
		t.Fatal("expected L1 record to still exist after migration")
	}
	if vote.PartitionID != "sealed" {
		t.Fatalf("expected PartitionID=sealed, got %q", vote.PartitionID)
	}
	if vote.Superseded {
		t.Fatal("migrated record must not be Superseded — it still exists in sealed partition")
	}

	// SealedCount incremented.
	if s.polls[pollID].SealedCount != 1 {
		t.Fatalf("expected SealedCount=1, got %d", s.polls[pollID].SealedCount)
	}

	// L2 entry unchanged.
	h := sha256.Sum256(append(voterPriv.Public().(ed25519.PublicKey), []byte(pollID)...))
	identityHash := hex.EncodeToString(h[:])
	if _, ok := s.voterRegistry[pollID+":"+identityHash]; !ok {
		t.Fatal("L2 entry must be preserved after partition migration")
	}

	// Tally excludes the sealed ballot.
	ballotIDs, identityHashes, counts := s.collectPollLists(pollID, types.VotingMethodPlurality, []string{"yes", "no"})
	if len(ballotIDs) != 0 {
		t.Fatalf("sealed ballot must be excluded from counted tally, got %d ballot(s)", len(ballotIDs))
	}
	// L2 is still present — total participant count is 1.
	if len(identityHashes) != 1 {
		t.Fatalf("expected 1 identity hash (participation proven), got %d", len(identityHashes))
	}
	if counts["yes"] != 0 {
		t.Fatalf("expected 'yes' count=0 after migration, got %d", counts["yes"])
	}
}

// TestResealVoteRejectsWrongKey verifies that a different voter cannot migrate
// a ballot they did not cast (Claim 47 — participant-initiated, not operator-initiable).
func TestResealVoteRejectsWrongKey(t *testing.T) {
	s := newTestState(t)
	_, voterPriv, _ := ed25519.GenerateKey(nil)
	_, attackerPriv, _ := ed25519.GenerateKey(nil)

	const pollID = "poll-reseal-2"
	injectOpenPollForReseal(s, pollID)
	ballotID := injectCastBallotForReseal(s, pollID, "nonce-002", []string{"no"}, voterPriv)

	// Attacker tries to migrate with their own key and sig.
	attackerPub := attackerPriv.Public().(ed25519.PublicKey)
	attackerPubHex := hex.EncodeToString(attackerPub)
	migSig := ed25519.Sign(attackerPriv, migrationSigMessage(ballotID, pollID))
	data, _ := json.Marshal(tx.ResealVoteData{
		PollID:       pollID,
		BallotID:     ballotID,
		VoterPubKey:  attackerPubHex,
		MigrationSig: migSig,
		Timestamp:    time.Now().Unix(),
	})
	wrongKeyTx := &tx.Tx{Type: tx.TxTypeResealVote, Signature: []byte{1}, Data: data}

	if err := s.ValidateTx(wrongKeyTx); err == nil {
		t.Fatal("expected wrong voter_pub_key to be rejected")
	}
}

// TestResealVoteRejectsBadSig verifies the migration signature check.
func TestResealVoteRejectsBadSig(t *testing.T) {
	s := newTestState(t)
	_, voterPriv, _ := ed25519.GenerateKey(nil)
	voterPub := voterPriv.Public().(ed25519.PublicKey)
	voterPubHex := hex.EncodeToString(voterPub)

	const pollID = "poll-reseal-3"
	injectOpenPollForReseal(s, pollID)
	ballotID := injectCastBallotForReseal(s, pollID, "nonce-003", []string{"yes"}, voterPriv)

	// Corrupt the migration signature.
	migSig := ed25519.Sign(voterPriv, migrationSigMessage(ballotID, pollID))
	migSig[0] ^= 0xFF

	data, _ := json.Marshal(tx.ResealVoteData{
		PollID:       pollID,
		BallotID:     ballotID,
		VoterPubKey:  voterPubHex,
		MigrationSig: migSig,
		Timestamp:    time.Now().Unix(),
	})
	badSigTx := &tx.Tx{Type: tx.TxTypeResealVote, Signature: []byte{1}, Data: data}

	if err := s.ValidateTx(badSigTx); err == nil {
		t.Fatal("expected bad migration signature to be rejected")
	}
}

// TestResealVoteRejectsAlreadySealed verifies idempotence protection —
// a ballot already in the sealed partition cannot be migrated again.
func TestResealVoteRejectsAlreadySealed(t *testing.T) {
	s := newTestState(t)
	_, voterPriv, _ := ed25519.GenerateKey(nil)

	const pollID = "poll-reseal-4"
	injectOpenPollForReseal(s, pollID)
	ballotID := injectCastBallotForReseal(s, pollID, "nonce-004", []string{"yes"}, voterPriv)

	// First migration — should succeed.
	resealTx := buildResealTx(t, pollID, ballotID, voterPriv)
	if err := s.ValidateTx(resealTx); err != nil {
		t.Fatalf("first ValidateTx: %v", err)
	}
	if _, err := s.ExecuteTx(resealTx); err != nil {
		t.Fatalf("first ExecuteTx: %v", err)
	}

	// Second migration — must be rejected.
	resealTx2 := buildResealTx(t, pollID, ballotID, voterPriv)
	if err := s.ValidateTx(resealTx2); err == nil {
		t.Fatal("expected second migration of already-sealed ballot to be rejected")
	}
}

// TestResealVoteCountMatchInvariant verifies that after migration:
//
//	|L2| == counted-partition-|L1| + SealedCount
//
// for a poll with two voters where one migrates.
func TestResealVoteCountMatchInvariant(t *testing.T) {
	s := newTestState(t)
	_, voter1Priv, _ := ed25519.GenerateKey(nil)
	_, voter2Priv, _ := ed25519.GenerateKey(nil)

	const pollID = "poll-reseal-5"
	injectOpenPollForReseal(s, pollID)
	ballot1 := injectCastBallotForReseal(s, pollID, "nonce-v1", []string{"yes"}, voter1Priv)
	injectCastBallotForReseal(s, pollID, "nonce-v2", []string{"no"}, voter2Priv)

	// Migrate voter1's ballot.
	if _, err := s.ExecuteTx(buildResealTx(t, pollID, ballot1, voter1Priv)); err != nil {
		t.Fatalf("ExecuteTx reseal: %v", err)
	}

	// Count L2 entries.
	l2Count := 0
	for key := range s.voterRegistry {
		if len(key) > len(pollID)+1 && key[:len(pollID)+1] == pollID+":" {
			l2Count++
		}
	}

	// Count counted-partition L1 entries.
	ballotIDs, _, _ := s.collectPollLists(pollID, types.VotingMethodPlurality, []string{"yes", "no"})
	countedL1 := len(ballotIDs)
	sealedCount := int(s.polls[pollID].SealedCount)

	// Invariant: |L2| == counted-L1 + SealedCount
	if l2Count != countedL1+sealedCount {
		t.Fatalf("|L2|=%d != counted-|L1|=%d + SealedCount=%d", l2Count, countedL1, sealedCount)
	}

	// Voter2's ballot still counted; voter1's is not.
	if countedL1 != 1 {
		t.Fatalf("expected 1 counted ballot, got %d", countedL1)
	}
	if sealedCount != 1 {
		t.Fatalf("expected SealedCount=1, got %d", sealedCount)
	}
}
