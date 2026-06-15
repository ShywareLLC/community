package state

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/ShywareLLC/community/protocol/tx"
	"github.com/ShywareLLC/community/protocol/types"
)

// --- helpers ---

func injectOpenPollWithRescind(s *State, pollID string, eligPub, reconcilePub ed25519.PublicKey) {
	now := time.Now().Unix()
	s.polls[pollID] = &types.Poll{
		PollID:                     pollID,
		Question:                   "Test question?",
		Options:                    []string{"yes", "no"},
		VotingMethod:               types.VotingMethodPlurality,
		StartTime:                  now - 10,
		EndTime:                    now + 3600,
		Status:                     "open",
		CreatedAt:                  now - 10,
		EligibilityAuthorityPubKey: base64.StdEncoding.EncodeToString(eligPub),
		ReconcilingAuthorityPubKey: base64.StdEncoding.EncodeToString(reconcilePub),
	}
}

func injectL1L2(s *State, pollID, ballotID, identityHash string) {
	s.voteDirections[pollID+":"+ballotID] = &types.VoteRecord{
		BallotID: ballotID,
		Choices:  []string{"yes"},
	}
	s.voterRegistry[pollID+":"+identityHash] = &types.VoterRecord{
		IdentityHash: identityHash,
	}
}

func buildRescindTx(
	t *testing.T,
	pollID, ballotID, identityHash, revocationRef string,
	eligPriv ed25519.PrivateKey,
	reconcilePriv ed25519.PrivateKey,
) *tx.Tx {
	t.Helper()
	msg := rescindMessage(pollID, ballotID, identityHash, revocationRef)
	eligSig := ed25519.Sign(eligPriv, msg)
	reconcileSig := ed25519.Sign(reconcilePriv, msg)

	data, err := json.Marshal(tx.AuthorityRescindData{
		PollID:            pollID,
		BallotID:          ballotID,
		IdentityHash:      identityHash,
		RevocationRef:     revocationRef,
		EligibilitySig:    eligSig,
		ReconcilingSig:    reconcileSig,
	})
	if err != nil {
		t.Fatalf("marshal rescind data: %v", err)
	}
	return &tx.Tx{Type: tx.TxTypeAuthorityRescind, Signature: []byte{1}, Data: data}
}

// --- tests ---

func TestAuthorityRescind_HappyPath(t *testing.T) {
	s := newTestState(t)

	eligPub, eligPriv, _ := ed25519.GenerateKey(nil)
	reconcilePub, reconcilePriv, _ := ed25519.GenerateKey(nil)

	pollID := "poll-rescind-1"
	ballotID := "ballot-abc"
	identityHash := "identity-xyz"
	revocationRef := "case-001"

	injectOpenPollWithRescind(s, pollID, eligPub, reconcilePub)
	injectL1L2(s, pollID, ballotID, identityHash)

	transaction := buildRescindTx(t, pollID, ballotID, identityHash, revocationRef, eligPriv, reconcilePriv)

	if err := s.ValidateTx(transaction); err != nil {
		t.Fatalf("ValidateTx: %v", err)
	}
	events, err := s.ExecuteTx(transaction)
	if err != nil {
		t.Fatalf("ExecuteTx: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected at least one event")
	}

	// L1 and L2 entries must be gone
	if _, ok := s.voteDirections[pollID+":"+ballotID]; ok {
		t.Error("L1 entry should have been deleted")
	}
	if _, ok := s.voterRegistry[pollID+":"+identityHash]; ok {
		t.Error("L2 entry should have been deleted")
	}

	// Append-only rescission audit record must exist
	rec, ok := s.rescissions[pollID+":"+ballotID]
	if !ok {
		t.Fatal("rescission audit record missing")
	}
	if rec.RevocationRef != revocationRef {
		t.Errorf("RevocationRef = %q, want %q", rec.RevocationRef, revocationRef)
	}
}

func TestAuthorityRescind_RejectWhenNoPollRescindKeys(t *testing.T) {
	s := newTestState(t)

	pollID := "poll-no-rescind"
	injectOpenPoll(s, pollID) // no rescind keys registered
	injectL1L2(s, pollID, "ballot-1", "identity-1")

	_, eligPriv, _ := ed25519.GenerateKey(nil)
	_, reconcilePriv, _ := ed25519.GenerateKey(nil)
	transaction := buildRescindTx(t, pollID, "ballot-1", "identity-1", "case-x", eligPriv, reconcilePriv)

	if err := s.ValidateTx(transaction); err == nil {
		t.Fatal("expected error for poll with no rescind keys, got nil")
	}
}

func TestAuthorityRescind_RejectBadEligibilitySig(t *testing.T) {
	s := newTestState(t)

	eligPub, _, _ := ed25519.GenerateKey(nil)
	reconcilePub, reconcilePriv, _ := ed25519.GenerateKey(nil)
	_, wrongEligPriv, _ := ed25519.GenerateKey(nil) // wrong key

	pollID := "poll-bad-elig"
	injectOpenPollWithRescind(s, pollID, eligPub, reconcilePub)
	injectL1L2(s, pollID, "ballot-1", "identity-1")

	transaction := buildRescindTx(t, pollID, "ballot-1", "identity-1", "case-x", wrongEligPriv, reconcilePriv)

	if err := s.ValidateTx(transaction); err == nil {
		t.Fatal("expected error for bad eligibility sig, got nil")
	}
}

func TestAuthorityRescind_RejectBadReconcilingSig(t *testing.T) {
	s := newTestState(t)

	eligPub, eligPriv, _ := ed25519.GenerateKey(nil)
	reconcilePub, _, _ := ed25519.GenerateKey(nil)
	_, wrongReconcilePriv, _ := ed25519.GenerateKey(nil) // wrong key

	pollID := "poll-bad-reconcile"
	injectOpenPollWithRescind(s, pollID, eligPub, reconcilePub)
	injectL1L2(s, pollID, "ballot-1", "identity-1")

	transaction := buildRescindTx(t, pollID, "ballot-1", "identity-1", "case-x", eligPriv, wrongReconcilePriv)

	if err := s.ValidateTx(transaction); err == nil {
		t.Fatal("expected error for bad reconciling sig, got nil")
	}
}

func TestAuthorityRescind_RejectEligibilityAloneCannotRescind(t *testing.T) {
	// Same sig used for both slots — eligibility authority cannot forge reconcile sig.
	s := newTestState(t)

	eligPub, eligPriv, _ := ed25519.GenerateKey(nil)
	reconcilePub, _, _ := ed25519.GenerateKey(nil) // different key; eligPriv cannot sign for it

	pollID := "poll-elig-alone"
	injectOpenPollWithRescind(s, pollID, eligPub, reconcilePub)
	injectL1L2(s, pollID, "ballot-1", "identity-1")

	// Pass eligPriv for both slots
	transaction := buildRescindTx(t, pollID, "ballot-1", "identity-1", "case-x", eligPriv, eligPriv)

	if err := s.ValidateTx(transaction); err == nil {
		t.Fatal("eligibility authority alone should not be able to produce a valid rescission")
	}
}

func TestAuthorityRescind_RejectReconcilingAloneCannotRescind(t *testing.T) {
	s := newTestState(t)

	eligPub, _, _ := ed25519.GenerateKey(nil)
	reconcilePub, reconcilePriv, _ := ed25519.GenerateKey(nil)

	pollID := "poll-reconcile-alone"
	injectOpenPollWithRescind(s, pollID, eligPub, reconcilePub)
	injectL1L2(s, pollID, "ballot-1", "identity-1")

	// Pass reconcilePriv for both slots
	transaction := buildRescindTx(t, pollID, "ballot-1", "identity-1", "case-x", reconcilePriv, reconcilePriv)

	if err := s.ValidateTx(transaction); err == nil {
		t.Fatal("reconciling authority alone should not be able to produce a valid rescission")
	}
}

func TestAuthorityRescind_IdempotencyGuard(t *testing.T) {
	s := newTestState(t)

	eligPub, eligPriv, _ := ed25519.GenerateKey(nil)
	reconcilePub, reconcilePriv, _ := ed25519.GenerateKey(nil)

	pollID := "poll-idempotent"
	ballotID := "ballot-idem"
	identityHash := "identity-idem"

	injectOpenPollWithRescind(s, pollID, eligPub, reconcilePub)
	injectL1L2(s, pollID, ballotID, identityHash)

	transaction := buildRescindTx(t, pollID, ballotID, identityHash, "case-idem", eligPriv, reconcilePriv)

	// First rescission succeeds.
	if err := s.ValidateTx(transaction); err != nil {
		t.Fatalf("first ValidateTx: %v", err)
	}
	if _, err := s.ExecuteTx(transaction); err != nil {
		t.Fatalf("first ExecuteTx: %v", err)
	}

	// Second rescission must be rejected.
	if err := s.ValidateTx(transaction); err == nil {
		t.Fatal("second rescission should be rejected (idempotency guard)")
	}
}

func TestAuthorityRescind_DeleteOnlyCannotAddNewEntries(t *testing.T) {
	// After rescission, the total L1+L2 count is strictly less; no new entries appear.
	s := newTestState(t)

	eligPub, eligPriv, _ := ed25519.GenerateKey(nil)
	reconcilePub, reconcilePriv, _ := ed25519.GenerateKey(nil)

	pollID := "poll-deleteonly"
	injectOpenPollWithRescind(s, pollID, eligPub, reconcilePub)
	injectL1L2(s, pollID, "ballot-a", "identity-a")
	injectL1L2(s, pollID, "ballot-b", "identity-b")

	l1Before, l2Before := countListEntries(s, pollID)

	transaction := buildRescindTx(t, pollID, "ballot-a", "identity-a", "case-del", eligPriv, reconcilePriv)
	if err := s.ValidateTx(transaction); err != nil {
		t.Fatalf("ValidateTx: %v", err)
	}
	if _, err := s.ExecuteTx(transaction); err != nil {
		t.Fatalf("ExecuteTx: %v", err)
	}

	l1After, l2After := countListEntries(s, pollID)

	if l1After >= l1Before {
		t.Errorf("L1 count did not decrease: before=%d after=%d", l1Before, l1After)
	}
	if l2After >= l2Before {
		t.Errorf("L2 count did not decrease: before=%d after=%d", l2Before, l2After)
	}
	if l1After != l1Before-1 || l2After != l2Before-1 {
		t.Errorf("counts should each decrease by exactly 1: l1 %d→%d, l2 %d→%d",
			l1Before, l1After, l2Before, l2After)
	}
}

func TestAuthorityRescind_SealerDeploymentHasNoRescindKeys(t *testing.T) {
	// Sealer-governed polls must not have rescind keys — TxTypeAuthorityRescind
	// is structurally unavailable for them.
	s := newTestState(t)

	pollID := "shychat-poll"
	now := time.Now().Unix()
	// Sealer-governed: no EligibilityAuthorityPubKey, no ReconcilingAuthorityPubKey
	s.polls[pollID] = &types.Poll{
		PollID:       pollID,
		Question:     "Chat message?",
		Options:      []string{"yes", "no"},
		VotingMethod: types.VotingMethodPlurality,
		StartTime:    now - 10,
		EndTime:      now + 3600,
		Status:       "open",
		CreatedAt:    now - 10,
	}
	injectL1L2(s, pollID, "ballot-chat", "identity-chat")

	_, eligPriv, _ := ed25519.GenerateKey(nil)
	_, reconcilePriv, _ := ed25519.GenerateKey(nil)
	transaction := buildRescindTx(t, pollID, "ballot-chat", "identity-chat", "case-sealer", eligPriv, reconcilePriv)

	if err := s.ValidateTx(transaction); err == nil {
		t.Fatal("sealer-governed deployment should reject TxTypeAuthorityRescind")
	}
}

// TestAuthorityRescind_SealedPartitionDecrementsSealedCount verifies the
// global count-match invariant |L2| = counted-partition-|L1| + SealedCount is
// preserved when a two-party rescission targets a ballot that has already been
// migrated to the sealed partition via TxTypeResealVote.
//
// Without the fix, SealedCount would remain 1 after the L2 deletion, breaking
// the invariant: |L2|=0 ≠ counted-L1=0 + SealedCount=1.
func TestAuthorityRescind_SealedPartitionDecrementsSealedCount(t *testing.T) {
	s := newTestState(t)

	eligPub, eligPriv, _ := ed25519.GenerateKey(nil)
	reconcilePub, reconcilePriv, _ := ed25519.GenerateKey(nil)

	const pollID = "poll-rescind-sealed"
	const ballotID = "ballot-sealed-001"
	const identityHash = "identity-sealed-001"
	const revocationRef = "case-sealed-001"

	injectOpenPollWithRescind(s, pollID, eligPub, reconcilePub)

	// Inject a sealed-partition L1 record (simulates a prior TxTypeResealVote).
	s.voteDirections[pollID+":"+ballotID] = &types.VoteRecord{
		BallotID:    ballotID,
		Choices:     []string{"yes"},
		PartitionID: "sealed",
	}
	s.voterRegistry[pollID+":"+identityHash] = &types.VoterRecord{
		IdentityHash: identityHash,
	}
	s.polls[pollID].SealedCount = 1 // reflects the prior partition migration

	// Pre-condition: invariant holds before rescission.
	// counted-L1 = 0 (sealed records excluded), SealedCount = 1, |L2| = 1 → 1 = 0 + 1 ✓
	if s.polls[pollID].SealedCount != 1 {
		t.Fatalf("pre-condition: SealedCount=%d, want 1", s.polls[pollID].SealedCount)
	}

	transaction := buildRescindTx(t, pollID, ballotID, identityHash, revocationRef, eligPriv, reconcilePriv)
	if err := s.ValidateTx(transaction); err != nil {
		t.Fatalf("ValidateTx: %v", err)
	}
	if _, err := s.ExecuteTx(transaction); err != nil {
		t.Fatalf("ExecuteTx: %v", err)
	}

	// L1 and L2 must be deleted.
	if _, ok := s.voteDirections[pollID+":"+ballotID]; ok {
		t.Error("L1 sealed record should have been deleted")
	}
	if _, ok := s.voterRegistry[pollID+":"+identityHash]; ok {
		t.Error("L2 record should have been deleted")
	}

	// SealedCount must have been decremented to preserve the invariant.
	if s.polls[pollID].SealedCount != 0 {
		t.Fatalf("SealedCount=%d after rescinding sealed record, want 0 (invariant: |L2| = counted-L1 + SealedCount)",
			s.polls[pollID].SealedCount)
	}

	// Verify invariant: |L2| = counted-L1 + SealedCount.
	// All three terms are now 0.
	l1Count, l2Count := countListEntries(s, pollID)
	sealedCount := int(s.polls[pollID].SealedCount)
	// counted-L1 excludes sealed records — count only non-sealed, non-superseded entries.
	countedL1 := 0
	prefix := pollID + ":"
	for key, v := range s.voteDirections {
		if len(key) > len(prefix) && key[:len(prefix)] == prefix {
			if !v.Superseded && v.PartitionID != "sealed" {
				countedL1++
			}
		}
	}
	if int(l2Count) != countedL1+sealedCount {
		t.Fatalf("|L2|=%d != counted-L1=%d + SealedCount=%d (invariant broken)", l2Count, countedL1, sealedCount)
	}
	_ = l1Count // l1Count includes sealed; invariant uses counted-L1 (non-sealed)
}
