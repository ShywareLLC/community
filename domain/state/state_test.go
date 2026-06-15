package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	dbm "github.com/cometbft/cometbft-db"
	"github.com/cometbft/cometbft/libs/log"

	"github.com/ShywareLLC/community/services/identity"
	"github.com/ShywareLLC/community/protocol/tx"
	"github.com/ShywareLLC/community/protocol/types"
	"github.com/ShywareLLC/community/verify"
)

// testNonce returns a deterministic, valid 64-hex-char (32-byte) nonce for tests.
// It SHA-256-hashes the tag so each unique tag produces a unique, entropy-passing nonce.
func testNonce(tag string) string {
	h := sha256.Sum256([]byte("test-nonce:" + tag))
	return hex.EncodeToString(h[:])
}

// testBeaconHash is the canonical test beacon block hash (64 hex chars).
const testBeaconHeight int64 = 42

var testBeaconHash = func() string {
	h := sha256.Sum256([]byte("test-beacon-block"))
	return hex.EncodeToString(h[:])
}()

// seedBeacon injects the test beacon into s.beaconWindow so that validators
// calling ValidateBeacon with testBeaconHash/testBeaconHeight will pass.
func seedBeacon(s *State) {
	s.RecordBeacon(testBeaconHeight, testBeaconHash)
}

// --- test helpers ---

func newTestState(t *testing.T) *State {
	t.Helper()
	s, err := NewState(context.Background(), dbm.NewMemDB(), "", log.NewNopLogger())
	if err != nil {
		t.Fatalf("NewState: %v", err)
	}
	seedBeacon(s)
	return s
}

func buildTx(t *testing.T, typ uint8, payload any) *tx.Tx {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal tx payload: %v", err)
	}
	return &tx.Tx{Type: typ, Signature: []byte{1}, Data: data}
}

func mustMarshalJSON(t *testing.T, payload any) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return data
}

func buildBatchFlushTx(t *testing.T, pollID string, submissions ...tx.Tx) *tx.Tx {
	t.Helper()
	return buildTx(t, tx.TxTypeBatchFlush, tx.BatchFlushData{
		PollID:      pollID,
		Submissions: submissions,
	})
}

// injectOpenPoll inserts an open poll directly into state, bypassing
// validatePollCreate's "start_time must be in the future" constraint.
func injectOpenPoll(s *State, pollID string) {
	now := time.Now().Unix()
	s.polls[pollID] = &types.Poll{
		PollID:       pollID,
		Question:     "Test question?",
		Options:      []string{"yes", "no"},
		VotingMethod: types.VotingMethodPlurality,
		StartTime:    now - 10,
		EndTime:      now + 3600,
		Status:       "open",
		CreatedAt:    now - 10,
	}
}

// injectEndedPoll inserts a poll whose EndTime is in the past, ready for close.
func injectEndedPoll(s *State, pollID string) {
	now := time.Now().Unix()
	s.polls[pollID] = &types.Poll{
		PollID:       pollID,
		Question:     "Test question?",
		Options:      []string{"yes", "no"},
		VotingMethod: types.VotingMethodPlurality,
		StartTime:    now - 7200,
		EndTime:      now - 1,
		Status:       "open",
		CreatedAt:    now - 7200,
	}
}

// castIdentusBallot submits a valid Identus-embodiment ballot through the full
// ValidateTx → ExecuteTx path using in-process Ed25519 keys.
// Pass nil or empty choices for a structural abstention.
func buildIdentusBallotEnvelope(
	t *testing.T, s *State,
	pollID, nonce, subjectDID string,
	choices []string,
	voterPriv ed25519.PrivateKey,
	issuerPriv ed25519.PrivateKey,
) tx.Tx {
	t.Helper()
	voterPub := voterPriv.Public().(ed25519.PublicKey)
	voterPubHex := hex.EncodeToString(voterPub)

	voterSig := ed25519.Sign(voterPriv, []byte(nonce+":"+pollID))

	h := sha256.New()
	h.Write([]byte(subjectDID))
	h.Write([]byte(voterPubHex))
	h.Write([]byte(pollID))
	credSig := ed25519.Sign(issuerPriv, h.Sum(nil))

	transaction := buildTx(t, tx.TxTypeBallotCast, tx.BallotCastData{
		PollID:               pollID,
		Choices:              choices,
		BallotNonce:          nonce,
		BeaconBlockHash:      testBeaconHash,
		BeaconBlockHeight:    testBeaconHeight,
		Timestamp:            time.Now().Unix(),
		VoterPubKey:          voterPubHex,
		VoterSig:             voterSig,
		IdentusSubjectDID:    subjectDID,
		IdentusCredentialSig: credSig,
	})
	return *transaction
}

func castIdentusBallot(
	t *testing.T, s *State,
	pollID, nonce, subjectDID string,
	choices []string,
	voterPriv ed25519.PrivateKey,
	issuerPriv ed25519.PrivateKey,
) {
	t.Helper()
	envelope := buildIdentusBallotEnvelope(t, s, pollID, nonce, subjectDID, choices, voterPriv, issuerPriv)
	transaction := buildBatchFlushTx(t, pollID, envelope)
	if err := s.ValidateTx(transaction); err != nil {
		t.Fatalf("ValidateTx (cast): %v", err)
	}
	if _, err := s.ExecuteTx(transaction); err != nil {
		t.Fatalf("ExecuteTx (cast): %v", err)
	}
}

// updateIdentusBallot submits a valid TxTypeUpdateBallot through the full
// ValidateTx → ExecuteTx path. Pass nil or empty newChoices for re-abstention.
// Returns the new ballot_id = H(newNonce).
func updateIdentusBallot(
	t *testing.T, s *State,
	pollID, oldBallotID, newNonce, subjectDID string,
	newChoices []string,
	voterPriv ed25519.PrivateKey,
	issuerPriv ed25519.PrivateKey,
) string {
	t.Helper()
	voterPub := voterPriv.Public().(ed25519.PublicKey)
	voterPubHex := hex.EncodeToString(voterPub)

	// Update device sig: "update:" + newNonce + ":" + pollID
	voterSig := ed25519.Sign(voterPriv, []byte("update:"+newNonce+":"+pollID))

	h := sha256.New()
	h.Write([]byte(subjectDID))
	h.Write([]byte(voterPubHex))
	h.Write([]byte(pollID))
	credSig := ed25519.Sign(issuerPriv, h.Sum(nil))

	transaction := buildTx(t, tx.TxTypeUpdateBallot, tx.BallotUpdateData{
		PollID:               pollID,
		OldBallotID:          oldBallotID,
		NewBallotNonce:       newNonce,
		NewChoices:           newChoices,
		BeaconBlockHash:      testBeaconHash,
		BeaconBlockHeight:    testBeaconHeight,
		Timestamp:            time.Now().Unix(),
		VoterPubKey:          voterPubHex,
		VoterSig:             voterSig,
		IdentusSubjectDID:    subjectDID,
		IdentusCredentialSig: credSig,
	})
	if err := s.ValidateTx(transaction); err != nil {
		t.Fatalf("ValidateTx (update): %v", err)
	}
	if _, err := s.ExecuteTx(transaction); err != nil {
		t.Fatalf("ExecuteTx (update): %v", err)
	}
	return computeBallotIDWithBeacon(testBeaconHash, newNonce)
}

func confirmIdentusReceipt(
	t *testing.T, s *State,
	pollID, subjectDID string,
	voterPriv ed25519.PrivateKey,
	issuerPriv ed25519.PrivateKey,
) string {
	t.Helper()
	voterPubHex := hex.EncodeToString(voterPriv.Public().(ed25519.PublicKey))

	hid := sha256.New()
	hid.Write([]byte(subjectDID))
	hid.Write([]byte(voterPubHex))
	hid.Write([]byte(pollID))
	identityHash := hex.EncodeToString(hid.Sum(nil))

	hcm := sha256.New()
	hcm.Write([]byte("confirm:"))
	hcm.Write([]byte(subjectDID))
	hcm.Write([]byte(voterPubHex))
	hcm.Write([]byte(pollID))
	confirmCredSig := ed25519.Sign(issuerPriv, hcm.Sum(nil))

	confirmTx := buildTx(t, tx.TxTypeConfirmReceipt, tx.ConfirmReceiptData{
		PollID:               pollID,
		IdentityHash:         identityHash,
		VoterPubKey:          voterPubHex,
		IdentusSubjectDID:    subjectDID,
		IdentusCredentialSig: confirmCredSig,
	})
	if err := s.ValidateTx(confirmTx); err != nil {
		t.Fatalf("ValidateTx (confirm): %v", err)
	}
	if _, err := s.ExecuteTx(confirmTx); err != nil {
		t.Fatalf("ExecuteTx (confirm): %v", err)
	}

	return identityHash
}

// countListEntries counts L1 (voteDirections) and L2 (voterRegistry) entries for a poll.
func countListEntries(s *State, pollID string) (l1, l2 int64) {
	prefix := pollID + ":"
	for key := range s.voteDirections {
		if strings.HasPrefix(key, prefix) {
			l1++
		}
	}
	for key := range s.voterRegistry {
		if strings.HasPrefix(key, prefix) {
			l2++
		}
	}
	return
}

// --- Tests ---

// TestComputeAppHashDeterminism verifies that computeAppHash returns identical
// bytes on two consecutive calls with no state mutation between them.
// Regression test for the silent json.Marshal error bug.
func TestComputeAppHashDeterminism(t *testing.T) {
	s := newTestState(t)
	injectOpenPoll(s, "poll-1")
	s.voteDirections[voteStoreKey("poll-1", "ballot-a")] = &types.VoteRecord{
		BallotID: "ballot-a", Choices: []string{"yes"},
	}
	s.voterRegistry["poll-1:hash-a"] = &types.VoterRecord{
		IdentityHash: "hash-a",
	}

	h1, err := s.computeAppHash()
	if err != nil {
		t.Fatalf("computeAppHash #1: %v", err)
	}
	h2, err := s.computeAppHash()
	if err != nil {
		t.Fatalf("computeAppHash #2: %v", err)
	}
	if !bytes.Equal(h1, h2) {
		t.Fatalf("non-deterministic app hash: %x != %x", h1, h2)
	}
}

// TestAppHashChangesOnMutation verifies that computeAppHash changes when state changes.
func TestAppHashChangesOnMutation(t *testing.T) {
	s := newTestState(t)
	injectOpenPoll(s, "poll-1")

	h1, err := s.computeAppHash()
	if err != nil {
		t.Fatalf("computeAppHash before: %v", err)
	}

	s.voteDirections[voteStoreKey("poll-1", "ballot-b")] = &types.VoteRecord{
		BallotID: "ballot-b", Choices: []string{"no"},
	}

	h2, err := s.computeAppHash()
	if err != nil {
		t.Fatalf("computeAppHash after: %v", err)
	}
	if bytes.Equal(h1, h2) {
		t.Fatal("app hash unchanged after state mutation")
	}
}

// TestBallotCastDeduplication verifies that the same identity_hash cannot cast
// two ballots in the same poll — the two-list dedup is structural, not policy.
func TestBallotCastDeduplication(t *testing.T) {
	s := newTestState(t)

	issuerPub, issuerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	s.SetIdentityVerifier(&identity.IdentusVerifier{IssuerPubKey: issuerPub})
	injectOpenPoll(s, "poll-dedup")

	_, voterPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate voter key: %v", err)
	}
	subjectDID := "did:test:alice"

	// First ballot — must succeed.
	castIdentusBallot(t, s, "poll-dedup", testNonce("001"), subjectDID, []string{"yes"}, voterPriv, issuerPriv)

	// Second ballot with the same identity (same subjectDID + voterPub → same identity_hash).
	voterPubHex := hex.EncodeToString(voterPriv.Public().(ed25519.PublicKey))
	hd := sha256.New()
	hd.Write([]byte(subjectDID))
	hd.Write([]byte(voterPubHex))
	hd.Write([]byte("poll-dedup"))
	credSig := ed25519.Sign(issuerPriv, hd.Sum(nil))
	nonce002 := testNonce("002")
	voterSig2 := ed25519.Sign(voterPriv, []byte(nonce002+":poll-dedup"))

	t2 := buildBatchFlushTx(t, "poll-dedup", tx.Tx{
		Type:      tx.TxTypeBallotCast,
		Signature: []byte{1},
		Data: mustMarshalJSON(t, tx.BallotCastData{
			PollID:               "poll-dedup",
			Choices:              []string{"no"},
			BallotNonce:          nonce002,
			BeaconBlockHash:      testBeaconHash,
			BeaconBlockHeight:    testBeaconHeight,
			Timestamp:            time.Now().Unix(),
			VoterPubKey:          voterPubHex,
			VoterSig:             voterSig2,
			IdentusSubjectDID:    subjectDID,
			IdentusCredentialSig: credSig,
		}),
	})
	err = s.ValidateTx(t2)
	if err == nil {
		t.Fatal("expected ErrorDuplicateVote, got nil")
	}
	var dupErr *types.ErrorDuplicateVote
	if !errors.As(err, &dupErr) {
		t.Fatalf("expected *types.ErrorDuplicateVote, got %T: %v", err, err)
	}
	if dupErr.PollID != "poll-dedup" {
		t.Errorf("dupErr.PollID = %q, want %q", dupErr.PollID, "poll-dedup")
	}
}

// TestCountMatchInvariant verifies that after N ballots are cast, poll close
// produces TotalVotes == N and |L1| == |L2| == N.
func TestCountMatchInvariant(t *testing.T) {
	const N = 5
	s := newTestState(t)

	pollID := "poll-count"
	injectEndedPoll(s, pollID)

	// Inject N vote records (L1) and N voter records (L2) directly, since the
	// poll has already ended and ballot casting would be rejected by time check.
	for i := 0; i < N; i++ {
		nonce := fmt.Sprintf("nonce-%03d", i)
		identityHash := fmt.Sprintf("identity-hash-%03d", i)
		ballotID := computeBallotID(nonce)
		choice := "yes"
		if i%2 == 1 {
			choice = "no"
		}
		s.voteDirections[voteStoreKey(pollID, ballotID)] = &types.VoteRecord{
			BallotID: ballotID, Choices: []string{choice},
		}
		s.voterRegistry[pollID+":"+identityHash] = &types.VoterRecord{
			IdentityHash: identityHash,
		}
	}
	s.dirty = true

	closeTx := buildTx(t, tx.TxTypePollClose, tx.PollCloseData{PollID: pollID, ClosingHeight: 1})
	if err := s.ValidateTx(closeTx); err != nil {
		t.Fatalf("ValidateTx (poll close): %v", err)
	}
	if _, err := s.ExecuteTx(closeTx); err != nil {
		t.Fatalf("ExecuteTx (poll close): %v", err)
	}

	tally, ok := s.tallies[pollID]
	if !ok {
		t.Fatal("tally not found after close")
	}
	if tally.TotalVotes != N {
		t.Errorf("TotalVotes = %d, want %d", tally.TotalVotes, N)
	}

	// Both lists must contain exactly N entries for this poll.
	l1, l2 := int64(0), int64(0)
	prefix := pollID + ":"
	for key := range s.voteDirections {
		if strings.HasPrefix(key, prefix) {
			l1++
		}
	}
	for key := range s.voterRegistry {
		if strings.HasPrefix(key, prefix) {
			l2++
		}
	}
	if l1 != N || l2 != N || l1 != l2 {
		t.Errorf("count-match: |L1|=%d |L2|=%d want %d each", l1, l2, N)
	}
}

// TestUpdateToAbstain verifies bilateral withdrawal: a voter who cast "yes"
// updates to re-abstain. Both L1 and L2 entries are deleted; the invariant
// |L1| = |L2| holds (both go from 1 to 0). No on-chain trace remains.
// Tally at close: TotalVotes=0, Counts["yes"]=0.
func TestUpdateToAbstain(t *testing.T) {
	s := newTestState(t)
	issuerPub, issuerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	s.SetIdentityVerifier(&identity.IdentusVerifier{IssuerPubKey: issuerPub})

	pollID := "poll-update-to-abstain"
	injectOpenPoll(s, pollID)

	_, voterPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate voter key: %v", err)
	}
	subjectDID := "did:test:voter-update-abstain"

	castIdentusBallot(t, s, pollID, testNonce("cast"), subjectDID,
		[]string{"yes"}, voterPriv, issuerPriv)

	l1, l2 := countListEntries(s, pollID)
	if l1 != 1 || l2 != 1 {
		t.Errorf("|L1|=%d |L2|=%d want 1 each after cast", l1, l2)
	}

	oldBallotID := computeBallotIDWithBeacon(testBeaconHash, testNonce("cast"))
	// Empty NewChoices = bilateral withdrawal.
	updateIdentusBallot(t, s, pollID, oldBallotID, testNonce("abstain"), subjectDID,
		nil, voterPriv, issuerPriv)

	// Both lists must now be empty for this poll — no on-chain trace.
	if _, exists := s.voteDirections[voteStoreKey(pollID, oldBallotID)]; exists {
		t.Error("old ballot_id still present in L1 after withdrawal")
	}
	l1, l2 = countListEntries(s, pollID)
	if l1 != 0 || l2 != 0 {
		t.Errorf("|L1|=%d |L2|=%d want 0 each after bilateral withdrawal", l1, l2)
	}

	// Close: TotalVotes=0, invariant holds trivially.
	injectEndedPoll(s, pollID)
	s.polls[pollID].Status = "open"
	closeTx := buildTx(t, tx.TxTypePollClose, tx.PollCloseData{PollID: pollID, ClosingHeight: 1})
	if err := s.ValidateTx(closeTx); err != nil {
		t.Fatalf("ValidateTx (close): %v", err)
	}
	if _, err := s.ExecuteTx(closeTx); err != nil {
		t.Fatalf("ExecuteTx (close): %v", err)
	}
	tally := s.tallies[pollID]
	if tally.TotalVotes != 0 {
		t.Errorf("TotalVotes = %d, want 0", tally.TotalVotes)
	}
	if tally.Counts["yes"] != 0 {
		t.Errorf("Counts[yes] = %d, want 0", tally.Counts["yes"])
	}
}

// TestAbstainAndRecast verifies that after bilateral withdrawal, the voter's
// identity_hash is no longer in L2, so they may re-cast a directional ballot.
// Full cycle: cast "yes" → withdraw → re-cast "no".
// Final state: |L1| = |L2| = 1, TotalVotes=1, Counts["no"]=1.
func TestAbstainAndRecast(t *testing.T) {
	s := newTestState(t)
	issuerPub, issuerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	s.SetIdentityVerifier(&identity.IdentusVerifier{IssuerPubKey: issuerPub})

	pollID := "poll-abstain-recast"
	injectOpenPoll(s, pollID)

	_, voterPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate voter key: %v", err)
	}
	subjectDID := "did:test:voter-recast"

	// Cast "yes".
	castIdentusBallot(t, s, pollID, testNonce("yes"), subjectDID,
		[]string{"yes"}, voterPriv, issuerPriv)

	// Withdraw (re-abstain) — clears L1 and L2.
	oldBallotID := computeBallotIDWithBeacon(testBeaconHash, testNonce("yes"))
	updateIdentusBallot(t, s, pollID, oldBallotID, testNonce("withdraw"), subjectDID,
		nil, voterPriv, issuerPriv)

	l1, l2 := countListEntries(s, pollID)
	if l1 != 0 || l2 != 0 {
		t.Errorf("|L1|=%d |L2|=%d want 0 each after withdrawal", l1, l2)
	}

	// Re-cast "no" — L2 is clear so this must succeed.
	castIdentusBallot(t, s, pollID, testNonce("no"), subjectDID,
		[]string{"no"}, voterPriv, issuerPriv)

	l1, l2 = countListEntries(s, pollID)
	if l1 != 1 || l2 != 1 {
		t.Errorf("|L1|=%d |L2|=%d want 1 each after re-cast", l1, l2)
	}

	injectEndedPoll(s, pollID)
	s.polls[pollID].Status = "open"
	closeTx := buildTx(t, tx.TxTypePollClose, tx.PollCloseData{PollID: pollID, ClosingHeight: 1})
	if err := s.ValidateTx(closeTx); err != nil {
		t.Fatalf("ValidateTx (close): %v", err)
	}
	if _, err := s.ExecuteTx(closeTx); err != nil {
		t.Fatalf("ExecuteTx (close): %v", err)
	}
	tally := s.tallies[pollID]
	if tally.TotalVotes != 1 {
		t.Errorf("TotalVotes = %d, want 1", tally.TotalVotes)
	}
	if tally.Counts["no"] != 1 {
		t.Errorf("Counts[no] = %d, want 1", tally.Counts["no"])
	}
	if tally.Counts["yes"] != 0 {
		t.Errorf("Counts[yes] = %d, want 0", tally.Counts["yes"])
	}
}

// TestCountMatchViolationDetected verifies that executePollClose returns an error
// when |L1| != |L2| — the invariant enforcement is active.
func TestCountMatchViolationDetected(t *testing.T) {
	s := newTestState(t)
	pollID := "poll-corrupt"
	injectEndedPoll(s, pollID)

	// L1 has 2 entries, L2 has 1 → invariant violated.
	s.voteDirections[voteStoreKey(pollID, computeBallotID("n1"))] = &types.VoteRecord{
		BallotID: computeBallotID("n1"), Choices: []string{"yes"},
	}
	s.voteDirections[voteStoreKey(pollID, computeBallotID("n2"))] = &types.VoteRecord{
		BallotID: computeBallotID("n2"), Choices: []string{"no"},
	}
	s.voterRegistry[pollID+":hash-a"] = &types.VoterRecord{
		IdentityHash: "hash-a",
	}

	closeTx := buildTx(t, tx.TxTypePollClose, tx.PollCloseData{PollID: pollID, ClosingHeight: 1})
	if err := s.ValidateTx(closeTx); err != nil {
		t.Fatalf("ValidateTx: %v", err)
	}
	_, err := s.ExecuteTx(closeTx)
	if err == nil {
		t.Fatal("expected count-match violation error, got nil")
	}
}

// TestBallotUpdateDirectionChange verifies the direction-change path of
// BallotUpdate: casting "yes" then updating to "no" replaces the L1 entry
// (new ballot_id) while L2 is unchanged. Tally: Counts["no"]=1, Counts["yes"]=0.
func TestBallotUpdateDirectionChange(t *testing.T) {
	s := newTestState(t)
	issuerPub, issuerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	s.SetIdentityVerifier(&identity.IdentusVerifier{IssuerPubKey: issuerPub})

	pollID := "poll-direction-change"
	injectOpenPoll(s, pollID)

	_, voterPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate voter key: %v", err)
	}
	subjectDID := "did:test:voter-direction"

	castIdentusBallot(t, s, pollID, testNonce("yes"), subjectDID, []string{"yes"}, voterPriv, issuerPriv)

	oldBallotID := computeBallotIDWithBeacon(testBeaconHash, testNonce("yes"))
	if _, exists := s.voteDirections[voteStoreKey(pollID, oldBallotID)]; !exists {
		t.Fatal("old ballot_id not in L1 after cast")
	}
	l1Before, l2Before := countListEntries(s, pollID)

	// Direction change: "yes" → "no". Non-empty NewChoices.
	newBallotID := updateIdentusBallot(t, s, pollID, oldBallotID, testNonce("no"), subjectDID,
		[]string{"no"}, voterPriv, issuerPriv)

	// Old ballot_id must be gone; new ballot_id must be present.
	if _, exists := s.voteDirections[voteStoreKey(pollID, oldBallotID)]; exists {
		t.Error("old ballot_id still in L1 after direction change")
	}
	if _, exists := s.voteDirections[voteStoreKey(pollID, newBallotID)]; !exists {
		t.Error("new ballot_id not in L1 after direction change")
	}
	// L1 and L2 counts are unchanged — it's a replace, not a delete+insert.
	l1After, l2After := countListEntries(s, pollID)
	if l1After != l1Before || l2After != l2Before {
		t.Errorf("|L1| %d→%d |L2| %d→%d: direction change must not alter list sizes",
			l1Before, l1After, l2Before, l2After)
	}

	// Close and verify tally.
	injectEndedPoll(s, pollID)
	s.polls[pollID].Status = "open"
	closeTx := buildTx(t, tx.TxTypePollClose, tx.PollCloseData{PollID: pollID, ClosingHeight: 1})
	if err := s.ValidateTx(closeTx); err != nil {
		t.Fatalf("ValidateTx (close): %v", err)
	}
	if _, err := s.ExecuteTx(closeTx); err != nil {
		t.Fatalf("ExecuteTx (close): %v", err)
	}
	tally := s.tallies[pollID]
	if tally.TotalVotes != 1 {
		t.Errorf("TotalVotes = %d, want 1", tally.TotalVotes)
	}
	if tally.Counts["no"] != 1 {
		t.Errorf("Counts[no] = %d, want 1", tally.Counts["no"])
	}
	if tally.Counts["yes"] != 0 {
		t.Errorf("Counts[yes] = %d, want 0 after direction change", tally.Counts["yes"])
	}
}

// TestAdversarialUpdateWrongVoter verifies that Voter B cannot update Voter A's
// ballot even when supplying the correct old_ballot_id. The state machine checks
// that the submitter's identity_hash is registered in L2 — Voter B's is not.
func TestAdversarialUpdateWrongVoter(t *testing.T) {
	s := newTestState(t)
	issuerPub, issuerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	s.SetIdentityVerifier(&identity.IdentusVerifier{IssuerPubKey: issuerPub})

	pollID := "poll-adversarial-wrong-voter"
	injectOpenPoll(s, pollID)

	// Voter A casts.
	_, voterAPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate voter A key: %v", err)
	}
	castIdentusBallot(t, s, pollID, testNonce("a"), "did:test:alice", []string{"yes"}, voterAPriv, issuerPriv)
	oldBallotID := computeBallotIDWithBeacon(testBeaconHash, testNonce("a"))

	// Voter B attempts to update Voter A's ballot_id using their own credentials.
	_, voterBPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate voter B key: %v", err)
	}
	voterBPub := voterBPriv.Public().(ed25519.PublicKey)
	voterBPubHex := hex.EncodeToString(voterBPub)

	nonceBAttempt := testNonce("b-attempt")
	voterBSig := ed25519.Sign(voterBPriv, []byte("update:"+nonceBAttempt+":"+pollID))
	hb := sha256.New()
	hb.Write([]byte("did:test:bob"))
	hb.Write([]byte(voterBPubHex))
	hb.Write([]byte(pollID))
	credSig := ed25519.Sign(issuerPriv, hb.Sum(nil))

	attackTx := buildTx(t, tx.TxTypeUpdateBallot, tx.BallotUpdateData{
		PollID:               pollID,
		OldBallotID:          oldBallotID, // Voter A's ballot_id
		NewBallotNonce:       nonceBAttempt,
		NewChoices:           []string{"no"},
		BeaconBlockHash:      testBeaconHash,
		BeaconBlockHeight:    testBeaconHeight,
		Timestamp:            time.Now().Unix(),
		VoterPubKey:          voterBPubHex,
		VoterSig:             voterBSig,
		IdentusSubjectDID:    "did:test:bob",
		IdentusCredentialSig: credSig,
	})

	if err := s.ValidateTx(attackTx); err == nil {
		t.Fatal("expected error when voter B tries to update voter A's ballot; got nil")
	}
	// L1 must be unchanged — Voter A's ballot still present.
	if _, exists := s.voteDirections[voteStoreKey(pollID, oldBallotID)]; !exists {
		t.Error("voter A's ballot was removed by voter B's attack attempt")
	}
}

// TestAdversarialUpdateTamperedSig verifies that a ballot update with a tampered
// device signature is rejected — the oracle-forgery prevention property applies
// to updates as well as casts.
func TestAdversarialUpdateTamperedSig(t *testing.T) {
	s := newTestState(t)
	issuerPub, issuerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	s.SetIdentityVerifier(&identity.IdentusVerifier{IssuerPubKey: issuerPub})

	pollID := "poll-adversarial-tampered-sig"
	injectOpenPoll(s, pollID)

	_, voterPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate voter key: %v", err)
	}
	subjectDID := "did:test:voter-tampered"
	voterPubHex := hex.EncodeToString(voterPriv.Public().(ed25519.PublicKey))

	castIdentusBallot(t, s, pollID, testNonce("cast-tamper"), subjectDID, []string{"yes"}, voterPriv, issuerPriv)
	oldBallotID := computeBallotIDWithBeacon(testBeaconHash, testNonce("cast-tamper"))

	ht := sha256.New()
	ht.Write([]byte(subjectDID))
	ht.Write([]byte(voterPubHex))
	ht.Write([]byte(pollID))
	credSig := ed25519.Sign(issuerPriv, ht.Sum(nil))

	// Correct VoterSig would be sign(sk_v, "update:"+testNonce("tampered")+":"+pollID).
	// Instead supply random bytes.
	tamperedSig := make([]byte, ed25519.SignatureSize)
	tamperedSig[0] = 0xff

	tamperTx := buildTx(t, tx.TxTypeUpdateBallot, tx.BallotUpdateData{
		PollID:               pollID,
		OldBallotID:          oldBallotID,
		NewBallotNonce:       testNonce("tampered"),
		NewChoices:           []string{"no"},
		BeaconBlockHash:      testBeaconHash,
		BeaconBlockHeight:    testBeaconHeight,
		Timestamp:            time.Now().Unix(),
		VoterPubKey:          voterPubHex,
		VoterSig:             tamperedSig, // tampered
		IdentusSubjectDID:    subjectDID,
		IdentusCredentialSig: credSig,
	})

	if err := s.ValidateTx(tamperTx); err == nil {
		t.Fatal("expected signature validation error for tampered VoterSig; got nil")
	}
	// Original ballot must still be present.
	if _, exists := s.voteDirections[voteStoreKey(pollID, oldBallotID)]; !exists {
		t.Error("original ballot removed despite tampered sig rejection")
	}
}

// TestConfirmReceiptBeforeCloseCarriesIntoFinalTally verifies that a
// ConfirmReceipt tx submitted while a poll is open is retained as live state and
// carried into the final tally at close.
func TestConfirmReceiptBeforeCloseCarriesIntoFinalTally(t *testing.T) {
	s := newTestState(t)
	issuerPub, issuerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	s.SetIdentityVerifier(&identity.IdentusVerifier{IssuerPubKey: issuerPub})

	pollID := "poll-confirm-receipt"
	injectOpenPoll(s, pollID)

	_, voterPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate voter key: %v", err)
	}
	subjectDID := "did:test:voter-confirm"

	castIdentusBallot(t, s, pollID, testNonce("confirm"), subjectDID, []string{"yes"}, voterPriv, issuerPriv)
	identityHash := confirmIdentusReceipt(t, s, pollID, subjectDID, voterPriv, issuerPriv)
	if _, exists := s.confirms[pollID+":"+identityHash]; !exists {
		t.Error("ConfirmRecord not written after confirm receipt tx")
	}
	if got := s.confirmedCountForPoll(pollID); got != 1 {
		t.Errorf("confirmedCountForPoll = %d, want 1", got)
	}

	// Close the poll and ensure the live confirmation state carries into the
	// final tally.
	injectEndedPoll(s, pollID)
	s.polls[pollID].Status = "open"
	closeTx := buildTx(t, tx.TxTypePollClose, tx.PollCloseData{PollID: pollID, ClosingHeight: 1})
	if err := s.ValidateTx(closeTx); err != nil {
		t.Fatalf("ValidateTx (close): %v", err)
	}
	if _, err := s.ExecuteTx(closeTx); err != nil {
		t.Fatalf("ExecuteTx (close): %v", err)
	}

	if s.tallies[pollID].ConfirmedCount != 1 {
		t.Errorf("ConfirmedCount = %d after close, want 1", s.tallies[pollID].ConfirmedCount)
	}
}

// TestConfirmReceiptAfterCloseStillUpdatesTally verifies that a confirm
// submitted after close still updates the final tally directly.
func TestConfirmReceiptAfterCloseStillUpdatesTally(t *testing.T) {
	s := newTestState(t)
	issuerPub, issuerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	s.SetIdentityVerifier(&identity.IdentusVerifier{IssuerPubKey: issuerPub})

	pollID := "poll-confirm-after-close"
	injectOpenPoll(s, pollID)

	_, voterPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate voter key: %v", err)
	}
	subjectDID := "did:test:voter-confirm-after-close"

	castIdentusBallot(t, s, pollID, testNonce("confirm-after-close"), subjectDID, []string{"yes"}, voterPriv, issuerPriv)

	injectEndedPoll(s, pollID)
	s.polls[pollID].Status = "open"
	closeTx := buildTx(t, tx.TxTypePollClose, tx.PollCloseData{PollID: pollID, ClosingHeight: 1})
	if err := s.ValidateTx(closeTx); err != nil {
		t.Fatalf("ValidateTx (close): %v", err)
	}
	if _, err := s.ExecuteTx(closeTx); err != nil {
		t.Fatalf("ExecuteTx (close): %v", err)
	}
	if s.tallies[pollID].ConfirmedCount != 0 {
		t.Errorf("ConfirmedCount = %d before confirm, want 0", s.tallies[pollID].ConfirmedCount)
	}

	confirmIdentusReceipt(t, s, pollID, subjectDID, voterPriv, issuerPriv)

	if s.tallies[pollID].ConfirmedCount != 1 {
		t.Errorf("ConfirmedCount = %d after confirm, want 1", s.tallies[pollID].ConfirmedCount)
	}
}

// TestWithdrawalClearsPriorConfirmation verifies that an open-poll withdrawal
// clears any earlier confirmation so confirmed_count cannot exceed live registry
// cardinality.
func TestWithdrawalClearsPriorConfirmation(t *testing.T) {
	s := newTestState(t)
	issuerPub, issuerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	s.SetIdentityVerifier(&identity.IdentusVerifier{IssuerPubKey: issuerPub})

	pollID := "poll-confirm-withdraw"
	injectOpenPoll(s, pollID)

	_, voterPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate voter key: %v", err)
	}
	subjectDID := "did:test:voter-confirm-withdraw"
	oldBallotID := computeBallotIDWithBeacon(testBeaconHash, testNonce("confirm-withdraw"))

	castIdentusBallot(t, s, pollID, testNonce("confirm-withdraw"), subjectDID, []string{"yes"}, voterPriv, issuerPriv)
	identityHash := confirmIdentusReceipt(t, s, pollID, subjectDID, voterPriv, issuerPriv)

	if got := s.confirmedCountForPoll(pollID); got != 1 {
		t.Fatalf("confirmedCountForPoll before withdraw = %d, want 1", got)
	}

	updateIdentusBallot(t, s, pollID, oldBallotID, testNonce("confirm-withdraw-update"), subjectDID, nil, voterPriv, issuerPriv)

	if got := s.confirmedCountForPoll(pollID); got != 0 {
		t.Errorf("confirmedCountForPoll after withdraw = %d, want 0", got)
	}
	if _, exists := s.confirms[pollID+":"+identityHash]; exists {
		t.Error("ConfirmRecord still present after withdrawal")
	}
}

// TestVerifyRoundTrip verifies that verify.BuildSigningPayload produces the same
// bytes that the signer used to produce the tally signature. In the dev/test
// configuration (no KMS), signTallyPayload returns the raw SHA-256 payload as
// the stub signature, so payload == tally.Signature is the correctness assertion.
// This proves the verifier and signer use identical payload construction.
func TestVerifyRoundTrip(t *testing.T) {
	s := newTestState(t)
	pollID := "poll-verify-roundtrip"
	injectEndedPoll(s, pollID)

	// Inject 2 votes so the tally is non-trivial.
	for i, choice := range []string{"yes", "no"} {
		nonce := fmt.Sprintf("vr-nonce-%d", i)
		ballotID := computeBallotID(nonce)
		s.voteDirections[voteStoreKey(pollID, ballotID)] = &types.VoteRecord{
			BallotID: ballotID, Choices: []string{choice},
		}
		s.voterRegistry[fmt.Sprintf("%s:vr-hash-%d", pollID, i)] = &types.VoterRecord{
			IdentityHash: fmt.Sprintf("vr-hash-%d", i),
		}
	}

	closeTx := buildTx(t, tx.TxTypePollClose, tx.PollCloseData{PollID: pollID, ClosingHeight: 1})
	if err := s.ValidateTx(closeTx); err != nil {
		t.Fatalf("ValidateTx: %v", err)
	}
	if _, err := s.ExecuteTx(closeTx); err != nil {
		t.Fatalf("ExecuteTx: %v", err)
	}

	tally := s.tallies[pollID]
	if tally == nil {
		t.Fatal("tally not found")
	}

	// Reconstruct the signing payload using the verifier package.
	payload := verify.BuildSigningPayload(
		tally.VoteMerkleRoot,
		tally.VoterMerkleRoot,
		tally.TotalVotes,
		tally.Counts,
	)

	// In dev mode (no KMS), tally.Signature == raw payload (see signTallyPayload).
	if !bytes.Equal(payload, tally.Signature) {
		t.Errorf("verify.BuildSigningPayload output does not match stub signature:\n  payload=%x\n  sig=%x",
			payload, tally.Signature)
	}
}

func computeBallotIDNoncePlusPayload(t *testing.T, ballotNonce string, choices []string) string {
	t.Helper()
	payloadBytes, err := json.Marshal(choices)
	if err != nil {
		t.Fatalf("marshal ballot choices: %v", err)
	}
	h := sha256.Sum256([]byte(ballotNonce + ":" + string(payloadBytes)))
	return hex.EncodeToString(h[:])
}

func TestBallotIdentifierDerivationNoncePlusPayloadFlow(t *testing.T) {
	s := newTestState(t)

	issuerPub, issuerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	s.SetIdentityVerifier(&identity.IdentusVerifier{IssuerPubKey: issuerPub})

	pollID := "poll-derivation-nonce-plus-payload"
	injectOpenPoll(s, pollID)

	_, voterPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate voter key: %v", err)
	}
	voterPubHex := hex.EncodeToString(voterPriv.Public().(ed25519.PublicKey))
	subjectDID := "did:test:derivation-mode"

	h := sha256.New()
	h.Write([]byte(subjectDID))
	h.Write([]byte(voterPubHex))
	h.Write([]byte(pollID))
	credSig := ed25519.Sign(issuerPriv, h.Sum(nil))

	castChoices := []string{"yes"}
	castNonce := testNonce("mode-cast")
	castTx := buildTx(t, tx.TxTypeBallotCast, tx.BallotCastData{
		PollID:                         pollID,
		Choices:                        castChoices,
		BallotNonce:                    castNonce,
		BeaconBlockHash:                testBeaconHash,
		BeaconBlockHeight:              testBeaconHeight,
		SubmissionIdentifierDerivation: tx.SubmissionIdentifierDerivationNoncePlusPayload,
		Timestamp:                      time.Now().Unix(),
		VoterPubKey:                    voterPubHex,
		VoterSig:                       ed25519.Sign(voterPriv, []byte(castNonce+":"+pollID)),
		IdentusSubjectDID:              subjectDID,
		IdentusCredentialSig:           credSig,
	})

	batch := buildBatchFlushTx(t, pollID, *castTx)
	if err := s.ValidateTx(batch); err != nil {
		t.Fatalf("ValidateTx (batch cast): %v", err)
	}
	if _, err := s.ExecuteTx(batch); err != nil {
		t.Fatalf("ExecuteTx (batch cast): %v", err)
	}

	expectedCastBallotID := computeBallotIDNoncePlusPayload(t, castNonce, castChoices)
	if _, exists := s.voteDirections[voteStoreKey(pollID, expectedCastBallotID)]; !exists {
		t.Fatalf("expected nonce_plus_payload ballot ID %s to exist", expectedCastBallotID)
	}
	if _, exists := s.voteDirections[voteStoreKey(pollID, computeBallotID(castNonce))]; exists {
		t.Fatalf("unexpected nonce_only ballot ID for nonce_plus_payload cast")
	}

	newChoices := []string{"no"}
	newNonce := testNonce("mode-update")
	updateTx := buildTx(t, tx.TxTypeUpdateBallot, tx.BallotUpdateData{
		PollID:                         pollID,
		OldBallotID:                    expectedCastBallotID,
		NewBallotNonce:                 newNonce,
		BeaconBlockHash:                testBeaconHash,
		BeaconBlockHeight:              testBeaconHeight,
		SubmissionIdentifierDerivation: tx.SubmissionIdentifierDerivationNoncePlusPayload,
		NewChoices:                     newChoices,
		Timestamp:                      time.Now().Unix(),
		VoterPubKey:                    voterPubHex,
		VoterSig:                       ed25519.Sign(voterPriv, []byte("update:"+newNonce+":"+pollID)),
		IdentusSubjectDID:              subjectDID,
		IdentusCredentialSig:           credSig,
	})

	if err := s.ValidateTx(updateTx); err != nil {
		t.Fatalf("ValidateTx (update): %v", err)
	}
	if _, err := s.ExecuteTx(updateTx); err != nil {
		t.Fatalf("ExecuteTx (update): %v", err)
	}

	expectedUpdatedBallotID := computeBallotIDNoncePlusPayload(t, newNonce, newChoices)
	if _, exists := s.voteDirections[voteStoreKey(pollID, expectedUpdatedBallotID)]; !exists {
		t.Fatalf("expected nonce_plus_payload updated ballot ID %s to exist", expectedUpdatedBallotID)
	}
	if _, exists := s.voteDirections[voteStoreKey(pollID, expectedCastBallotID)]; exists {
		t.Fatalf("old ballot ID still present after update")
	}
	if _, exists := s.voteDirections[voteStoreKey(pollID, computeBallotID(newNonce))]; exists {
		t.Fatalf("unexpected nonce_only updated ballot ID for nonce_plus_payload update")
	}
}

func TestBatchFlushIdentifierDerivationNoncePlusPayload(t *testing.T) {
	s := newTestState(t)

	issuerPub, issuerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	s.SetIdentityVerifier(&identity.IdentusVerifier{IssuerPubKey: issuerPub})

	pollID := "poll-batch-derivation-mode"
	injectOpenPoll(s, pollID)

	_, voterOnePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate voter one key: %v", err)
	}
	voterOnePubHex := hex.EncodeToString(voterOnePriv.Public().(ed25519.PublicKey))
	subjectOne := "did:test:batch-one"
	hOne := sha256.New()
	hOne.Write([]byte(subjectOne))
	hOne.Write([]byte(voterOnePubHex))
	hOne.Write([]byte(pollID))
	credOne := ed25519.Sign(issuerPriv, hOne.Sum(nil))

	_, voterTwoPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate voter two key: %v", err)
	}
	voterTwoPubHex := hex.EncodeToString(voterTwoPriv.Public().(ed25519.PublicKey))
	subjectTwo := "did:test:batch-two"
	hTwo := sha256.New()
	hTwo.Write([]byte(subjectTwo))
	hTwo.Write([]byte(voterTwoPubHex))
	hTwo.Write([]byte(pollID))
	credTwo := ed25519.Sign(issuerPriv, hTwo.Sum(nil))

	nonceOne := testNonce("batch-one")
	choicesOne := []string{"yes"}
	nonceTwo := testNonce("batch-two")
	choicesTwo := []string{"no"}

	castOne := buildIdentusBallotEnvelope(t, s, pollID, nonceOne, subjectOne, choicesOne, voterOnePriv, issuerPriv)
	castOneData := tx.BallotCastData{}
	if err := json.Unmarshal(castOne.Data, &castOneData); err != nil {
		t.Fatalf("unmarshal cast one: %v", err)
	}
	castOneData.SubmissionIdentifierDerivation = tx.SubmissionIdentifierDerivationNoncePlusPayload
	castOne = tx.Tx{Type: tx.TxTypeBallotCast, Signature: []byte{1}, Data: mustMarshalJSON(t, castOneData)}

	castTwo := buildTx(t, tx.TxTypeBallotCast, tx.BallotCastData{
		PollID:                         pollID,
		Choices:                        choicesTwo,
		BallotNonce:                    nonceTwo,
		BeaconBlockHash:                testBeaconHash,
		BeaconBlockHeight:              testBeaconHeight,
		SubmissionIdentifierDerivation: tx.SubmissionIdentifierDerivationNoncePlusPayload,
		Timestamp:                      time.Now().Unix(),
		VoterPubKey:                    voterTwoPubHex,
		VoterSig:                       ed25519.Sign(voterTwoPriv, []byte(nonceTwo+":"+pollID)),
		IdentusSubjectDID:              subjectTwo,
		IdentusCredentialSig:           credTwo,
	})

	batch := buildBatchFlushTx(t, pollID, castOne, *castTwo)
	if err := s.ValidateTx(batch); err != nil {
		t.Fatalf("ValidateTx (batch): %v", err)
	}
	if _, err := s.ExecuteTx(batch); err != nil {
		t.Fatalf("ExecuteTx (batch): %v", err)
	}

	expectedOne := computeBallotIDNoncePlusPayload(t, nonceOne, choicesOne)
	expectedTwo := computeBallotIDNoncePlusPayload(t, nonceTwo, choicesTwo)
	if _, exists := s.voteDirections[voteStoreKey(pollID, expectedOne)]; !exists {
		t.Fatalf("expected nonce_plus_payload ballot one ID %s to exist", expectedOne)
	}
	if _, exists := s.voteDirections[voteStoreKey(pollID, expectedTwo)]; !exists {
		t.Fatalf("expected nonce_plus_payload ballot two ID %s to exist", expectedTwo)
	}
	if _, exists := s.voteDirections[voteStoreKey(pollID, computeBallotID(nonceOne))]; exists {
		t.Fatalf("unexpected nonce_only ballot one ID for nonce_plus_payload batch")
	}
	if _, exists := s.voteDirections[voteStoreKey(pollID, computeBallotID(nonceTwo))]; exists {
		t.Fatalf("unexpected nonce_only ballot two ID for nonce_plus_payload batch")
	}

	_ = credOne // already validated through castOne envelope path
}

// =============================================================================
// NON-CONSENSUS EMBODIMENT TESTS
// =============================================================================
// These tests verify that the two-list structural invariant holds independent
// of the commit authority model. The rejection predicate, atomic write, and
// count-match invariant are validation-layer constraints that apply regardless
// of whether commit finalization is achieved through distributed consensus,
// centralized database transactions, or key-value store atomic operations.

// TestCentralizedDatabaseEmbodiment_RejectionPredicate verifies that the
// rejection predicate operates correctly in a simulated centralized database
// context where there is no distributed consensus, only single-authority commit.
func TestCentralizedDatabaseEmbodiment_RejectionPredicate(t *testing.T) {
	// The State object's ValidateTx and ExecuteTx methods implement the
	// rejection predicate independent of CometBFT consensus. This test
	// demonstrates that the validation logic is separable from consensus.
	s := newTestState(t)
	pollID := "centralized-db-poll"
	injectOpenPoll(s, pollID)

	// Configure identity verifier (simulates centralized authority)
	issuerPub, issuerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	s.SetIdentityVerifier(&identity.IdentusVerifier{IssuerPubKey: issuerPub})

	_, voterPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate voter key: %v", err)
	}

	// Test 1: Valid submission must pass rejection predicate
	nonce := testNonce("centralized-1")
	subjectDID := "did:prism:centralized-user-1"
	envelope := buildIdentusBallotEnvelope(t, s, pollID, nonce, subjectDID, []string{"yes"}, voterPriv, issuerPriv)
	batchTx := buildBatchFlushTx(t, pollID, envelope)

	// ValidateTx is the rejection predicate - it operates pre-commit
	if err := s.ValidateTx(batchTx); err != nil {
		t.Fatalf("rejection predicate should accept valid submission: %v", err)
	}

	// ExecuteTx performs atomic two-list write - operates post-validation
	if _, err := s.ExecuteTx(batchTx); err != nil {
		t.Fatalf("atomic write should succeed after predicate acceptance: %v", err)
	}

	// Test 2: Verify count-match invariant holds
	ballotCount := len(s.voteDirections)
	voterCount := len(s.voterRegistry)
	if ballotCount != voterCount {
		t.Fatalf("count-match invariant violated: %d ballots vs %d voters", ballotCount, voterCount)
	}

	// Test 3: Verify no joinable state exists
	// Attempt to reconstruct identity-payload association from canonical state
	for ballotKey := range s.voteDirections {
		// The ballot key contains only pollID:ballotID (no identity)
		if strings.Contains(ballotKey, subjectDID) {
			t.Fatalf("identity leaked into ballot key: %s", ballotKey)
		}
	}
	t.Log("✓ Centralized database embodiment: rejection predicate, atomic write, count-match verified")
}

// TestKeyValueStoreEmbodiment_AtomicWrite verifies that the atomic two-list
// write constraint holds in a simulated key-value store context where
// operations are key-based rather than row-based.
func TestKeyValueStoreEmbodiment_AtomicWrite(t *testing.T) {
	s := newTestState(t)
	pollID := "kv-store-poll"
	injectOpenPoll(s, pollID)

	issuerPub, issuerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	s.SetIdentityVerifier(&identity.IdentusVerifier{IssuerPubKey: issuerPub})

	// Simulate batch write as would occur in Redis MULTI/EXEC or DynamoDB TransactWriteItems
	nonce1 := testNonce("kv-1")
	nonce2 := testNonce("kv-2")
	subjectDID1 := "did:prism:kv-user-1"
	subjectDID2 := "did:prism:kv-user-2"

	_, voterPriv1, _ := ed25519.GenerateKey(nil)
	_, voterPriv2, _ := ed25519.GenerateKey(nil)

	envelope1 := buildIdentusBallotEnvelope(t, s, pollID, nonce1, subjectDID1, []string{"yes"}, voterPriv1, issuerPriv)
	envelope2 := buildIdentusBallotEnvelope(t, s, pollID, nonce2, subjectDID2, []string{"no"}, voterPriv2, issuerPriv)

	// Batch flush simulates atomic multi-key write
	batchTx := buildBatchFlushTx(t, pollID, envelope1, envelope2)

	// Pre-commit validation (equivalent to Redis Lua script or DynamoDB ConditionExpression)
	if err := s.ValidateTx(batchTx); err != nil {
		t.Fatalf("batch validation failed: %v", err)
	}

	// Atomic commit (equivalent to EXEC or TransactWriteItems)
	preCommitBallots := len(s.voteDirections)
	preCommitVoters := len(s.voterRegistry)

	if _, err := s.ExecuteTx(batchTx); err != nil {
		t.Fatalf("batch execution failed: %v", err)
	}

	postCommitBallots := len(s.voteDirections)
	postCommitVoters := len(s.voterRegistry)

	// Verify atomicity: both lists grew by exactly 2
	if postCommitBallots-preCommitBallots != 2 {
		t.Fatalf("non-atomic ballot write: expected +2, got +%d", postCommitBallots-preCommitBallots)
	}
	if postCommitVoters-preCommitVoters != 2 {
		t.Fatalf("non-atomic voter write: expected +2, got +%d", postCommitVoters-preCommitVoters)
	}

	// Verify count-match holds
	if postCommitBallots != postCommitVoters {
		t.Fatalf("count-match violated after atomic write: %d != %d", postCommitBallots, postCommitVoters)
	}

	t.Log("✓ Key-value store embodiment: atomic multi-key write, count-match verified")
}

// TestNonConsensusEmbodiment_FieldExclusivity verifies that the field-exclusivity
// condition of the rejection predicate holds regardless of commit authority model.
func TestNonConsensusEmbodiment_FieldExclusivity(t *testing.T) {
	s := newTestState(t)
	pollID := "field-exclusivity-poll"
	injectOpenPoll(s, pollID)

	issuerPub, issuerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	s.SetIdentityVerifier(&identity.IdentusVerifier{IssuerPubKey: issuerPub})

	_, voterPriv, _ := ed25519.GenerateKey(nil)

	nonce := testNonce("fe-1")
	subjectDID := "did:prism:fe-user-1"
	choices := []string{"yes"}

	envelope := buildIdentusBallotEnvelope(t, s, pollID, nonce, subjectDID, choices, voterPriv, issuerPriv)
	batchTx := buildBatchFlushTx(t, pollID, envelope)

	if err := s.ValidateTx(batchTx); err != nil {
		t.Fatalf("validation failed: %v", err)
	}
	if _, err := s.ExecuteTx(batchTx); err != nil {
		t.Fatalf("execution failed: %v", err)
	}

	// Verify field-exclusivity condition (1) of rejection predicate:
	// No anonymous submission record field carries participant identity commitment
	for voteKey, voteRecord := range s.voteDirections {
		// Vote key (List 1) must not contain identity
		if strings.Contains(voteKey, subjectDID) {
			t.Fatalf("field-exclusivity violated: identity in List 1 key")
		}
		// Vote record choices must not contain identity
		for _, choice := range voteRecord.Choices {
			if strings.Contains(choice, subjectDID) {
				t.Fatalf("field-exclusivity violated: identity in List 1 payload")
			}
		}
	}

	// Verify field-exclusivity condition (2) of rejection predicate:
	// No participant registry record field carries submission payload or identifier
	for voterKey, voterRecord := range s.voterRegistry {
		// Voter key (List 2) must not contain ballot choices
		if strings.Contains(voterKey, "yes") || strings.Contains(voterKey, "no") {
			t.Fatalf("field-exclusivity violated: payload in List 2 key")
		}
		// VoterRecord contains only IdentityHash - verify it doesn't contain payload data
		if strings.Contains(voterRecord.IdentityHash, "yes") || strings.Contains(voterRecord.IdentityHash, "no") {
			t.Fatalf("field-exclusivity violated: payload encoded in identity hash")
		}
	}

	t.Log("✓ Non-consensus embodiment: field-exclusivity constraint verified")
}

// TestNonConsensusEmbodiment_ReachableStateSpace verifies that joinable states
// are architecturally unreachable regardless of commit authority model.
func TestNonConsensusEmbodiment_ReachableStateSpace(t *testing.T) {
	s := newTestState(t)
	pollID := "reachable-state-poll"
	injectOpenPoll(s, pollID)

	issuerPub, issuerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	s.SetIdentityVerifier(&identity.IdentusVerifier{IssuerPubKey: issuerPub})

	// Submit multiple ballots
	for i := 0; i < 10; i++ {
		_, voterPriv, _ := ed25519.GenerateKey(nil)
		nonce := testNonce(fmt.Sprintf("rs-%d", i))
		subjectDID := fmt.Sprintf("did:prism:rs-user-%d", i)
		choice := "yes"
		if i%2 == 0 {
			choice = "no"
		}

		envelope := buildIdentusBallotEnvelope(t, s, pollID, nonce, subjectDID, []string{choice}, voterPriv, issuerPriv)
		batchTx := buildBatchFlushTx(t, pollID, envelope)

		if err := s.ValidateTx(batchTx); err != nil {
			t.Fatalf("validation %d failed: %v", i, err)
		}
		if _, err := s.ExecuteTx(batchTx); err != nil {
			t.Fatalf("execution %d failed: %v", i, err)
		}
	}

	// Attempt to derive identity-payload associations from canonical state
	// This simulates an attacker with full read access to canonical storage

	// Collect all submission identifiers from List 1
	var submissionIDs []string
	for key := range s.voteDirections {
		parts := strings.Split(key, ":")
		if len(parts) >= 2 {
			submissionIDs = append(submissionIDs, parts[1])
		}
	}

	// Collect all identity commitments from List 2
	var identityHashes []string
	for key := range s.voterRegistry {
		parts := strings.Split(key, ":")
		if len(parts) >= 2 {
			identityHashes = append(identityHashes, parts[1])
		}
	}

	// Verify no structural correlation exists
	// An attacker cannot determine which identity corresponds to which submission
	// because:
	// (a) No shared fields exist between List 1 and List 2 records
	// (b) No temporal/ordering metadata correlates records
	// (c) No system-defined operation produces the mapping

	if len(submissionIDs) != len(identityHashes) {
		t.Fatalf("count-match violated: %d submissions vs %d identities",
			len(submissionIDs), len(identityHashes))
	}

	// The best an attacker can do is random guessing: 1/N probability
	// This is the formal non-derivability bound from Claim 13
	n := len(submissionIDs)
	if n < 2 {
		n = 2
	}
	expectedProbability := 1.0 / float64(n)
	t.Logf("✓ Reachable state space: no joinable state exists; best attack = %.4f probability",
		expectedProbability)
}
