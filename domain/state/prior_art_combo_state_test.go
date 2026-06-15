package state

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/ShywareLLC/community/services/identity"
	"github.com/ShywareLLC/community/protocol/tx"
	"github.com/ShywareLLC/community/protocol/types"
)

// TestPriorArtComboSplitRecordsWithoutPairedInvariantCannotFinalize shows that a
// "split records" design does not reproduce the shyware voting apparatus unless
// it also preserves the paired count-coupled structure. Here the state is
// intentionally drifted so List 1 and List 2 are both present but not conserved
// one-for-one; poll close fails and no tally is committed.
func TestPriorArtComboSplitRecordsWithoutPairedInvariantCannotFinalize(t *testing.T) {
	s := newTestState(t)
	pollID := "poll-prior-art-split-only"
	injectEndedPoll(s, pollID)

	s.voteDirections[voteStoreKey(pollID, computeBallotID("nonce-a"))] = &types.VoteRecord{
		BallotID: computeBallotID("nonce-a"),
		Choices:  []string{"yes"},
	}
	s.voteDirections[voteStoreKey(pollID, computeBallotID("nonce-b"))] = &types.VoteRecord{
		BallotID: computeBallotID("nonce-b"),
		Choices:  []string{"no"},
	}
	s.voterRegistry[pollID+":identity-a"] = &types.VoterRecord{
		IdentityHash: "identity-a",
	}

	closeTx := buildTx(t, tx.TxTypePollClose, tx.PollCloseData{PollID: pollID, ClosingHeight: 1})
	if err := s.ValidateTx(closeTx); err != nil {
		t.Fatalf("ValidateTx (close): %v", err)
	}
	if _, err := s.ExecuteTx(closeTx); err == nil {
		t.Fatal("expected poll close to fail when split records drift out of paired conservation")
	}
	if _, exists := s.tallies[pollID]; exists {
		t.Fatal("tally should not be committed when count-match is violated")
	}
}

// TestPriorArtComboRecoveryNeedsProtectedLinkage demonstrates that a protocol
// variant with anonymous submission plus deduplicated participation, but without
// receipt/reconcile linkage, cannot support credential-free direction change. The
// state machine requires old_ballot_id; canonical state does not yield it from
// identity credentials alone.
func TestPriorArtComboRecoveryNeedsProtectedLinkage(t *testing.T) {
	s := newTestState(t)
	issuerPub, issuerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	s.SetIdentityVerifier(&identity.IdentusVerifier{IssuerPubKey: issuerPub})

	pollID := "poll-prior-art-no-linkage"
	injectOpenPoll(s, pollID)

	_, voterPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate voter key: %v", err)
	}
	subjectDID := "did:test:prior-art-no-linkage"

	castIdentusBallot(t, s, pollID, testNonce("cast-no-linkage"), subjectDID, []string{"yes"}, voterPriv, issuerPriv)

	nonceNew := testNonce("new-no-linkage")
	voterPubHex := hex.EncodeToString(voterPriv.Public().(ed25519.PublicKey))
	voterSig := ed25519.Sign(voterPriv, []byte("update:"+nonceNew+":"+pollID))
	h := sha256.New()
	h.Write([]byte(subjectDID))
	h.Write([]byte(voterPubHex))
	h.Write([]byte(pollID))
	credSig := ed25519.Sign(issuerPriv, h.Sum(nil))

	// This simulates a "split records + identity dedup" design with no receipt or
	// reconciling tier: the voter can authenticate, but cannot supply old_ballot_id.
	updateTx := buildTx(t, tx.TxTypeUpdateBallot, tx.BallotUpdateData{
		PollID:               pollID,
		OldBallotID:          "",
		NewBallotNonce:       nonceNew,
		NewChoices:           []string{"no"},
		BeaconBlockHash:      testBeaconHash,
		BeaconBlockHeight:    testBeaconHeight,
		Timestamp:            time.Now().Unix(),
		VoterPubKey:          voterPubHex,
		VoterSig:             voterSig,
		IdentusSubjectDID:    subjectDID,
		IdentusCredentialSig: credSig,
	})

	err = s.ValidateTx(updateTx)
	if err == nil {
		t.Fatal("expected direction change without protected linkage / old_ballot_id to fail")
	}
	if !strings.Contains(err.Error(), "old_ballot_id") && !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected missing old_ballot_id / not found error, got: %v", err)
	}
}

// TestPriorArtComboWriteOnlyPosturePermitsDirectionChangeWithValidState shows that
// write-only posture does NOT block direction changes. Write-only suppresses only
// participant-facing reconcile and receipt-readback paths. A voter under coercion
// must be able to change a forced submission; readback suppression already prevents
// the coercer from reading back the direction, so blocking the update would remove
// the only effective counter without providing additional protection.
func TestPriorArtComboWriteOnlyPosturePermitsDirectionChangeWithValidState(t *testing.T) {
	s := newTestState(t)
	issuerPub, issuerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	s.SetIdentityVerifier(&identity.IdentusVerifier{IssuerPubKey: issuerPub})
	s.SetWriteOnly(true)

	pollID := "poll-prior-art-write-only"
	injectOpenPoll(s, pollID)

	_, voterPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate voter key: %v", err)
	}
	subjectDID := "did:test:prior-art-write-only"

	castNonceWO := testNonce("cast-write-only")
	castIdentusBallot(t, s, pollID, castNonceWO, subjectDID, []string{"yes"}, voterPriv, issuerPriv)

	nonceNewWO := testNonce("new-write-only")
	voterPubHex := hex.EncodeToString(voterPriv.Public().(ed25519.PublicKey))
	voterSig := ed25519.Sign(voterPriv, []byte("update:"+nonceNewWO+":"+pollID))
	h := sha256.New()
	h.Write([]byte(subjectDID))
	h.Write([]byte(voterPubHex))
	h.Write([]byte(pollID))
	credSig := ed25519.Sign(issuerPriv, h.Sum(nil))

	updateTx := buildTx(t, tx.TxTypeUpdateBallot, tx.BallotUpdateData{
		PollID:               pollID,
		OldBallotID:          computeBallotIDWithBeacon(testBeaconHash, castNonceWO),
		NewBallotNonce:       nonceNewWO,
		NewChoices:           []string{"no"},
		BeaconBlockHash:      testBeaconHash,
		BeaconBlockHeight:    testBeaconHeight,
		Timestamp:            time.Now().Unix(),
		VoterPubKey:          voterPubHex,
		VoterSig:             voterSig,
		IdentusSubjectDID:    subjectDID,
		IdentusCredentialSig: credSig,
	})

	if err = s.ValidateTx(updateTx); err != nil {
		t.Fatalf("write-only posture must not reject direction change with valid old_ballot_id: %v", err)
	}
}
