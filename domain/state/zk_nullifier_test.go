package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"testing"
	"time"

	dbm "github.com/cometbft/cometbft-db"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/consensys/gnark/backend/groth16"

	"github.com/ShywareLLC/community/services/identity"
	"github.com/ShywareLLC/community/protocol/tx"
	"github.com/ShywareLLC/community/protocol/zkp"
)

var (
	testZKOnce     sync.Once
	testZKErr      error
	testZKProver   *zkp.Prover
	testZKVerifier *zkp.Verifier
)

func getTestZKArtifacts(t *testing.T) (*zkp.Prover, *zkp.Verifier) {
	t.Helper()

	testZKOnce.Do(func() {
		cs, err := zkp.Compile()
		if err != nil {
			testZKErr = err
			return
		}

		pk, vk, err := groth16.Setup(cs)
		if err != nil {
			testZKErr = err
			return
		}

		var pkBuf bytes.Buffer
		if _, err := pk.WriteTo(&pkBuf); err != nil {
			testZKErr = err
			return
		}

		var vkBuf bytes.Buffer
		if _, err := vk.WriteTo(&vkBuf); err != nil {
			testZKErr = err
			return
		}

		testZKProver, err = zkp.NewProver(bytes.NewReader(pkBuf.Bytes()))
		if err != nil {
			testZKErr = err
			return
		}

		testZKVerifier, err = zkp.NewVerifier(bytes.NewReader(vkBuf.Bytes()))
		if err != nil {
			testZKErr = err
			return
		}
	})

	if testZKErr != nil {
		t.Fatalf("setup zk artifacts: %v", testZKErr)
	}

	return testZKProver, testZKVerifier
}

func newZKTestState(t *testing.T) (*State, ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()

	s, err := NewState(context.Background(), dbm.NewMemDB(), "", nil, log.NewNopLogger())
	if err != nil {
		t.Fatalf("NewState: %v", err)
	}
	seedBeacon(s)

	_, verifier := getTestZKArtifacts(t)
	diditPub, diditPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate Didit key: %v", err)
	}

	s.SetIdentityVerifier(&identity.ZKVerifier{
		DiditPubKey: diditPub,
		ZK:          verifier,
	})

	return s, diditPriv, diditPub
}

func signZKCommitment(priv ed25519.PrivateKey, commitment, pollID string) []byte {
	h := sha256.New()
	h.Write([]byte(commitment))
	h.Write([]byte(pollID))
	return ed25519.Sign(priv, h.Sum(nil))
}

func signZKConfirmCommitment(priv ed25519.PrivateKey, commitment, pollID string) []byte {
	h := sha256.New()
	h.Write([]byte("confirm:"))
	h.Write([]byte(commitment))
	h.Write([]byte(pollID))
	return ed25519.Sign(priv, h.Sum(nil))
}

func buildZKBallotEnvelope(
	t *testing.T,
	pollID, ballotNonce, personSecret string,
	choices []string,
	voterPriv ed25519.PrivateKey,
	diditPriv ed25519.PrivateKey,
) tx.Tx {
	t.Helper()

	prover, _ := getTestZKArtifacts(t)
	proofBytes, commitmentHex, nullifierHex, err := prover.Prove(personSecret, pollID)
	if err != nil {
		t.Fatalf("prove zk ballot: %v", err)
	}

	voterPubHex := hex.EncodeToString(voterPriv.Public().(ed25519.PublicKey))
	voterSig := ed25519.Sign(voterPriv, []byte(ballotNonce+":"+pollID))

	payload := tx.BallotCastData{
		PollID:             pollID,
		Choices:            choices,
		BallotNonce:        ballotNonce,
		BeaconBlockHash:    testBeaconHash,
		BeaconBlockHeight:  testBeaconHeight,
		Timestamp:          time.Now().Unix(),
		VoterPubKey:        voterPubHex,
		VoterSig:           voterSig,
		ZKNullifier:        nullifierHex,
		ZKNullifierProof:   proofBytes,
		ZKCommitment:       commitmentHex,
		DiditCommitmentSig: signZKCommitment(diditPriv, commitmentHex, pollID),
	}

	return *buildTx(t, tx.TxTypeBallotCast, payload)
}

func buildZKConfirmTx(
	t *testing.T,
	pollID, personSecret string,
	voterPub ed25519.PublicKey,
	diditPriv ed25519.PrivateKey,
) *tx.Tx {
	t.Helper()

	prover, _ := getTestZKArtifacts(t)
	proofBytes, commitmentHex, nullifierHex, err := prover.Prove(personSecret, pollID)
	if err != nil {
		t.Fatalf("prove zk confirm: %v", err)
	}

	return buildTx(t, tx.TxTypeConfirmReceipt, tx.ConfirmReceiptData{
		PollID:             pollID,
		IdentityHash:       nullifierHex,
		VoterPubKey:        hex.EncodeToString(voterPub),
		ZKNullifier:        nullifierHex,
		ZKNullifierProof:   proofBytes,
		ZKCommitment:       commitmentHex,
		DiditCommitmentSig: signZKConfirmCommitment(diditPriv, commitmentHex, pollID),
	})
}

func buildZKUpdateTx(
	t *testing.T,
	pollID, oldBallotID, newBallotNonce, personSecret string,
	newChoices []string,
	voterPriv ed25519.PrivateKey,
	diditPriv ed25519.PrivateKey,
) *tx.Tx {
	t.Helper()

	prover, _ := getTestZKArtifacts(t)
	proofBytes, commitmentHex, nullifierHex, err := prover.Prove(personSecret, pollID)
	if err != nil {
		t.Fatalf("prove zk update: %v", err)
	}

	return buildTx(t, tx.TxTypeUpdateBallot, tx.BallotUpdateData{
		PollID:             pollID,
		OldBallotID:        oldBallotID,
		NewBallotNonce:     newBallotNonce,
		NewChoices:         newChoices,
		BeaconBlockHash:    testBeaconHash,
		BeaconBlockHeight:  testBeaconHeight,
		Timestamp:          time.Now().Unix(),
		VoterPubKey:        hex.EncodeToString(voterPriv.Public().(ed25519.PublicKey)),
		VoterSig:           ed25519.Sign(voterPriv, []byte("update:"+newBallotNonce+":"+pollID)),
		ZKNullifier:        nullifierHex,
		ZKNullifierProof:   proofBytes,
		ZKCommitment:       commitmentHex,
		DiditCommitmentSig: signZKCommitment(diditPriv, commitmentHex, pollID),
	})
}

func TestZKNullifierBallotFlowAndConfirm(t *testing.T) {
	s, diditPriv, _ := newZKTestState(t)
	pollID := "zk-poll-confirm"
	injectOpenPoll(s, pollID)

	_, voterPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate voter key: %v", err)
	}

	personSecret := "zk-person-secret-confirm"
	ballotNonce := testNonce("zk-confirm")
	cast := buildZKBallotEnvelope(t, pollID, ballotNonce, personSecret, []string{"yes"}, voterPriv, diditPriv)
	batch := buildBatchFlushTx(t, pollID, cast)

	if err := s.ValidateTx(batch); err != nil {
		t.Fatalf("ValidateTx (zk cast): %v", err)
	}
	if _, err := s.ExecuteTx(batch); err != nil {
		t.Fatalf("ExecuteTx (zk cast): %v", err)
	}

	confirmTx := buildZKConfirmTx(t, pollID, personSecret, voterPriv.Public().(ed25519.PublicKey), diditPriv)
	if err := s.ValidateTx(confirmTx); err != nil {
		t.Fatalf("ValidateTx (zk confirm): %v", err)
	}
	if _, err := s.ExecuteTx(confirmTx); err != nil {
		t.Fatalf("ExecuteTx (zk confirm): %v", err)
	}

	_, _, nullifierHex, err := testZKProver.Prove(personSecret, pollID)
	if err != nil {
		t.Fatalf("recompute nullifier: %v", err)
	}

	registryKey := pollID + ":" + nullifierHex
	if _, ok := s.voterRegistry[registryKey]; !ok {
		t.Fatalf("expected voter registry entry for %s", registryKey)
	}
	if _, ok := s.confirms[registryKey]; !ok {
		t.Fatalf("expected confirm record for %s", registryKey)
	}

	voteKey := voteStoreKey(pollID, computeBallotIDWithBeacon(testBeaconHash, ballotNonce))
	voteRecord, ok := s.voteDirections[voteKey]
	if !ok {
		t.Fatalf("expected vote record for %s", voteKey)
	}
	if len(voteRecord.Choices) != 1 || voteRecord.Choices[0] != "yes" {
		t.Fatalf("unexpected vote choices: %+v", voteRecord.Choices)
	}
}

// TestZKNullifierWriteOnlyPermitsUpdate verifies that write-only posture does NOT
// block ballot updates. Write-only suppresses readback paths (receipt, nonce,
// payload) but must allow the voter to retract or replace a forced submission —
// blocking updates in write-only mode would remove the coercion victim's only
// available counter-measure. This is the documented behaviour in validateBallotUpdate.
func TestZKNullifierWriteOnlyPermitsUpdate(t *testing.T) {
	s, diditPriv, _ := newZKTestState(t)
	pollID := "zk-poll-write-only"
	injectOpenPoll(s, pollID)

	_, voterPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate voter key: %v", err)
	}

	personSecret := "zk-person-secret-write-only"
	ballotNonce := testNonce("zk-write-only")
	cast := buildZKBallotEnvelope(t, pollID, ballotNonce, personSecret, []string{"yes"}, voterPriv, diditPriv)
	batch := buildBatchFlushTx(t, pollID, cast)

	if err := s.ValidateTx(batch); err != nil {
		t.Fatalf("ValidateTx (zk cast): %v", err)
	}
	if _, err := s.ExecuteTx(batch); err != nil {
		t.Fatalf("ExecuteTx (zk cast): %v", err)
	}

	s.SetWriteOnly(true)
	updateTx := buildZKUpdateTx(
		t,
		pollID,
		computeBallotIDWithBeacon(testBeaconHash, ballotNonce),
		testNonce("zk-update"),
		personSecret,
		[]string{"no"},
		voterPriv,
		diditPriv,
	)

	if err = s.ValidateTx(updateTx); err != nil {
		t.Fatalf("write-only posture must not block ballot updates (coercion resistance requires retraction): %v", err)
	}
}

func TestZKNullifierProofFieldsRoundTrip(t *testing.T) {
	_, diditPriv, _ := newZKTestState(t)
	pollID := "zk-poll-json"
	_, voterPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate voter key: %v", err)
	}

	envelope := buildZKBallotEnvelope(t, pollID, testNonce("zk-json"), "zk-person-secret-json", []string{"yes"}, voterPriv, diditPriv)

	var payload tx.BallotCastData
	if err := json.Unmarshal(envelope.Data, &payload); err != nil {
		t.Fatalf("unmarshal envelope payload: %v", err)
	}

	if payload.ZKNullifier == "" || payload.ZKCommitment == "" || len(payload.ZKNullifierProof) == 0 {
		t.Fatalf("expected zk payload fields to be populated: %+v", payload)
	}
	if len(payload.DiditCommitmentSig) == 0 {
		t.Fatalf("expected didit commitment signature to be populated")
	}
}
