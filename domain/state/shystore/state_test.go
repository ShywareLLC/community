package shystore

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	dbm "github.com/cometbft/cometbft-db"
	"github.com/cometbft/cometbft/libs/log"

	"github.com/ShywareLLC/community/services/identity"
	"github.com/ShywareLLC/community/protocol/tx"
)

// testNonce returns a deterministic valid 64-hex-char nonce for tests.
func testNonce(tag string) string {
	h := sha256.Sum256([]byte("test-nonce:" + tag))
	return hex.EncodeToString(h[:])
}

// testBeaconHeight and testBeaconHash mirror the values in state_test.go.
const testBeaconHeight int64 = 42

var testBeaconHash = func() string {
	h := sha256.Sum256([]byte("test-beacon-block"))
	return hex.EncodeToString(h[:])
}()

func newTestStoreState(t *testing.T) *StoreState {
	t.Helper()
	s, err := NewStoreState(context.Background(), dbm.NewMemDB(), "", log.NewNopLogger())
	if err != nil {
		t.Fatalf("NewStoreState: %v", err)
	}
	s.TwoListBase.RecordBeacon(testBeaconHeight, testBeaconHash)
	return s
}

func buildStoreTx(t *testing.T, typ uint8, payload any) *tx.Tx {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal store payload: %v", err)
	}
	return &tx.Tx{Type: typ, Signature: []byte{1}, Data: data}
}

func identusCredentialSig(issuerPriv ed25519.PrivateKey, subjectDID, senderPubHex, bucketID string) []byte {
	h := sha256.New()
	h.Write([]byte(subjectDID))
	h.Write([]byte(senderPubHex))
	h.Write([]byte(bucketID))
	return ed25519.Sign(issuerPriv, h.Sum(nil))
}

func computeSecretIDNoncePlusPayload(t *testing.T, secretNonce string, payload json.RawMessage) string {
	t.Helper()
	h := sha256.Sum256([]byte(secretNonce + ":" + string(payload)))
	return hex.EncodeToString(h[:])
}

func TestSecretIdentifierDerivationNoncePlusPayloadStoreAndRotate(t *testing.T) {
	s := newTestStoreState(t)

	issuerPub, issuerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	s.SetIdentityVerifier(&identity.IdentusVerifier{IssuerPubKey: issuerPub})

	bucketID := "bucket-derivation-nonce-plus-payload"
	if err := s.NewBucket(bucketID, []string{"health_record"}); err != nil {
		t.Fatalf("NewBucket: %v", err)
	}

	_, senderPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate sender key: %v", err)
	}
	senderPubHex := hex.EncodeToString(senderPriv.Public().(ed25519.PublicKey))
	subjectDID := "did:test:store-derivation"
	credSig := identusCredentialSig(issuerPriv, subjectDID, senderPubHex, bucketID)

	initialNonce := testNonce("store-1")
	initialPayload := json.RawMessage(`{"ciphertext":"AAA","iv":"111"}`)
	storeTx := buildStoreTx(t, tx.StoreTxTypeSecretStore, tx.SecretStoreData{
		BucketID:                       bucketID,
		SecretNonce:                    initialNonce,
		BeaconBlockHash:                testBeaconHash,
		BeaconBlockHeight:              testBeaconHeight,
		SubmissionIdentifierDerivation: tx.SubmissionIdentifierDerivationNoncePlusPayload,
		Timestamp:                      time.Now().Unix(),
		Category:                       "health_record",
		SealedPayload:                  initialPayload,
		SenderPubKey:                   senderPubHex,
		SenderSig:                      ed25519.Sign(senderPriv, []byte(initialNonce+":"+bucketID)),
		IdentusSubjectDID:              subjectDID,
		IdentusCredentialSig:           credSig,
	})

	if err := s.ValidateTx(storeTx); err != nil {
		t.Fatalf("ValidateTx (store): %v", err)
	}
	if _, err := s.ExecuteTx(storeTx); err != nil {
		t.Fatalf("ExecuteTx (store): %v", err)
	}

	expectedInitialID := computeSecretIDNoncePlusPayload(t, initialNonce, initialPayload)
	if !s.TwoListBase.HasSubmission(bucketID, expectedInitialID) {
		t.Fatalf("expected nonce_plus_payload secret ID %s to exist", expectedInitialID)
	}
	if s.TwoListBase.HasSubmission(bucketID, computeSecretID(initialNonce)) {
		t.Fatalf("unexpected nonce_only secret ID for nonce_plus_payload store")
	}

	rotatedNonce := testNonce("store-2")
	rotatedPayload := json.RawMessage(`{"ciphertext":"BBB","iv":"222"}`)
	rotateTx := buildStoreTx(t, tx.StoreTxTypeSecretRotate, tx.SecretRotateData{
		BucketID:                       bucketID,
		OldSecretID:                    expectedInitialID,
		NewSecretNonce:                 rotatedNonce,
		BeaconBlockHash:                testBeaconHash,
		BeaconBlockHeight:              testBeaconHeight,
		SubmissionIdentifierDerivation: tx.SubmissionIdentifierDerivationNoncePlusPayload,
		NewSealedPayload:               rotatedPayload,
		Timestamp:                      time.Now().Unix(),
		SenderPubKey:                   senderPubHex,
		SenderSig:                      ed25519.Sign(senderPriv, []byte("rotate:"+rotatedNonce+":"+bucketID)),
		IdentusSubjectDID:              subjectDID,
		IdentusCredentialSig:           credSig,
	})

	if err := s.ValidateTx(rotateTx); err != nil {
		t.Fatalf("ValidateTx (rotate): %v", err)
	}
	if _, err := s.ExecuteTx(rotateTx); err != nil {
		t.Fatalf("ExecuteTx (rotate): %v", err)
	}

	expectedRotatedID := computeSecretIDNoncePlusPayload(t, rotatedNonce, rotatedPayload)
	if !s.TwoListBase.HasSubmission(bucketID, expectedRotatedID) {
		t.Fatalf("expected nonce_plus_payload rotated secret ID %s to exist", expectedRotatedID)
	}
	if s.TwoListBase.HasSubmission(bucketID, expectedInitialID) {
		t.Fatalf("old secret ID still present after rotate")
	}
	if s.TwoListBase.HasSubmission(bucketID, computeSecretID(rotatedNonce)) {
		t.Fatalf("unexpected nonce_only rotated secret ID for nonce_plus_payload rotate")
	}
}
