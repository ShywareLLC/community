package tx

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Wire-format discriminators for shystore-v1 transactions.
// Scoped to the shystore domain state machine; values are reused independently
// across domains because each ABCI app dispatches from its own type set.
const (
	StoreTxTypeSecretStore       uint8 = 1 // store a secret — atomic List 1 + List 2 write
	StoreTxTypeSecretReveal      uint8 = 2 // reveal / read back a secret (off-chain receipt path)
	StoreTxTypeSecretRotate      uint8 = 3 // replace a secret (recoverable posture only)
	StoreTxTypeBucketClose       uint8 = 4 // close a bucket and commit attested closure record
	StoreTxTypeRegisterValidator uint8 = 5 // add or remove a consensus validator
	StoreTxTypeAdverseAction     uint8 = 6 // two-party threshold authority action on a store identity
)

// SecretStoreData submits a secret to a bucket.
//
// The structural anonymity contract mirrors BallotCastData / MessageDispatchData:
//   - SecretNonce is random; SecretID = H(SecretNonce) is unlinkable to IdentityHash.
//   - SenderSig = Ed25519.Sign(sk_s, SecretNonce + ":" + BucketID) proves device authorship.
//   - IDV attestation derives IdentityHash for List 2 dedup. The IDV cannot forge a
//     secret because it never holds sk_s and the SealedPayload is encrypted before broadcast.
//   - SealedPayload is AES-GCM encrypted by the sender using a participant-derived key;
//     the ABCI layer stores ciphertext in List 1 and never has access to the plaintext.
type SecretStoreData struct {
	BucketID                       string `json:"scoping_id"`
	SecretNonce                    string `json:"submission_nonce"`                               // random 32-byte hex; secret_id = H(beacon || nonce), unlinkable to identity
	BeaconBlockHash                string `json:"beacon_block_hash"`                          // hex-encoded hash of a recent canonical block
	BeaconBlockHeight              int64  `json:"beacon_block_height"`                        // height of the beacon block
	SubmissionIdentifierDerivation string `json:"submission_identifier_derivation,omitempty"` // "nonce_only" (default) or "nonce_plus_payload"
	Timestamp                      int64  `json:"timestamp"`
	PartitionID                    string `json:"partition_id,omitempty"` // "sealed" (default) | "public"

	// Category narrows the allowable secret type for this bucket per shyconfig.store.secret_categories.
	Category string `json:"category"` // e.g. "health_record" | "auth_seed_totp" | "arbitrary"

	// SealedPayload is JSON-encoded SealedSecretEnvelope (participant-derived key, AES-GCM).
	SealedPayload json.RawMessage `json:"sealed_payload"`

	// Device signature — oracle-forgery prevention.
	SenderPubKey string `json:"sender_pub_key"` // hex-encoded Ed25519 public key
	SenderSig    []byte `json:"sender_sig"`     // Ed25519 sig over SecretNonce + ":" + BucketID

	// IDV attestation.
	IdvAttestationSig []byte `json:"idv_attestation_sig,omitempty"`
}

// SecretRevealData requests retrieval of a stored secret via the reconciling path.
//
// The state machine does not return plaintext; it validates that the identity_hash
// is registered in List 2 for this bucket and emits a reveal_requested event that
// the off-chain reconciling authority processes to return the off-chain receipt
// containing the sealed payload.
type SecretRevealData struct {
	BucketID  string `json:"scoping_id"`
	SecretID  string `json:"submission_id"` // H(nonce) — the secret to reveal
	Timestamp int64  `json:"timestamp"`

	SenderPubKey string `json:"sender_pub_key"`
	SenderSig    []byte `json:"sender_sig"` // signs SecretID + ":" + BucketID

	IdvAttestationSig []byte `json:"idv_attestation_sig,omitempty"`
}

// SecretRotateData replaces a stored secret (key rotation / content update).
//
// Direction change analogue: OldSecretID is removed from List 1; a new entry
// keyed by H(NewSecretNonce) is written. List 2 is unchanged. |L1| is constant.
// Only valid when the bucket is not in write-only posture.
//
// SenderSig = Ed25519.Sign(sk_s, "rotate:" + NewSecretNonce + ":" + BucketID).
// The "rotate:" prefix prevents a SecretStore signature from replaying as a rotation.
type SecretRotateData struct {
	BucketID                       string          `json:"scoping_id"`
	OldSecretID                    string          `json:"old_submission_id"`                              // H(old_nonce)
	NewSecretNonce                 string          `json:"new_submission_nonce"`                           // random 32-byte hex; new_secret_id = H(beacon || new_nonce)
	BeaconBlockHash                string          `json:"beacon_block_hash"`                          // hex-encoded hash of a recent canonical block
	BeaconBlockHeight              int64           `json:"beacon_block_height"`                        // height of the beacon block
	SubmissionIdentifierDerivation string          `json:"submission_identifier_derivation,omitempty"` // "nonce_only" (default) or "nonce_plus_payload"
	NewSealedPayload               json.RawMessage `json:"new_sealed_payload"`
	Timestamp                      int64           `json:"timestamp"`

	SenderPubKey string `json:"sender_pub_key"`
	SenderSig    []byte `json:"sender_sig"` // signs "rotate:" + NewSecretNonce + ":" + BucketID

	IdvAttestationSig []byte `json:"idv_attestation_sig,omitempty"`
}

// BucketCloseData closes a bucket and commits the period-close attestation.
// Equivalent to PollCloseData / MailboxCloseData for the shystore domain.
type BucketCloseData struct {
	BucketID      string `json:"scoping_id"`
	ClosingHeight int64  `json:"closing_height"`
}

// StoreAdverseActionData carries a two-party threshold authority action against
// a store participant identity within a bucket. Both EligibilityAuth and
// ReconciliationAuth must be valid ed25519 signatures over the canonical action
// message for the transaction to commit. The resulting StoreActionRecord is
// written to the append-only authority-action log and never deleted.
//
// ActionType values: "suppress" | "restore"
//   - suppress: blocks SecretReveal for this identity in this bucket; the List 1
//               and List 2 entries remain in canonical state (no deletion) but
//               the reveal path is gated pending authority review.
//   - restore:  clears the suppression; reveals are permitted again.
//
// ReferencedActionID is optional. When set on a "restore" action, it must equal
// the ActionID of a prior "suppress" record in the log — making the appeal linkage
// explicit and on-chain verifiable.
type StoreAdverseActionData struct {
	ActionID           string `json:"action_id"`                       // H(ActionNonce) — caller-derived
	ActionNonce        string `json:"action_nonce"`                    // random nonce; action_id = H(nonce)
	BucketID           string `json:"scoping_id"`                       // scoping identifier
	IdentityHash       string `json:"identity_hash"`                   // target identity within the bucket
	ActionType         string `json:"action_type"`                     // "suppress" | "restore"
	ReferencedActionID string `json:"referenced_action_id,omitempty"` // for "restore": action_id being appealed
	EligibilityAuth    []byte `json:"eligibility_auth"`                // ed25519 sig from eligibility authority
	ReconciliationAuth []byte `json:"reconciliation_auth"`             // ed25519 sig from reconciling authority
	Reason             string `json:"reason"`                          // attestation reason; no PII
	Timestamp          int64  `json:"timestamp"`
}

// ValidateStoreTx performs stateless validation of a shystore transaction.
func ValidateStoreTx(t *Tx) error {
	validStoreTypes := map[uint8]bool{
		StoreTxTypeSecretStore:       true,
		StoreTxTypeSecretReveal:      true,
		StoreTxTypeSecretRotate:      true,
		StoreTxTypeBucketClose:       true,
		StoreTxTypeRegisterValidator: true,
		StoreTxTypeAdverseAction:     true,
	}
	if !validStoreTypes[t.Type] {
		return fmt.Errorf("invalid shystore transaction type: %d", t.Type)
	}
	if len(t.Signature) == 0 {
		return fmt.Errorf("missing transaction signature")
	}
	if len(t.Data) == 0 {
		return fmt.Errorf("missing transaction data")
	}

	switch t.Type {
	case StoreTxTypeSecretStore:
		var d SecretStoreData
		if err := json.Unmarshal(t.Data, &d); err != nil {
			return fmt.Errorf("invalid secret store data: %w", err)
		}
		if d.BucketID == "" {
			return fmt.Errorf("missing scoping_id")
		}
		if d.SecretNonce == "" {
			return fmt.Errorf("missing submission_nonce")
		}
		if d.Category == "" {
			return fmt.Errorf("missing category")
		}
		if d.SubmissionIdentifierDerivation != "" &&
			d.SubmissionIdentifierDerivation != SubmissionIdentifierDerivationNonceOnly &&
			d.SubmissionIdentifierDerivation != SubmissionIdentifierDerivationNoncePlusPayload {
			return fmt.Errorf("invalid submission_identifier_derivation")
		}
		if len(d.SealedPayload) == 0 {
			return fmt.Errorf("missing sealed_payload")
		}
		if d.SenderPubKey == "" {
			return fmt.Errorf("missing sender_pub_key")
		}
		if len(d.SenderSig) == 0 {
			return fmt.Errorf("missing sender_sig")
		}
		if len(d.IdvAttestationSig) == 0 {
			return fmt.Errorf("secret store must carry idv_attestation_sig")
		}

	case StoreTxTypeSecretReveal:
		var d SecretRevealData
		if err := json.Unmarshal(t.Data, &d); err != nil {
			return fmt.Errorf("invalid secret reveal data: %w", err)
		}
		if d.BucketID == "" {
			return fmt.Errorf("missing scoping_id")
		}
		if d.SecretID == "" {
			return fmt.Errorf("missing submission_id")
		}
		if d.SenderPubKey == "" {
			return fmt.Errorf("missing sender_pub_key")
		}
		if len(d.SenderSig) == 0 {
			return fmt.Errorf("missing sender_sig")
		}
		if len(d.IdvAttestationSig) == 0 {
			return fmt.Errorf("secret reveal must carry idv_attestation_sig")
		}

	case StoreTxTypeSecretRotate:
		var d SecretRotateData
		if err := json.Unmarshal(t.Data, &d); err != nil {
			return fmt.Errorf("invalid secret rotate data: %w", err)
		}
		if d.BucketID == "" {
			return fmt.Errorf("missing scoping_id")
		}
		if d.OldSecretID == "" {
			return fmt.Errorf("missing old_submission_id")
		}
		if d.NewSecretNonce == "" {
			return fmt.Errorf("missing new_submission_nonce")
		}
		if d.SubmissionIdentifierDerivation != "" &&
			d.SubmissionIdentifierDerivation != SubmissionIdentifierDerivationNonceOnly &&
			d.SubmissionIdentifierDerivation != SubmissionIdentifierDerivationNoncePlusPayload {
			return fmt.Errorf("invalid submission_identifier_derivation")
		}
		if d.SenderPubKey == "" {
			return fmt.Errorf("missing sender_pub_key")
		}
		if len(d.SenderSig) == 0 {
			return fmt.Errorf("missing sender_sig")
		}
		if len(d.IdvAttestationSig) == 0 {
			return fmt.Errorf("secret rotate must carry idv_attestation_sig")
		}

	case StoreTxTypeBucketClose:
		var d BucketCloseData
		if err := json.Unmarshal(t.Data, &d); err != nil {
			return fmt.Errorf("invalid bucket close data: %w", err)
		}
		if d.BucketID == "" {
			return fmt.Errorf("missing scoping_id")
		}

	case StoreTxTypeRegisterValidator:
		var d ValidatorRegistrationData
		if err := json.Unmarshal(t.Data, &d); err != nil {
			return fmt.Errorf("invalid validator registration data: %w", err)
		}
		raw, err := base64.StdEncoding.DecodeString(d.PubKeyBase64)
		if err != nil {
			return fmt.Errorf("pub_key_base64 is not valid base64: %w", err)
		}
		if len(raw) != 32 {
			return fmt.Errorf("pub_key_base64 must decode to 32 bytes (Ed25519), got %d", len(raw))
		}
		if d.Name == "" {
			return fmt.Errorf("missing validator name")
		}
		if d.Power < 0 {
			return fmt.Errorf("power must be >= 0")
		}

	case StoreTxTypeAdverseAction:
		var d StoreAdverseActionData
		if err := json.Unmarshal(t.Data, &d); err != nil {
			return fmt.Errorf("invalid store adverse action data: %w", err)
		}
		if d.ActionID == "" || d.ActionNonce == "" {
			return fmt.Errorf("store adverse action: action_id and action_nonce are required")
		}
		if d.BucketID == "" {
			return fmt.Errorf("store adverse action: bucket_id is required")
		}
		if d.IdentityHash == "" {
			return fmt.Errorf("store adverse action: identity_hash is required")
		}
		if d.Reason == "" {
			return fmt.Errorf("store adverse action: reason is required")
		}
		if d.Timestamp <= 0 {
			return fmt.Errorf("store adverse action: timestamp is required")
		}
		switch d.ActionType {
		case "suppress", "restore":
		default:
			return fmt.Errorf("store adverse action: unknown action_type %q (must be suppress or restore)", d.ActionType)
		}
		if len(d.EligibilityAuth) == 0 || len(d.ReconciliationAuth) == 0 {
			return fmt.Errorf("store adverse action: both eligibility_auth and reconciliation_auth are required")
		}
	}

	return nil
}
