package tx

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Wire-format discriminators. Tx.Type must equal one of these values;
// any other value is rejected by Tx.Validate and state.ValidateTx.
const (
	TxTypePollCreate        uint8 = 1 // create a new poll
	TxTypeBallotCast        uint8 = 2 // ballot payload envelope; canonical materialization occurs via TxTypeBatchFlush
	TxTypePollClose         uint8 = 3 // close a poll and finalize the tally
	TxTypeRegisterValidator uint8 = 4 // add or remove a consensus validator
	TxTypeConfirmReceipt    uint8 = 5 // voter confirms their receipt during or after the active voting window (Sybil-audit signal)
	TxTypeUpdateBallot      uint8 = 6 // replace a previously cast ballot (recoverable-posture only)
	TxTypeBatchFlush        uint8 = 7 // atomically materialize a queued batch of ballot submissions
	TxTypeResealVote        uint8 = 8 // reseal a previously public vote (partition migration)
	TxTypeAuthorityRescind  uint8 = 9  // operator-delete rescission of a Sybil submission; only available in count-match deployments (OperatorRescindPubKey registered at poll creation)
	TxTypeAuthorityRestore  uint8 = 10 // two-party co-signed restoration authorization after wrongful rescission; grants re-cast permission without modifying L1/L2 directly
)

const (
	SubmissionIdentifierDerivationNonceOnly        = "nonce_only"
	SubmissionIdentifierDerivationNoncePlusPayload = "nonce_plus_payload"
)

// Tx is the canonical transaction envelope.
// Data is a JSON-encoded payload whose concrete type is determined by Type.
// Signature authenticates the transaction sender (validator key for governance
// transactions; voter device key for ballot transactions).
type Tx struct {
	Type      uint8           `json:"type"`      // wire-format discriminator; see TxType* constants
	Signature []byte          `json:"signature"` // sender authentication
	Data      json.RawMessage `json:"data"`      // JSON payload; decode with Tx.UnmarshalData
}

// PollCreateData contains data for creating a new poll.
// VotingMethod defaults to "plurality" when omitted.
//
// EligibilityAuthorityPubKeyBase64 and ReconcilingAuthorityPubKeyBase64 together
// enable the two-party threshold rescission path (TxTypeAuthorityRescind). Both
// must be provided together or neither; providing only one is rejected at
// validation. Applicable only to count-match deployments (shyvoting-v1,
// shywire-v1, shycustody-v1) where count-match encodes a unique-person eligibility
// guarantee and purchased-biometric / IDV-collusion / device-attestation-gap Sybil
// writes are material correctness threats. For sealer-governed deployments
// (shychat-v1, shystore-v1) where the sealer's access control is the operative
// guarantee, these fields must be omitted. When omitted, TxTypeAuthorityRescind is
// structurally unavailable for the poll.
//
// EligibilityAuthorityPubKeyBase64: the eligibility authority's Ed25519 public key.
// Defaults to the operator; may be delegated to any party (voter registration
// authority, KYC provider, court-designated eligibility officer) at poll creation.
//
// ReconcilingAuthorityPubKeyBase64: the reconciling authority's Ed25519 public key.
// The reconciling authority is the off-chain linkage store operator (e.g.,
// CockroachDB). It resolves ballot_id from identity_hash and co-signs rescissions.
//
// Both keys are base64-encoded raw 32-byte Ed25519 public keys, immutable after
// poll creation. Neither authority alone can produce a valid rescission transaction.
type PollCreateData struct {
	PollID       string   `json:"scoping_id"`
	Question     string   `json:"question"`
	Options      []string `json:"options"`
	VotingMethod string   `json:"voting_method"` // "plurality" | "approval" | "ranked"; default "plurality"
	StartTime    int64    `json:"start_time"`
	EndTime      int64    `json:"end_time"`

	// Two-party threshold rescission keys. Both or neither. See comment above.
	EligibilityAuthorityPubKeyBase64 string `json:"eligibility_authority_pub_key_base64,omitempty"`
	ReconcilingAuthorityPubKeyBase64 string `json:"reconciling_authority_pub_key_base64,omitempty"`
}

// BallotCastData contains data for casting a ballot.
//
// Three embodiments are supported. In all three, the voter device generates a
// per-poll Ed25519 keypair (sk_v, voter_pub_key) and signs ballotNonce:pollId
// with sk_v — this is the oracle-forgery prevention property: no IDV provider
// ever holds sk_v and therefore cannot forge a ballot.
//
// IDV attestation embodiment:
//
//	identity_hash = sha256(voter_pub_key || poll_id)
//	The IDV provider attests the voter's pub key by signing sha256(voter_pub_key || poll_id).
//	Required: VoterPubKey, VoterSig, IdvAttestationSig.
//
// High-assurance embodiment (ZK nullifier, loaded when zkVerifier is non-nil):
//
//	identity_hash = ZKNullifier = MiMC(person_secret, poll_id)
//	Groth16 proof binds nullifier and commitment to the same device-held secret.
//	Required: VoterPubKey, VoterSig, ZKNullifier, ZKNullifierProof,
//	          ZKCommitment, DiditCommitmentSig.
type BallotCastData struct {
	PollID                         string   `json:"scoping_id"`
	Choices                        []string `json:"choices"`                                    // 1 for plurality, subset for approval, ordered for ranked
	BallotNonce                    string   `json:"submission_nonce"`                           // random 32-byte hex; submission_id = H(beacon || nonce), unlinkable to identity_hash
	BeaconBlockHash                string   `json:"beacon_block_hash"`                          // hex-encoded hash of a recent canonical block; committed to canonical state before submission
	BeaconBlockHeight              int64    `json:"beacon_block_height"`                        // height of the beacon block; must be within the recent beacon window
	SubmissionIdentifierDerivation string   `json:"submission_identifier_derivation,omitempty"` // "nonce_only" (default) or "nonce_plus_payload"
	Timestamp                      int64    `json:"timestamp"`
	PartitionID                    string   `json:"partition_id,omitempty"` // "sealed" or "public" for audit partitioning

	// Device signature — required in all embodiments.
	// Proves only the submitting device could have produced this ballot.
	// VoterSig = Ed25519.Sign(sk_v, ballotNonce + ":" + poll_id).
	VoterPubKey string `json:"voter_pub_key"` // hex-encoded Ed25519 public key (32 bytes)
	VoterSig    []byte `json:"voter_sig"`     // Ed25519 signature over "ballotNonce:pollId"

	// IDV attestation — signs sha256(voter_pub_key || poll_id) to attest this keypair
	// belongs to a biometrically verified real person for this poll.
	// identity_hash = sha256(voter_pub_key || poll_id).
	IdvAttestationSig []byte `json:"idv_attestation_sig,omitempty"`

	// ZK fields — high-assurance embodiment (zkVerifier loaded).
	// When present, ZK verification supersedes the IdvAttestationSig check.
	// identity_hash = ZKNullifier = MiMC(person_secret, poll_id).
	ZKNullifier        string `json:"zk_nullifier,omitempty"`
	ZKNullifierProof   []byte `json:"zk_nullifier_proof,omitempty"`
	ZKCommitment       string `json:"zk_commitment,omitempty"`
	DiditCommitmentSig []byte `json:"didit_commitment_sig,omitempty"` // Ed25519 sig over sha256(zk_commitment || poll_id)

	// Wallet embodiment — EVM wallet identity (shyshares-v1 / DAO governance).
	// identity_hash = sha256(lowercase(wallet_address) + ":" + poll_id).
	// TODO(wallet-ecdsa): add WalletSig (personal_sign ownership proof).
	WalletAddress string `json:"wallet_address,omitempty"`
}

// PollCloseData contains data for closing a poll
type PollCloseData struct {
	PollID        string `json:"scoping_id"`
	ClosingHeight int64  `json:"closing_height"`
}

// BatchFlushData contains a deterministic batch of queued ballot submissions to
// be materialized atomically into canonical List 1 / List 2 state.
//
// Each embedded submission must be a TxTypeBallotCast envelope. The order of
// materialization is derived deterministically by the state machine from the
// direction-free submission identifiers, not from API ingress timing.
type BatchFlushData struct {
	PollID      string `json:"scoping_id"`
	Submissions []Tx   `json:"submissions"`
}

// BallotUpdateData replaces an existing ballot's choice.
//
// Security properties:
//   - VoterSig covers "update:" + NewBallotNonce + ":" + PollID, distinguishing
//     update messages from cast messages and preventing cross-type replay.
//   - OldBallotID is the direction-free H(old_nonce) already on-chain. For the
//     reconcileed API path, the server injects this from the CockroachDB receipt
//     store — the voter device never needs to hold it (receipts suppressed in
//     write-only posture). For the device-receipt API path, the client provides
//     it from their locally retained receipt.
//   - Identity attestation is identical to BallotCastData — the IDV still cannot
//     forge an update because it never holds sk_v.
//
// Only valid on polls in write-only=false (recoverable) posture. The state
// machine rejects TxTypeUpdateBallot if the posture is write-only.
type BallotUpdateData struct {
	PollID                         string   `json:"scoping_id"`
	OldBallotID                    string   `json:"old_submission_id"`                          // H(old_nonce); server fills for reconcileed path
	NewBallotNonce                 string   `json:"new_submission_nonce"`                       // random 32-byte hex; new_submission_id = H(beacon || new_nonce)
	BeaconBlockHash                string   `json:"beacon_block_hash"`                          // hex-encoded hash of a recent canonical block
	BeaconBlockHeight              int64    `json:"beacon_block_height"`                        // height of the beacon block
	SubmissionIdentifierDerivation string   `json:"submission_identifier_derivation,omitempty"` // "nonce_only" (default) or "nonce_plus_payload"
	NewChoices                     []string `json:"new_choices"`
	Timestamp                      int64    `json:"timestamp"`

	// Device signature — required in all embodiments.
	// VoterSig = Ed25519.Sign(sk_v, "update:" + NewBallotNonce + ":" + PollID).
	// The "update:" prefix prevents a BallotCast message from being replayed as an update.
	VoterPubKey string `json:"voter_pub_key"`
	VoterSig    []byte `json:"voter_sig"`

	// Identity attestation — same paths as BallotCastData.
	IdvAttestationSig  []byte `json:"idv_attestation_sig,omitempty"`
	ZKNullifier        string `json:"zk_nullifier,omitempty"`
	ZKNullifierProof   []byte `json:"zk_nullifier_proof,omitempty"`
	ZKCommitment       string `json:"zk_commitment,omitempty"`
	DiditCommitmentSig []byte `json:"didit_commitment_sig,omitempty"`
	WalletAddress      string `json:"wallet_address,omitempty"`
}

// ConfirmReceiptData contains data for confirming a voter's receipt during or
// after the active voting window.
//
// Security: the IDV attestation fields are required to prove a genuine biometric
// re-authentication session occurred.  A party who merely knows the identity_hash
// cannot submit a valid confirmation — the IDV must have re-signed for this confirmation
// context.  This makes the confirmed-count Sybil signal structural rather than
// behavioral: only a live participant can produce a fresh IDV attestation.
//
// The attestation message uses a "confirm:" prefix to prevent replay of cast-time
// attestations as confirmation transactions.
//
// IdentityHash is accepted from the client for routing/indexing; the state machine
// re-derives it from the attestation fields and rejects any mismatch.
type ConfirmReceiptData struct {
	PollID       string `json:"scoping_id"`
	IdentityHash string `json:"identity_hash"` // re-derived by state machine; client hint only

	// VoterPubKey is the hex-encoded Ed25519 public key used for this confirmation.
	// For biometric-recovery deployments this is re-derived from person_secret on
	// any device, so it matches the key attested at cast time.
	VoterPubKey string `json:"voter_pub_key"`

	// IDV attestation — signs sha256("confirm:" || voter_pub_key || poll_id).
	IdvAttestationSig []byte `json:"idv_attestation_sig,omitempty"`

	// ZK high-assurance embodiment.
	ZKNullifier        string `json:"zk_nullifier,omitempty"`
	ZKNullifierProof   []byte `json:"zk_nullifier_proof,omitempty"`
	ZKCommitment       string `json:"zk_commitment,omitempty"`
	DiditCommitmentSig []byte `json:"didit_commitment_sig,omitempty"` // signs sha256("confirm:" || zk_commitment || poll_id)

	// Wallet embodiment — EVM wallet identity (shyshares-v1).
	// identity_hash = sha256(lowercase(wallet_address) + ":" + poll_id).
	WalletAddress string `json:"wallet_address,omitempty"`
}

// ValidatorRegistrationData contains data for adding or removing a consensus validator.
// PubKeyBase64 is the base64-encoded raw 32-byte Ed25519 consensus public key,
// as reported by CometBFT at GET /status → result.validator_info.pub_key.value.
// Power > 0 adds the validator; Power == 0 removes it from the active set.
type ValidatorRegistrationData struct {
	PubKeyBase64 string `json:"pub_key_base64"` // 32-byte Ed25519 key, base64-encoded
	Power        int64  `json:"power"`          // voting power (>0 add, 0 remove)
	Name         string `json:"name"`           // human-readable label
}

// AuthorityRescindData carries an operator-delete rescission of a previously
// committed anonymous submission. This is a two-party threshold transaction:
// both the eligibility authority and the reconciling authority must sign the
// canonical rescission message:
//
//	"authority-rescind:" + PollID + ":" + BallotID + ":" + IdentityHash + ":" + RevocationRef
//
// The state machine verifies EligibilitySig against Poll.EligibilityAuthorityPubKey
// and ReconcilingSig against Poll.ReconcilingAuthorityPubKey, both registered at
// poll creation. Neither signature alone is sufficient.
//
// Applicable only to count-match deployments (shyvoting-v1, shywire-v1,
// shycustody-v1) where count-match encodes unique-person eligibility and
// purchased-biometric / IDV-collusion / device-attestation-gap Sybil writes are
// material threats. Sealer-governed deployments (shychat-v1, shystore-v1) do not
// register rescission keys; this transaction type is structurally unavailable.
//
// Rescission is valid on open and closed polls. On closed polls the tally's
// TotalVotes and per-option Counts are decremented, RescissionCount incremented,
// and AttestationDegraded set because the original HSM signature no longer matches.
type AuthorityRescindData struct {
	PollID        string `json:"scoping_id"`
	BallotID      string `json:"submission_id"`  // direction-free L1 key suffix; H(submission_nonce)
	IdentityHash  string `json:"identity_hash"`  // L2 key suffix; ZK nullifier or sha256(voter_pub_key || scoping_id)
	RevocationRef string `json:"revocation_ref"` // eligibility-authority-supplied revocation reference (opaque; bound in signed message)

	// Two-party threshold signatures over the canonical rescission message.
	// Both are required; either alone is rejected by the state machine.
	EligibilitySig []byte `json:"eligibility_sig"`  // Ed25519 sig from eligibility authority (defaults to operator; may be delegated)
	ReconcilingSig []byte `json:"reconciling_sig"`  // Ed25519 sig from reconciling authority (off-chain linkage store operator)
}

// ResealVoteData is the payload for TxTypeResealVote — participant-initiated
// partition migration. The participant provides the ballot_id of their previously
// cast counted-partition submission and a fresh device-side migration signature.
//
// The migration signature message is:
//
//	"migrate:" + BallotID + ":" + PollID
//
// The "migrate:" prefix prevents a BallotCast or BallotUpdate device signature from
// being replayed as a migration transaction. The state machine verifies MigrationSig
// against the VoterPubKey stored in the VoteRecord at cast time (Claim 47(a)).
//
// The migration is participant-initiated, requires no authority co-signature, and
// is operator-irreversible once committed (Claim 47(d)(iii)).
type ResealVoteData struct {
	PollID       string `json:"scoping_id"`     // transaction-scoping identifier
	BallotID     string `json:"submission_id"`  // direction-free L1 key already committed on-chain
	VoterPubKey  string `json:"voter_pub_key"`  // hex-encoded Ed25519 public key; must match VoteRecord.VoterPubKey
	MigrationSig []byte `json:"migration_sig"`  // Ed25519.Sign(sk_v, "migrate:" + BallotID + ":" + PollID)
	Timestamp    int64  `json:"timestamp"`
}

// AuthorityRestoreData carries a two-party co-signed restoration authorization
// after a wrongful rescission. It does not directly re-insert L1 or L2 entries;
// instead it commits an append-only RestoreRecord that grants the wrongfully-
// rescinded participant permission to re-cast their ballot through the normal
// BallotCast path, which enforces full IDV re-attestation. This preserves the
// count-match invariant throughout: the rescission already decremented both |L1|
// and |L2|; the re-cast increments both atomically.
//
// The canonical restore message is:
//
//	"authority-restore:" + PollID + ":" + BallotID + ":" + IdentityHash + ":" + RevocationRef
//
// binding the same four fields as the original rescission to prevent cross-event replay.
// Both EligibilitySig and ReconcilingSig are required.
type AuthorityRestoreData struct {
	PollID        string `json:"scoping_id"`
	BallotID      string `json:"submission_id"`  // the original submission_id that was rescinded
	IdentityHash  string `json:"identity_hash"`  // the identity being restored
	RevocationRef string `json:"revocation_ref"` // same binding as the rescission (cross-references the rescind record)

	// Two-party threshold signatures over the canonical restore message.
	EligibilitySig []byte `json:"eligibility_sig"`
	ReconcilingSig []byte `json:"reconciling_sig"`
}

// DecodeTx decodes a transaction from bytes
func DecodeTx(txBytes []byte) (*Tx, error) {
	var tx Tx
	if err := json.Unmarshal(txBytes, &tx); err != nil {
		return nil, fmt.Errorf("failed to decode transaction: %w", err)
	}
	return &tx, nil
}

// EncodeTx encodes a transaction to bytes
func EncodeTx(tx *Tx) ([]byte, error) {
	data, err := json.Marshal(tx)
	if err != nil {
		return nil, fmt.Errorf("failed to encode transaction: %w", err)
	}
	return data, nil
}

// Validate performs stateless validation of a transaction
func (tx *Tx) Validate() error {
	// Check transaction type
	if tx.Type != TxTypePollCreate && tx.Type != TxTypeBallotCast && tx.Type != TxTypePollClose &&
		tx.Type != TxTypeRegisterValidator && tx.Type != TxTypeConfirmReceipt &&
		tx.Type != TxTypeUpdateBallot && tx.Type != TxTypeBatchFlush &&
		tx.Type != TxTypeResealVote && tx.Type != TxTypeAuthorityRescind &&
		tx.Type != TxTypeAuthorityRestore {
		return fmt.Errorf("invalid transaction type: %d", tx.Type)
	}

	// Check signature exists
	if len(tx.Signature) == 0 {
		return fmt.Errorf("missing transaction signature")
	}

	// Check data exists
	if len(tx.Data) == 0 {
		return fmt.Errorf("missing transaction data")
	}

	// Type-specific validation
	switch tx.Type {
	case TxTypePollCreate:
		var data PollCreateData
		if err := json.Unmarshal(tx.Data, &data); err != nil {
			return fmt.Errorf("invalid poll create data: %w", err)
		}
		if data.PollID == "" {
			return fmt.Errorf("missing scoping_id")
		}
		if data.Question == "" {
			return fmt.Errorf("missing question")
		}
		if len(data.Options) < 2 {
			return fmt.Errorf("must have at least 2 options")
		}
		// Two-party rescission keys: both or neither.
		hasElig := data.EligibilityAuthorityPubKeyBase64 != ""
		hasReconcile := data.ReconcilingAuthorityPubKeyBase64 != ""
		if hasElig != hasReconcile {
			return fmt.Errorf("eligibility_authority_pub_key_base64 and reconciling_authority_pub_key_base64 must both be provided or both omitted")
		}
		for label, val := range map[string]string{
			"eligibility_authority_pub_key_base64":  data.EligibilityAuthorityPubKeyBase64,
			"reconciling_authority_pub_key_base64": data.ReconcilingAuthorityPubKeyBase64,
		} {
			if val == "" {
				continue
			}
			raw, err := base64.StdEncoding.DecodeString(val)
			if err != nil {
				return fmt.Errorf("%s is not valid base64: %w", label, err)
			}
			if len(raw) != 32 {
				return fmt.Errorf("%s must decode to 32 bytes (Ed25519), got %d", label, len(raw))
			}
		}

	case TxTypeBallotCast:
		var data BallotCastData
		if err := json.Unmarshal(tx.Data, &data); err != nil {
			return fmt.Errorf("invalid ballot cast data: %w", err)
		}
		if data.PollID == "" {
			return fmt.Errorf("missing scoping_id")
		}
		if len(data.Choices) == 0 {
			return fmt.Errorf("missing choices")
		}
		if data.BallotNonce == "" {
			return fmt.Errorf("missing submission_nonce")
		}
		if data.SubmissionIdentifierDerivation != "" &&
			data.SubmissionIdentifierDerivation != SubmissionIdentifierDerivationNonceOnly &&
			data.SubmissionIdentifierDerivation != SubmissionIdentifierDerivationNoncePlusPayload {
			return fmt.Errorf("invalid submission_identifier_derivation")
		}
		// Device signature required in both embodiments
		if data.VoterPubKey == "" {
			return fmt.Errorf("missing voter_pub_key")
		}
		if len(data.VoterSig) == 0 {
			return fmt.Errorf("missing voter_sig")
		}
		// At least one identity attestation path must be present
		hasZK := data.ZKNullifier != "" && len(data.ZKNullifierProof) > 0 &&
			data.ZKCommitment != "" && len(data.DiditCommitmentSig) > 0
		hasAttestationSig := len(data.IdvAttestationSig) > 0
		if !hasZK && !hasAttestationSig {
			return fmt.Errorf("ballot must carry idv_attestation_sig or full ZK fields (high-assurance)")
		}

	case TxTypeConfirmReceipt:
		var data ConfirmReceiptData
		if err := json.Unmarshal(tx.Data, &data); err != nil {
			return fmt.Errorf("invalid confirm receipt data: %w", err)
		}
		if data.PollID == "" {
			return fmt.Errorf("missing scoping_id")
		}
		if data.IdentityHash == "" {
			return fmt.Errorf("missing identity hash")
		}

	case TxTypePollClose:
		var data PollCloseData
		if err := json.Unmarshal(tx.Data, &data); err != nil {
			return fmt.Errorf("invalid poll close data: %w", err)
		}
		if data.PollID == "" {
			return fmt.Errorf("missing scoping_id")
		}

	case TxTypeRegisterValidator:
		var data ValidatorRegistrationData
		if err := json.Unmarshal(tx.Data, &data); err != nil {
			return fmt.Errorf("invalid validator registration data: %w", err)
		}
		raw, err := base64.StdEncoding.DecodeString(data.PubKeyBase64)
		if err != nil {
			return fmt.Errorf("pub_key_base64 is not valid base64: %w", err)
		}
		if len(raw) != 32 {
			return fmt.Errorf("pub_key_base64 must decode to 32 bytes (Ed25519), got %d", len(raw))
		}
		if data.Name == "" {
			return fmt.Errorf("missing validator name")
		}
		if data.Power < 0 {
			return fmt.Errorf("power must be >= 0")
		}

	case TxTypeUpdateBallot:
		var data BallotUpdateData
		if err := json.Unmarshal(tx.Data, &data); err != nil {
			return fmt.Errorf("invalid ballot update data: %w", err)
		}
		if data.PollID == "" {
			return fmt.Errorf("missing scoping_id")
		}
		if data.OldBallotID == "" {
			return fmt.Errorf("missing old_submission_id")
		}
		if data.NewBallotNonce == "" {
			return fmt.Errorf("missing new_submission_nonce")
		}
		if data.SubmissionIdentifierDerivation != "" &&
			data.SubmissionIdentifierDerivation != SubmissionIdentifierDerivationNonceOnly &&
			data.SubmissionIdentifierDerivation != SubmissionIdentifierDerivationNoncePlusPayload {
			return fmt.Errorf("invalid submission_identifier_derivation")
		}
		// len(data.NewChoices) == 0 is valid — bilateral withdrawal (re-abstain).
		// The state machine deletes the voter's L1 entry AND their L2 entry;
		// both lists shrink by one, invariant maintained, no on-chain trace remains.
		if data.VoterPubKey == "" {
			return fmt.Errorf("missing voter_pub_key")
		}
		if len(data.VoterSig) == 0 {
			return fmt.Errorf("missing voter_sig")
		}
		hasZK := data.ZKNullifier != "" && len(data.ZKNullifierProof) > 0 &&
			data.ZKCommitment != "" && len(data.DiditCommitmentSig) > 0
		hasAttestationSig := len(data.IdvAttestationSig) > 0
		if !hasZK && !hasAttestationSig {
			return fmt.Errorf("ballot update must carry idv_attestation_sig or full ZK fields (high-assurance)")
		}

	case TxTypeBatchFlush:
		var data BatchFlushData
		if err := json.Unmarshal(tx.Data, &data); err != nil {
			return fmt.Errorf("invalid batch flush data: %w", err)
		}
		if data.PollID == "" {
			return fmt.Errorf("missing scoping_id")
		}
		if len(data.Submissions) == 0 {
			return fmt.Errorf("missing submissions")
		}
		for i := range data.Submissions {
			if data.Submissions[i].Type != TxTypeBallotCast {
				return fmt.Errorf("batch flush submission %d must be TxTypeBallotCast", i)
			}
			if err := data.Submissions[i].Validate(); err != nil {
				return fmt.Errorf("invalid batch flush submission %d: %w", i, err)
			}
		}

	case TxTypeResealVote:
		var data ResealVoteData
		if err := json.Unmarshal(tx.Data, &data); err != nil {
			return fmt.Errorf("invalid reseal vote data: %w", err)
		}
		if data.PollID == "" {
			return fmt.Errorf("reseal vote: missing scoping_id")
		}
		if data.BallotID == "" {
			return fmt.Errorf("reseal vote: missing submission_id")
		}
		if data.VoterPubKey == "" {
			return fmt.Errorf("reseal vote: missing voter_pub_key")
		}
		if len(data.MigrationSig) == 0 {
			return fmt.Errorf("reseal vote: missing migration_sig")
		}
		rawPub, err := hex.DecodeString(data.VoterPubKey)
		if err != nil || len(rawPub) != 32 {
			return fmt.Errorf("reseal vote: voter_pub_key must be a 64-char hex-encoded Ed25519 public key")
		}

	case TxTypeAuthorityRescind:
		var data AuthorityRescindData
		if err := json.Unmarshal(tx.Data, &data); err != nil {
			return fmt.Errorf("invalid authority rescind data: %w", err)
		}
		if data.PollID == "" {
			return fmt.Errorf("missing scoping_id")
		}
		if data.BallotID == "" {
			return fmt.Errorf("missing submission_id")
		}
		if data.IdentityHash == "" {
			return fmt.Errorf("missing identity_hash")
		}
		if data.RevocationRef == "" {
			return fmt.Errorf("missing revocation_ref")
		}
		if len(data.EligibilitySig) == 0 {
			return fmt.Errorf("missing eligibility_sig")
		}
		if len(data.ReconcilingSig) == 0 {
			return fmt.Errorf("missing reconciling_sig")
		}

	case TxTypeAuthorityRestore:
		var data AuthorityRestoreData
		if err := json.Unmarshal(tx.Data, &data); err != nil {
			return fmt.Errorf("invalid authority restore data: %w", err)
		}
		if data.PollID == "" {
			return fmt.Errorf("authority restore: missing scoping_id")
		}
		if data.BallotID == "" {
			return fmt.Errorf("authority restore: missing submission_id")
		}
		if data.IdentityHash == "" {
			return fmt.Errorf("authority restore: missing identity_hash")
		}
		if data.RevocationRef == "" {
			return fmt.Errorf("authority restore: missing revocation_ref")
		}
		if len(data.EligibilitySig) == 0 {
			return fmt.Errorf("authority restore: missing eligibility_sig")
		}
		if len(data.ReconcilingSig) == 0 {
			return fmt.Errorf("authority restore: missing reconciling_sig")
		}
	}

	return nil
}

// UnmarshalData unmarshals transaction data into the provided struct
func (tx *Tx) UnmarshalData(v interface{}) error {
	return json.Unmarshal(tx.Data, v)
}
