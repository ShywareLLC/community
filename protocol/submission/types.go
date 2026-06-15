package submission

import "encoding/json"

// SubmissionRecord is a List 1 entry: domain payload with no identity field.
//
// SubmissionID = SHA-256(beacon_block_hash || nonce) — derived from a
// BFT-committed public beacon and a fresh nonce. Neither appears in canonical
// state; their hash is unlinkable to the participant without the off-chain
// reconciling authority.
//
// Payload is a domain-specific JSON value: a sealed message body for shychat,
// a sealed secret envelope for shystore, etc.
type SubmissionRecord struct {
	SubmissionID string          `json:"submission_id"` // H(beacon || nonce) — no identity encoded
	Payload      json.RawMessage `json:"payload"`       // domain-specific sealed content
	PartitionID  string          `json:"partition_id,omitempty"` // "sealed" | "public"
	Superseded   bool            `json:"superseded,omitempty"`
}

// ParticipantRecord is a List 2 entry: identity commitment with no payload field.
//
// Contains exactly one committed value: the participant identity hash. No
// transactional metadata (height, timestamp, sequence number) is stored, so no
// field in List 2 correlates to any field exclusive to a List 1 entry. This is
// the structural basis for the non-derivability guarantee from canonical state.
//
// SealedAttributes, when non-nil, holds operator-facing identity-side attributes
// (network address, device-attestation evidence, geolocation, or other
// operator-facing metadata) encrypted under a sealing key that is absent from
// canonical state and recoverable only through the non-composable reconciling
// interface on fresh biometric attestation. The participant identity commitment
// (IdentityHash) itself is always unsealed so deduplication and recovery remain
// intact. No join key is introduced: SealedAttributes carries no submission
// identifier and the sealed ciphertext is not derivable from any List 1 field.
type ParticipantRecord struct {
	IdentityHash     string          `json:"identity_hash"`
	SealedAttributes json.RawMessage `json:"sealed_attributes,omitempty"` // optional sealed L2 identity-side attributes; key absent from canonical state
}

// PeriodRecord holds the generic lifecycle fields shared by all domain periods:
// shychat mailboxes, shystore buckets, shyvoting polls (if migrated), etc.
//
// Domain-specific metadata (question/options for polls, label/address for mailboxes,
// category whitelist for buckets) is stored in domain-specific maps in the embedding
// state; PeriodRecord is the canonical lifecycle record in TwoListBase.
type PeriodRecord struct {
	PeriodID   string `json:"period_id"`
	DomainType string `json:"domain_type"` // "shychat" | "shystore" | "shyvoting"
	StartTime  int64  `json:"start_time"`
	EndTime    int64  `json:"end_time,omitempty"`
	Status     string `json:"status"` // "open" | "closed"
	CreatedAt  int64  `json:"created_at"`
}

// ClosureRecord is the final HSM-signed attestation committed when a period is
// closed. L1MerkleRoot is computed over sorted submission IDs (List 1);
// L2MerkleRoot is computed over sorted identity hashes (List 2).
//
// Signature covers H(L1MerkleRoot || L2MerkleRoot || TotalSubmissions).
// A third party with only the signing public key can verify the count-match
// invariant held at close without any access to submission payloads or identity data.
type ClosureRecord struct {
	PeriodID            string `json:"period_id"`
	TotalSubmissions    int64  `json:"total_submissions"` // |L1| = |L2| at close
	L1MerkleRoot        []byte `json:"l1_merkle_root"`
	L2MerkleRoot        []byte `json:"l2_merkle_root"`
	Signature           []byte `json:"signature"`
	PublicKey           []byte `json:"public_key,omitempty"`
	FinalizedAt         int64  `json:"finalized_at"`
	Height              int64  `json:"height"`
	AttestationDegraded bool   `json:"attestation_degraded,omitempty"`
}

// AttestationCheckpoint is a rolling cryptographic attestation committed over
// the current two-list state during an active period without closing it.
// Unlike ClosureRecord it does not expose aggregate counts or close the period.
// Multiple checkpoints may be committed per period when attestation_mode is "rolling".
type AttestationCheckpoint struct {
	PeriodID            string `json:"period_id"`
	SequenceNumber      int    `json:"sequence_number"`   // monotonically increasing per period
	TotalSubmissions    int64  `json:"total_submissions"` // |L1| = |L2| at checkpoint time
	L1Commitment        []byte `json:"l1_commitment"`     // commitment over submission IDs
	L2Commitment        []byte `json:"l2_commitment"`     // commitment over identity hashes
	Signature           []byte `json:"signature"`
	PublicKey           []byte `json:"public_key,omitempty"`
	AttestationDegraded bool   `json:"attestation_degraded,omitempty"`
	CommittedAt         int64  `json:"committed_at"`
	Height              int64  `json:"height"`
}

// ValidatorRecord holds the registered state of a CometBFT consensus validator.
type ValidatorRecord struct {
	PubKeyBase64 string `json:"pub_key_base64"` // base64 raw 32-byte Ed25519 key
	Power        int64  `json:"power"`
	Name         string `json:"name"`
	Height       int64  `json:"height"` // block height at which the record was last updated
}

// ErrCountMismatch is returned when |L1| ≠ |L2| at period close or rolling attestation.
type ErrCountMismatch struct {
	PeriodID string
	L1Count  int
	L2Count  int
}

func (e *ErrCountMismatch) Error() string {
	return "count-match invariant violated for period " + e.PeriodID +
		": l1=" + itoa(e.L1Count) + " l2=" + itoa(e.L2Count)
}

// ErrDuplicateParticipant is returned when an identity_hash is already registered
// for a period (one submission per participant per period).
type ErrDuplicateParticipant struct {
	PeriodID     string
	IdentityHash string
}

func (e *ErrDuplicateParticipant) Error() string {
	return "duplicate participant: identity " + e.IdentityHash + " already registered in period " + e.PeriodID
}

// ErrPeriodNotFound is returned when an operation references a period that does not exist.
type ErrPeriodNotFound struct {
	PeriodID string
}

func (e *ErrPeriodNotFound) Error() string {
	return "period not found: " + e.PeriodID
}

// ErrWriteOnlyPosture is returned when a submission update is attempted but
// write-only posture is active (coercion_resistant deployment or runtime fallback).
type ErrWriteOnlyPosture struct{}

func (e *ErrWriteOnlyPosture) Error() string {
	return "write-only posture active: submission updates are not permitted"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	buf := make([]byte, 0, 10)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if neg {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}
