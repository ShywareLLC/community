package types

// VotingMethod controls how ballots are validated and how the tally is computed.
//
//   - "plurality" (default): voter selects exactly one option. Standard FPTP.
//   - "approval":            voter selects any non-empty subset; each selected option counts +1.
//   - "ranked":              voter ranks options in preference order; first-choice counts stored
//     on-chain; full rankings in voteDirections for off-chain IRV.
const (
	VotingMethodPlurality = "plurality"
	VotingMethodApproval  = "approval"
	VotingMethodRanked    = "ranked"
)

// Poll represents a poll definition in the canonical state
type Poll struct {
	PollID       string   `json:"poll_id"`
	PollHash     string   `json:"poll_hash"` // Deterministic hash of poll parameters
	Question     string   `json:"question"`
	Options      []string `json:"options"`
	VotingMethod string   `json:"voting_method"` // "plurality" | "approval" | "ranked"
	StartTime    int64    `json:"start_time"`
	EndTime      int64    `json:"end_time"`
	Status       string   `json:"status"` // pending, open, closed
	CreatedAt    int64    `json:"created_at"`

	// EligibilityAuthorityPubKey and ReconcilingAuthorityPubKey together enable
	// TxTypeAuthorityRescind (two-party threshold rescission). Both must be
	// registered at poll creation or neither is accepted. Applicable only to
	// count-match deployments (shyvoting-v1, shywire-v1, shycustody-v1) where
	// count-match encodes a unique-person eligibility guarantee. Omit for
	// sealer-governed deployments (shychat-v1, shystore-v1). Immutable after
	// poll creation. Each is a base64-encoded raw 32-byte Ed25519 public key.
	//
	// EligibilityAuthorityPubKey: defaults to the operator; may be delegated
	// to any party (voter registration authority, KYC provider, etc.) by the
	// operator at poll creation. Signs rescission authorizations.
	//
	// ReconcilingAuthorityPubKey: the off-chain linkage store operator (e.g.,
	// CockroachDB). Resolves ballot_id from identity_hash and co-signs.
	// Neither authority can unilaterally produce a valid rescission transaction.
	EligibilityAuthorityPubKey string `json:"eligibility_authority_pub_key,omitempty"`
	ReconcilingAuthorityPubKey string `json:"reconciling_authority_pub_key,omitempty"`

	// SealedCount is the cardinality of the sealed partition — the number of
	// submissions that have been participant-migrated from the counted partition.
	// Incremented atomically when a TxTypeResealVote is executed. Sealed submissions
	// contribute to this counter and are excluded from all tally computations and
	// counted-partition count-match aggregations. The total participant cardinality
	// is always |L2| = counted-partition L1 count + SealedCount.
	SealedCount int64 `json:"sealed_count,omitempty"`

	// ReattestationCount is the number of ConfirmReceipt events accepted for this
	// poll. Incremented atomically on each successful TxTypeConfirmReceipt execution.
	// Capped at |L2| by the idempotency constraint and the voter-registry lookup in
	// validateConfirmReceipt — a second ConfirmReceipt for the same identity is
	// rejected, so ReattestationCount can never exceed the current voter count.
	// A persistent deficit (|L2| > ReattestationCount) is a verifiable on-chain
	// signal that some voters have not re-attested, surfaced through
	// /reattestation_audit/{poll_id} (Claim 11, Claim 49, Claim 65).
	ReattestationCount int64 `json:"reattestation_count,omitempty"`

	// IDVCastCount is the number of IDV-attested ballot-cast events accepted for
	// this poll. Incremented once per unique ballot accepted via executeBallotCast
	// or executeBatchFlush; ballot updates are not counted (they do not change |L2|).
	// At any point before rescissions: IDVCastCount == |L2|. After rescissions:
	// IDVCastCount > |L2|, signalling the divergence. Surfaced through
	// /idv_audit/{poll_id} as the fabrication-detection interface (Claim 13, Claim 49).
	IDVCastCount int64 `json:"idv_cast_count,omitempty"`
}

// VoteRecord is List 1 — an anonymous vote direction with no identity field.
// ballot_id = hash(BallotNonce) is random and unlinkable to IdentityHash.
//
// Choices contains one or more option names depending on VotingMethod:
//   - "plurality": exactly one element.
//   - "approval":  one or more elements (any subset the voter approves).
//   - "ranked":    one or more elements in the voter's preference order (rank 1 first).
//   - nil/empty:   structural abstention — the voter participated (entry exists in both
//     L1 and L2, count-match invariant holds) but cast no directional choice.
type VoteRecord struct {
	BallotID    string   `json:"ballot_id"` // hash(BallotNonce) — no identity encoded
	Choices     []string `json:"choices"`
	PartitionID string   `json:"partition_id,omitempty"` // "sealed" or "public" for audit partitioning
	Superseded  bool     `json:"superseded,omitempty"`   // true if this vote has been replaced (e.g., by reseal)
	// VoterPubKeyHash is a domain-separated hash of the Ed25519 public key used to
	// cast this ballot, computed as sha256("partition-migration-auth:" + voter_pub_key
	// + ":" + poll_id) at cast time. Stored exclusively to authenticate the
	// partition-migration path (TxTypeResealVote): the validator hashes the raw
	// voter_pub_key supplied in the migration transaction and compares to this field.
	// The raw public key is never written to canonical state, so this field cannot
	// be used to derive identity_hash = sha256(voter_pub_key || poll_id) from L1 alone.
	VoterPubKeyHash string `json:"voter_pub_key_hash,omitempty"`
}

// VoterRecord is List 2 — a participation record with no choice field.
//
//	identity_hash = ZK nullifier = MiMC(person_secret, poll_id)
//
// The nullifier is the on-chain dedup key. It is derived from the voter's
// device-bound person_secret and the poll_id, so it is unique per (voter, poll)
// without revealing the secret. Didit attests the commitment = MiMC(person_secret)
// via Ed25519 signature; the Groth16 proof binds nullifier and commitment.
// VoterRecord contains exactly one committed value field: the participant
// identity commitment. The transaction-scoping identifier is carried by the
// storage partition / keyspace rather than the committed record body. No
// transactional metadata (height, timestamp, sequence number) is recorded, so
// no field in List 2 correlates to any field exclusive to a List 1 record.
// This is the structural basis for the impossibility-of-pairing guarantee from
// canonical state alone.
type VoterRecord struct {
	IdentityHash string `json:"identity_hash"` // ZK nullifier = MiMC(person_secret, poll_id)
}

// Tally represents the final tally for a poll.
//
// On-chain invariant at close: TotalVotes == |L1| == |L2| == directional voters only.
// Voters who re-abstained (bilateral withdrawal) are not counted — both their L1 and
// L2 entries were deleted before close; no on-chain trace of participation remains.
// Abstain history is retained in the off-chain CRDB receipt store.
//
// KMS signs hash(VoteMerkleRoot || VoterMerkleRoot || TotalVotes).
type Tally struct {
	PollID          string           `json:"poll_id"`
	VotingMethod    string           `json:"voting_method"`     // "plurality" | "approval" | "ranked"
	Counts          map[string]int64 `json:"counts"`            // option → count (for "ranked": first-choice counts)
	TotalVotes      int64            `json:"total_votes"`       // |L1| = |L2| = directional voters
	ConfirmedCount  int64            `json:"confirmed_count"`   // voters who confirmed receipt during or after the active voting window
	VoteMerkleRoot  []byte           `json:"vote_merkle_root"`  // root of sorted ballot_ids (List 1)
	VoterMerkleRoot []byte           `json:"voter_merkle_root"` // root of sorted identity_hashes (List 2)
	Signature       []byte           `json:"signature"`         // KMS signature
	// PublicKey is the DER-encoded ECDSA public key used to produce Signature,
	// enabling any third party to verify without accessing the signing key.
	PublicKey   []byte `json:"public_key"`
	FinalizedAt int64  `json:"finalized_at"`
	Height      int64  `json:"height"`
	// AttestationDegraded is true when the period-close attestation was signed
	// with a SHA-256 stub because the HSM/KMS was unavailable at close time, OR
	// when one or more TxTypeAuthorityRescind transactions have been applied after
	// close (the original HSM signature no longer matches the post-rescission counts).
	// Canonical writes are preserved; the tally is final modulo rescissions.
	// Third-party verifiers should treat a degraded attestation as unauditable by
	// the HSM public key and instead verify using the append-only RescindRecords.
	AttestationDegraded bool `json:"attestation_degraded,omitempty"`
	// RescissionCount is the number of TxTypeAuthorityRescind transactions applied
	// to this poll after close. Zero for polls with no post-close rescissions.
	RescissionCount int64 `json:"rescission_count,omitempty"`
}

// AttestationCheckpoint is a rolling cryptographic attestation committed over
// the current two-list state during an active submission window.
// Unlike a final Tally it does not close the poll or expose directional counts.
// Multiple checkpoints may be committed per poll when attestation_mode is "rolling".
type AttestationCheckpoint struct {
	PollID              string `json:"poll_id"`
	SequenceNumber      int    `json:"sequence_number"`   // monotonically increasing per poll
	TotalSubmissions    int64  `json:"total_submissions"` // |L1| = |L2| at checkpoint time
	L1Commitment        []byte `json:"l1_commitment"`     // commitment over direction-free submission identifiers
	L2Commitment        []byte `json:"l2_commitment"`     // commitment over identity hashes
	Signature           []byte `json:"signature"`
	PublicKey           []byte `json:"public_key,omitempty"`
	AttestationDegraded bool   `json:"attestation_degraded,omitempty"`
	CommittedAt         int64  `json:"committed_at"`
	Height              int64  `json:"height"`
}

// RescindRecord is an append-only audit record committed when a TxTypeAuthorityRescind
// transaction is executed. It documents which ballot and identity were rescinded,
// by whom (off-chain revocation reference), and at which block height.
//
// RescindRecords are keyed in State.rescissions as "pollID:ballotID".
// They survive the deletion of the corresponding L1 and L2 entries — auditors
// can verify the count-match invariant by counting (|L1| + |rescinded|) == (|L2| + |rescinded|).
type RescindRecord struct {
	PollID        string `json:"poll_id"`
	BallotID      string `json:"ballot_id"`      // former L1 key suffix
	IdentityHash  string `json:"identity_hash"`  // former L2 key suffix
	RevocationRef string `json:"revocation_ref"` // eligibility authority case reference
	Height        int64  `json:"height"`
}

// ConfirmRecord records that a voter acknowledged their receipt during or after
// the active voting window.
// Keyed in State.confirms as "pollID:identityHash".
type ConfirmRecord struct {
	PollID       string `json:"poll_id"`
	IdentityHash string `json:"identity_hash"` // ZK nullifier = MiMC(person_secret, poll_id)
	Height       int64  `json:"height"`
}

// RestoreRecord is an append-only audit record committed when a
// TxTypeAuthorityRestore transaction is executed. It grants a wrongfully-rescinded
// participant permission to re-cast their ballot without bypassing the normal
// IDV re-attestation path. The re-cast is authorised by the presence of this
// record for the participant's identity hash; the state machine allows the
// BallotCast to proceed even though the L2 entry was deleted by the prior rescission.
// Keyed in State.restores as "pollID:identityHash".
type RestoreRecord struct {
	PollID        string `json:"poll_id"`
	BallotID      string `json:"ballot_id"`       // the original ballot_id that was rescinded
	IdentityHash  string `json:"identity_hash"`   // identity being restored
	RevocationRef string `json:"revocation_ref"`  // same binding as the rescission
	EligibilitySig []byte `json:"eligibility_sig"` // ed25519 sig from eligibility authority
	ReconcilingSig []byte `json:"reconciling_sig"` // ed25519 sig from reconciling authority
	Height        int64  `json:"height"`
}

// Errors

type ErrorInvalidPoll struct {
	Message string
}

func (e *ErrorInvalidPoll) Error() string {
	return e.Message
}

type ErrorDuplicateVote struct {
	PollID       string
	IdentityHash string
}

func (e *ErrorDuplicateVote) Error() string {
	return "duplicate vote: identity " + e.IdentityHash + " already voted in poll " + e.PollID
}
