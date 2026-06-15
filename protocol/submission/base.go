package submission

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	dbm "github.com/cometbft/cometbft-db"
	abcitypes "github.com/cometbft/cometbft/abci/types"
	cmtcrypto "github.com/cometbft/cometbft/proto/tendermint/crypto"
	"github.com/cometbft/cometbft/libs/log"

	"github.com/ShywareLLC/community/services/identity"
	"github.com/ShywareLLC/community/services/kms"
	"github.com/ShywareLLC/community/services/signer"
	"github.com/ShywareLLC/community/verify"
)

// TwoListBase is the generic two-list invariant base.
//
// Domain state machines (shychat, shystore) embed this type to inherit the
// structural protocol — atomic two-list writes, count-match enforcement, rolling
// and period-close attestation, write-only posture, DB persistence, and
// consensus validator management — without duplicating any of it.
//
// List 1 (submissions): "periodID:submissionID" → SubmissionRecord   — payload, no identity
// List 2 (participants): "periodID:identityHash" → ParticipantRecord — identity, no payload
//
// No join key between the two maps is ever written to canonical state.
type TwoListBase struct {
	db       dbm.DB
	logger   log.Logger
	signer   signer.Signer
	verifier identity.IdentityVerifier

	// In-memory state (flushed on Commit).
	submissions  map[string]*SubmissionRecord  // List 1: periodKey → SubmissionRecord
	participants map[string]*ParticipantRecord // List 2: periodKey → ParticipantRecord
	periods      map[string]*PeriodRecord
	closures     map[string]*ClosureRecord

	validators              map[string]*ValidatorRecord
	pendingValidatorUpdates []abcitypes.ValidatorUpdate

	// beaconWindow holds the BeaconWindowSize most recent block hashes keyed by
	// height. Populated by RecordBeacon on every FinalizeBlock. Submission
	// validators call ValidateBeacon against this window to prove that the
	// submission nonce was derived from publicly-committed canonical entropy.
	beaconWindow map[int64]string

	// writeOnly rejects submission updates when true (coercion_resistant posture
	// or runtime fallback signal). Enforced at the ABCI validation layer, not only
	// at the API layer.
	writeOnly bool

	// attestationMode controls when cryptographic attestations are committed.
	//   "rolling" (default): every rollingThreshold submissions per period.
	//   "period_close": only at explicit close.
	//   "none": no attestation — structural anonymity and recovery still enforced.
	attestationMode  string
	rollingThreshold int

	submissionCounts map[string]int                     // submissions since last rolling attestation, per period
	checkpoints      map[string][]*AttestationCheckpoint // rolling attestations per period

	Height  int64
	appHash []byte
	dirty   bool
}

// NewTwoListBase creates a new TwoListBase.
// If kmsKeyID is non-empty a KMS ECDSA signer is initialised; leave empty for local dev.
func NewTwoListBase(ctx context.Context, db dbm.DB, kmsKeyID string, logger log.Logger) (*TwoListBase, error) {
	b := &TwoListBase{
		db:               db,
		logger:           logger,
		submissions:      make(map[string]*SubmissionRecord),
		participants:     make(map[string]*ParticipantRecord),
		periods:          make(map[string]*PeriodRecord),
		closures:         make(map[string]*ClosureRecord),
		validators:       make(map[string]*ValidatorRecord),
		submissionCounts: make(map[string]int),
		checkpoints:      make(map[string][]*AttestationCheckpoint),
		beaconWindow:     make(map[int64]string),
		attestationMode:  "rolling",
		rollingThreshold: 100,
	}

	if kmsKeyID != "" {
		kmsSgn, err := kms.NewSigner(ctx, kmsKeyID)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize KMS signer: %w", err)
		}
		b.signer = kmsSgn
		logger.Info("KMS signer initialized (FIPS 140-2/3)", "key_id", kmsKeyID)
	} else {
		logger.Info("No KMS key ID provided — attestation signing will use SHA-256 stub")
	}

	if err := b.loadState(); err != nil {
		return nil, fmt.Errorf("failed to load state: %w", err)
	}
	return b, nil
}

// SetIdentityVerifier installs the IDV attestation verifier.
// Must be called before any submission transactions are processed.
func (b *TwoListBase) SetIdentityVerifier(v identity.IdentityVerifier) {
	b.verifier = v
}

// SetWriteOnly configures the base to reject submission updates at the ABCI
// validation layer. Call when shyconfig.deployment.default_posture is
// "coercion_resistant" or when a runtime fallback signal is detected.
func (b *TwoListBase) SetWriteOnly(v bool) {
	b.writeOnly = v
}

// IsWriteOnly returns the current write-only posture.
func (b *TwoListBase) IsWriteOnly() bool {
	return b.writeOnly
}

// SetAttestationMode configures how cryptographic attestations are committed.
//   - "rolling" (default): commit an AttestationCheckpoint every threshold submissions.
//   - "period_close": commit attestation only at explicit close.
//   - "none": no attestation — structural anonymity and recovery preserved.
func (b *TwoListBase) SetAttestationMode(mode string, threshold int) {
	b.attestationMode = mode
	if mode == "rolling" && threshold > 0 {
		b.rollingThreshold = threshold
	}
}

// GetInfo returns the current height and app hash.
func (b *TwoListBase) GetInfo() (int64, []byte) {
	return b.Height, b.appHash
}

// GetVerifier returns the configured identity verifier.
func (b *TwoListBase) GetVerifier() identity.IdentityVerifier {
	return b.verifier
}

// RecordBeacon stores the canonical block hash for the given height and prunes
// entries older than BeaconWindowSize blocks. Called from FinalizeBlock on
// every block so that submission validators can prove nonce independence from
// publicly-committed BFT entropy.
func (b *TwoListBase) RecordBeacon(height int64, blockHashHex string) {
	b.beaconWindow[height] = blockHashHex
	for h := range b.beaconWindow {
		if h < height-int64(BeaconWindowSize) {
			delete(b.beaconWindow, h)
		}
	}
}

// BeaconWindow returns the current rolling beacon window (height → hex hash).
// Validators pass this to ValidateBeacon to confirm a submission's beacon fields
// reference a committed canonical block.
func (b *TwoListBase) BeaconWindow() map[int64]string {
	return b.beaconWindow
}

// ---- Period lifecycle ----

// CreatePeriod registers a new period. Domain callers supply validated metadata.
// Returns ErrPeriodNotFound (inverted) if the period already exists.
func (b *TwoListBase) CreatePeriod(periodID, domainType string, startTime, endTime int64) error {
	if _, exists := b.periods[periodID]; exists {
		return fmt.Errorf("period %s already exists", periodID)
	}
	b.periods[periodID] = &PeriodRecord{
		PeriodID:   periodID,
		DomainType: domainType,
		StartTime:  startTime,
		EndTime:    endTime,
		Status:     "open",
		CreatedAt:  time.Now().Unix(),
	}
	b.dirty = true
	return nil
}

// GetPeriod returns the period record or nil if not found.
func (b *TwoListBase) GetPeriod(periodID string) *PeriodRecord {
	return b.periods[periodID]
}

// ---- Two-list write operations ----

// SubmitToLists atomically writes two disjoint records:
//   - List 1 (submissions): submissionKey(periodID, submissionID) → SubmissionRecord — payload, no identity
//   - List 2 (participants): participantKey(periodID, identityHash) → ParticipantRecord — identity, no payload
//
// Called by domain execute methods after identity verification has produced
// identityHash and the domain has derived submissionID = H(nonce).
//
// Returns ErrDuplicateParticipant if the identity_hash is already registered
// for this period (one submission per participant per period).
func (b *TwoListBase) SubmitToLists(
	ctx context.Context,
	periodID, submissionID, identityHash string,
	payload json.RawMessage,
	partitionID string,
) ([]abcitypes.Event, error) {
	return b.SubmitToListsWithSealedAttrs(ctx, periodID, submissionID, identityHash, payload, partitionID, nil)
}

// SubmitToListsWithSealedAttrs is identical to SubmitToLists but also stores
// optional sealed identity-side attributes in the List 2 ParticipantRecord.
//
// sealedL2Attrs, when non-nil, holds operator-facing attributes (network address,
// device-attestation evidence, geolocation, etc.) encrypted under a sealing key
// that is absent from canonical state. The identity commitment (identityHash)
// itself is always unsealed so deduplication and recovery remain intact.
// No join key is introduced: sealedL2Attrs carries no submission identifier.
func (b *TwoListBase) SubmitToListsWithSealedAttrs(
	ctx context.Context,
	periodID, submissionID, identityHash string,
	payload json.RawMessage,
	partitionID string,
	sealedL2Attrs json.RawMessage,
) ([]abcitypes.Event, error) {
	pKey := participantKey(periodID, identityHash)
	if _, exists := b.participants[pKey]; exists {
		return nil, &ErrDuplicateParticipant{PeriodID: periodID, IdentityHash: identityHash}
	}

	sKey := submissionKey(periodID, submissionID)

	// List 1: submission payload — no identity field.
	b.submissions[sKey] = &SubmissionRecord{
		SubmissionID: submissionID,
		Payload:      payload,
		PartitionID:  partitionID,
		Superseded:   false,
	}

	// List 2: participant identity — no payload field, no transactional metadata.
	// Height is intentionally absent so no field shared with L1 can pair records.
	// SealedAttributes, when provided, carries sealed identity-side attributes under
	// a key absent from canonical state; no submission identifier is included.
	b.participants[pKey] = &ParticipantRecord{
		IdentityHash:     identityHash,
		SealedAttributes: sealedL2Attrs,
	}

	b.dirty = true
	b.logger.Info("Submission accepted", "period_id", periodID, "submission_id", submissionID)

	events := []abcitypes.Event{
		{
			Type: "submission_accepted",
			Attributes: []abcitypes.EventAttribute{
				{Key: "period_id", Value: periodID, Index: true},
				{Key: "status", Value: "accepted", Index: false},
			},
		},
	}

	// Rolling attestation: commit a checkpoint every rollingThreshold submissions.
	if b.attestationMode == "rolling" && b.rollingThreshold > 0 {
		b.submissionCounts[periodID]++
		if b.submissionCounts[periodID] >= b.rollingThreshold {
			b.submissionCounts[periodID] = 0
			if cpEvents, err := b.CommitRollingAttestation(ctx, periodID); err != nil {
				b.logger.Error("rolling attestation failed", "period_id", periodID, "error", err)
			} else {
				events = append(events, cpEvents...)
			}
		}
	}

	return events, nil
}

// UpdateSubmission replaces a List 1 entry (direction change).
// List 2 is unchanged; |L1| is held constant.
// Returns ErrWriteOnlyPosture if write-only posture is active.
func (b *TwoListBase) UpdateSubmission(
	periodID, oldSubmissionID, newSubmissionID string,
	newPayload json.RawMessage,
) ([]abcitypes.Event, error) {
	if b.writeOnly {
		return nil, &ErrWriteOnlyPosture{}
	}

	oldKey := submissionKey(periodID, oldSubmissionID)
	if _, exists := b.submissions[oldKey]; !exists {
		return nil, fmt.Errorf("old_submission_id %s not found in period %s", oldSubmissionID, periodID)
	}

	delete(b.submissions, oldKey)
	newKey := submissionKey(periodID, newSubmissionID)
	b.submissions[newKey] = &SubmissionRecord{
		SubmissionID: newSubmissionID,
		Payload:      newPayload,
	}

	b.dirty = true
	b.logger.Info("Submission updated", "period_id", periodID,
		"old_submission_id", oldSubmissionID, "new_submission_id", newSubmissionID)

	return []abcitypes.Event{{
		Type: "submission_updated",
		Attributes: []abcitypes.EventAttribute{
			{Key: "period_id", Value: periodID, Index: true},
			{Key: "old_submission_id", Value: oldSubmissionID, Index: true},
			{Key: "new_submission_id", Value: newSubmissionID, Index: true},
		},
	}}, nil
}

// WithdrawFromLists deletes the submission from both lists (bilateral withdrawal).
// Both lists shrink by one; the count-match invariant is preserved.
// The participant leaves no on-chain trace. Off-chain receipt history is retained
// in the reconciling authority store.
func (b *TwoListBase) WithdrawFromLists(
	periodID, submissionID, identityHash string,
) ([]abcitypes.Event, error) {
	sKey := submissionKey(periodID, submissionID)
	pKey := participantKey(periodID, identityHash)

	if _, exists := b.submissions[sKey]; !exists {
		return nil, fmt.Errorf("submission_id %s not found in period %s", submissionID, periodID)
	}
	if _, exists := b.participants[pKey]; !exists {
		return nil, fmt.Errorf("participant %s not registered in period %s", identityHash, periodID)
	}

	delete(b.submissions, sKey)
	delete(b.participants, pKey)

	b.dirty = true
	b.logger.Info("Submission withdrawn", "period_id", periodID, "submission_id", submissionID)

	return []abcitypes.Event{{
		Type: "submission_withdrawn",
		Attributes: []abcitypes.EventAttribute{
			{Key: "period_id", Value: periodID, Index: true},
			{Key: "submission_id", Value: submissionID, Index: true},
		},
	}}, nil
}

// ---- Participant / submission guards (called by domain validators) ----

// HasParticipant returns true if the identity_hash is registered in List 2
// for the given period. Used for dedup checks in domain validators.
func (b *TwoListBase) HasParticipant(periodID, identityHash string) bool {
	_, exists := b.participants[participantKey(periodID, identityHash)]
	return exists
}

// HasSubmission returns true if the submission_id is present in List 1
// for the given period.
func (b *TwoListBase) HasSubmission(periodID, submissionID string) bool {
	_, exists := b.submissions[submissionKey(periodID, submissionID)]
	return exists
}

// SubmissionPresence returns {"exists": bool} for a given submissionID within a
// period. This is the boolean-only List 1 presence surface: the response carries
// no protocol payload, submission direction, participant identity commitment, or
// any value from which a participant-specific association is derivable. It is
// structurally incapable of returning direction regardless of access controls.
func (b *TwoListBase) SubmissionPresence(periodID, submissionID string) ([]byte, error) {
	_, exists := b.submissions[submissionKey(periodID, submissionID)]
	return json.Marshal(map[string]bool{"exists": exists})
}

// CountsForPeriod returns |L1| and |L2| for the given period.
func (b *TwoListBase) CountsForPeriod(periodID string) (l1, l2 int) {
	prefix := periodID + ":"
	for k := range b.submissions {
		if strings.HasPrefix(k, prefix) {
			l1++
		}
	}
	for k := range b.participants {
		if strings.HasPrefix(k, prefix) {
			l2++
		}
	}
	return
}

// ---- Period close + attestation ----

// ClosePeriod verifies count-match, signs a ClosureRecord, commits it, and
// marks the period closed. Returns ErrCountMismatch if |L1| ≠ |L2|.
//
// When attestationMode is "none" the closure is committed without a signature;
// the count-match invariant is still enforced.
func (b *TwoListBase) ClosePeriod(ctx context.Context, periodID string, closingHeight int64) (*ClosureRecord, []abcitypes.Event, error) {
	period, exists := b.periods[periodID]
	if !exists {
		return nil, nil, &ErrPeriodNotFound{PeriodID: periodID}
	}
	if period.Status == "closed" {
		return nil, nil, fmt.Errorf("period %s is already closed", periodID)
	}
	if _, exists := b.closures[periodID]; exists {
		return nil, nil, fmt.Errorf("closure record already exists for period %s", periodID)
	}

	submissionIDs, identityHashes := b.collectPeriodLists(periodID)
	total := int64(len(submissionIDs))

	if int64(len(identityHashes)) != total {
		return nil, nil, &ErrCountMismatch{
			PeriodID: periodID,
			L1Count:  len(submissionIDs),
			L2Count:  len(identityHashes),
		}
	}

	l1Root := computeMerkleRoot(submissionIDs)
	l2Root := computeMerkleRoot(identityHashes)

	var sig, pubKeyDER []byte
	var degraded bool

	if b.attestationMode != "none" {
		var err error
		sig, degraded, err = b.signClosurePayload(ctx, periodID, l1Root, l2Root, total)
		if err != nil {
			return nil, nil, fmt.Errorf("closure signing failed for period %s: %w", periodID, err)
		}
		if b.signer != nil && !degraded {
			pubKeyDER = b.signer.PublicKeyDER()
		}
	}

	closure := &ClosureRecord{
		PeriodID:            periodID,
		TotalSubmissions:    total,
		L1MerkleRoot:        l1Root,
		L2MerkleRoot:        l2Root,
		Signature:           sig,
		PublicKey:           pubKeyDER,
		AttestationDegraded: degraded,
		FinalizedAt:         time.Now().Unix(),
		Height:              closingHeight,
	}

	period.Status = "closed"
	b.closures[periodID] = closure
	b.dirty = true

	b.logger.Info("Period closed",
		"period_id", periodID,
		"total_submissions", total,
		"attestation_mode", b.attestationMode,
	)

	events := []abcitypes.Event{{
		Type: "period_closed",
		Attributes: []abcitypes.EventAttribute{
			{Key: "period_id", Value: periodID, Index: true},
			{Key: "total_submissions", Value: fmt.Sprintf("%d", total), Index: false},
			{Key: "l1_commitment", Value: fmt.Sprintf("%x", l1Root), Index: false},
			{Key: "l2_commitment", Value: fmt.Sprintf("%x", l2Root), Index: false},
			{Key: "finalized_at", Value: fmt.Sprintf("%d", closure.FinalizedAt), Index: false},
		},
	}}

	return closure, events, nil
}

// CommitRollingAttestation commits a cryptographic attestation checkpoint over
// the current two-list state without closing the period. Called automatically
// after every rollingThreshold submissions when attestationMode == "rolling".
func (b *TwoListBase) CommitRollingAttestation(ctx context.Context, periodID string) ([]abcitypes.Event, error) {
	submissionIDs, identityHashes := b.collectPeriodLists(periodID)
	total := int64(len(submissionIDs))

	if int64(len(identityHashes)) != total {
		return nil, &ErrCountMismatch{
			PeriodID: periodID,
			L1Count:  len(submissionIDs),
			L2Count:  len(identityHashes),
		}
	}

	l1Commitment := computeMerkleRoot(submissionIDs)
	l2Commitment := computeMerkleRoot(identityHashes)

	sig, degraded, err := b.signClosurePayload(ctx, periodID, l1Commitment, l2Commitment, total)
	if err != nil {
		return nil, fmt.Errorf("rolling attestation signing failed for period %s: %w", periodID, err)
	}

	var pubKeyDER []byte
	if b.signer != nil && !degraded {
		pubKeyDER = b.signer.PublicKeyDER()
	}

	seq := len(b.checkpoints[periodID])
	cp := &AttestationCheckpoint{
		PeriodID:            periodID,
		SequenceNumber:      seq,
		TotalSubmissions:    total,
		L1Commitment:        l1Commitment,
		L2Commitment:        l2Commitment,
		Signature:           sig,
		PublicKey:           pubKeyDER,
		AttestationDegraded: degraded,
		CommittedAt:         time.Now().Unix(),
		Height:              b.Height + 1,
	}
	b.checkpoints[periodID] = append(b.checkpoints[periodID], cp)
	b.dirty = true

	b.logger.Info("Rolling attestation committed",
		"period_id", periodID,
		"sequence", seq,
		"total_submissions", total,
	)

	return []abcitypes.Event{{
		Type: "rolling_attestation",
		Attributes: []abcitypes.EventAttribute{
			{Key: "period_id", Value: periodID, Index: true},
			{Key: "sequence", Value: fmt.Sprintf("%d", seq), Index: false},
			{Key: "total_submissions", Value: fmt.Sprintf("%d", total), Index: false},
			{Key: "l1_commitment", Value: fmt.Sprintf("%x", l1Commitment), Index: false},
			{Key: "l2_commitment", Value: fmt.Sprintf("%x", l2Commitment), Index: false},
		},
	}}, nil
}

// ---- Validator management ----

// RegisterValidator upserts or removes a consensus validator.
// Power > 0 upserts; Power == 0 removes. Queues a ValidatorUpdate for EndBlock.
func (b *TwoListBase) RegisterValidator(pubKeyBase64 string, power int64, name string) ([]abcitypes.Event, error) {
	raw, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("pub_key_base64 decode failed: %w", err)
	}

	if power == 0 {
		delete(b.validators, pubKeyBase64)
	} else {
		b.validators[pubKeyBase64] = &ValidatorRecord{
			PubKeyBase64: pubKeyBase64,
			Power:        power,
			Name:         name,
			Height:       b.Height,
		}
	}

	b.pendingValidatorUpdates = append(b.pendingValidatorUpdates, abcitypes.ValidatorUpdate{
		PubKey: cmtcrypto.PublicKey{
			Sum: &cmtcrypto.PublicKey_Ed25519{Ed25519: raw},
		},
		Power: power,
	})

	b.dirty = true

	return []abcitypes.Event{{
		Type: "validator_registered",
		Attributes: []abcitypes.EventAttribute{
			{Key: "pub_key", Value: pubKeyBase64},
			{Key: "power", Value: fmt.Sprintf("%d", power)},
			{Key: "name", Value: name},
		},
	}}, nil
}

// GetPendingValidatorUpdates returns all queued ValidatorUpdates and clears the slice.
func (b *TwoListBase) GetPendingValidatorUpdates() []abcitypes.ValidatorUpdate {
	updates := b.pendingValidatorUpdates
	b.pendingValidatorUpdates = nil
	return updates
}

// ---- DB persistence ----

// Commit persists all in-memory state to the DB and computes the app hash.
func (b *TwoListBase) Commit() ([]byte, error) {
	if !b.dirty {
		return b.appHash, nil
	}

	batch := b.db.NewBatch()
	defer batch.Close()

	for id, period := range b.periods {
		data, err := json.Marshal(period)
		if err != nil {
			return nil, fmt.Errorf("marshal period %s: %w", id, err)
		}
		if err := batch.Set([]byte("period:"+id), data); err != nil {
			return nil, err
		}
	}

	for k, sub := range b.submissions {
		data, err := json.Marshal(sub)
		if err != nil {
			return nil, fmt.Errorf("marshal submission %s: %w", k, err)
		}
		if err := batch.Set([]byte("submission:"+k), data); err != nil {
			return nil, err
		}
	}

	for k, part := range b.participants {
		data, err := json.Marshal(part)
		if err != nil {
			return nil, fmt.Errorf("marshal participant %s: %w", k, err)
		}
		if err := batch.Set([]byte("participant:"+k), data); err != nil {
			return nil, err
		}
	}

	for id, closure := range b.closures {
		data, err := json.Marshal(closure)
		if err != nil {
			return nil, fmt.Errorf("marshal closure %s: %w", id, err)
		}
		if err := batch.Set([]byte("closure:"+id), data); err != nil {
			return nil, err
		}
	}

	for pubKey, val := range b.validators {
		data, err := json.Marshal(val)
		if err != nil {
			return nil, fmt.Errorf("marshal validator %s: %w", pubKey, err)
		}
		if err := batch.Set([]byte("validator:"+pubKey), data); err != nil {
			return nil, err
		}
	}

	appHash, err := b.computeAppHash()
	if err != nil {
		return nil, fmt.Errorf("computing app hash: %w", err)
	}
	b.appHash = appHash
	b.Height++

	if err := batch.Set([]byte("height"), []byte(fmt.Sprintf("%d", b.Height))); err != nil {
		return nil, err
	}
	if err := batch.Set([]byte("app_hash"), b.appHash); err != nil {
		return nil, err
	}
	if err := batch.WriteSync(); err != nil {
		return nil, fmt.Errorf("failed to write batch: %w", err)
	}

	b.dirty = false
	b.logger.Info("State committed",
		"height", b.Height,
		"app_hash", fmt.Sprintf("%x", b.appHash[:8]),
		"periods", len(b.periods),
		"submissions", len(b.submissions),
		"participants", len(b.participants),
		"validators", len(b.validators),
	)
	return b.appHash, nil
}

// loadState reloads all TwoListBase state from the DB on startup.
func (b *TwoListBase) loadState() error {
	heightBytes, err := b.db.Get([]byte("height"))
	if err != nil {
		return err
	}
	if heightBytes != nil {
		if _, err := fmt.Sscanf(string(heightBytes), "%d", &b.Height); err != nil {
			return fmt.Errorf("parsing stored height: %w", err)
		}
	}

	appHashBytes, err := b.db.Get([]byte("app_hash"))
	if err != nil {
		return err
	}
	if appHashBytes != nil {
		b.appHash = appHashBytes
	}

	if err := b.loadPrefix("period:", func(key string, val []byte) error {
		var r PeriodRecord
		if err := json.Unmarshal(val, &r); err != nil {
			return err
		}
		b.periods[r.PeriodID] = &r
		return nil
	}); err != nil {
		return fmt.Errorf("loading periods: %w", err)
	}

	if err := b.loadPrefix("submission:", func(key string, val []byte) error {
		var r SubmissionRecord
		if err := json.Unmarshal(val, &r); err != nil {
			return err
		}
		b.submissions[key] = &r
		return nil
	}); err != nil {
		return fmt.Errorf("loading submissions: %w", err)
	}

	if err := b.loadPrefix("participant:", func(key string, val []byte) error {
		var r ParticipantRecord
		if err := json.Unmarshal(val, &r); err != nil {
			return err
		}
		b.participants[key] = &r
		return nil
	}); err != nil {
		return fmt.Errorf("loading participants: %w", err)
	}

	if err := b.loadPrefix("closure:", func(key string, val []byte) error {
		var r ClosureRecord
		if err := json.Unmarshal(val, &r); err != nil {
			return err
		}
		b.closures[r.PeriodID] = &r
		return nil
	}); err != nil {
		return fmt.Errorf("loading closures: %w", err)
	}

	if err := b.loadPrefix("validator:", func(_ string, val []byte) error {
		var r ValidatorRecord
		if err := json.Unmarshal(val, &r); err != nil {
			return err
		}
		b.validators[r.PubKeyBase64] = &r
		return nil
	}); err != nil {
		return fmt.Errorf("loading validators: %w", err)
	}

	b.logger.Info("State loaded",
		"height", b.Height,
		"periods", len(b.periods),
		"submissions", len(b.submissions),
		"participants", len(b.participants),
		"validators", len(b.validators),
	)
	return nil
}

// loadPrefix iterates all DB keys with the given prefix and calls fn with the
// suffix key and stored value.
func (b *TwoListBase) loadPrefix(prefix string, fn func(string, []byte) error) error {
	start := []byte(prefix)
	end := prefixEnd(start)
	it, err := b.db.Iterator(start, end)
	if err != nil {
		return err
	}
	defer it.Close()
	for ; it.Valid(); it.Next() {
		key := strings.TrimPrefix(string(it.Key()), prefix)
		if err := fn(key, it.Value()); err != nil {
			return fmt.Errorf("key %s: %w", it.Key(), err)
		}
	}
	return it.Error()
}

// computeAppHash hashes all state deterministically (sorted map keys).
func (b *TwoListBase) computeAppHash() ([]byte, error) {
	h := sha256.New()

	for _, k := range sortedKeys(b.periods) {
		data, err := json.Marshal(b.periods[k])
		if err != nil {
			return nil, fmt.Errorf("marshal period %s: %w", k, err)
		}
		h.Write(data)
	}
	for _, k := range sortedKeys(b.submissions) {
		data, err := json.Marshal(b.submissions[k])
		if err != nil {
			return nil, fmt.Errorf("marshal submission %s: %w", k, err)
		}
		h.Write(data)
	}
	for _, k := range sortedKeys(b.participants) {
		data, err := json.Marshal(b.participants[k])
		if err != nil {
			return nil, fmt.Errorf("marshal participant %s: %w", k, err)
		}
		h.Write(data)
	}
	for _, k := range sortedKeys(b.closures) {
		data, err := json.Marshal(b.closures[k])
		if err != nil {
			return nil, fmt.Errorf("marshal closure %s: %w", k, err)
		}
		h.Write(data)
	}
	for _, k := range sortedKeys(b.validators) {
		data, err := json.Marshal(b.validators[k])
		if err != nil {
			return nil, fmt.Errorf("marshal validator %s: %w", k, err)
		}
		h.Write(data)
	}
	return h.Sum(nil), nil
}

// ---- Internal helpers ----

// collectPeriodLists returns all submission IDs (List 1) and identity hashes
// (List 2) for a given period. Used by ClosePeriod and CommitRollingAttestation.
func (b *TwoListBase) collectPeriodLists(periodID string) (submissionIDs, identityHashes []string) {
	prefix := periodID + ":"
	for k, sub := range b.submissions {
		if strings.HasPrefix(k, prefix) && !sub.Superseded {
			submissionIDs = append(submissionIDs, sub.SubmissionID)
		}
	}
	for k, part := range b.participants {
		if strings.HasPrefix(k, prefix) {
			identityHashes = append(identityHashes, part.IdentityHash)
		}
	}
	return
}

// signClosurePayload builds the canonical signing payload and signs it.
// Returns (signature, degraded, error).
//   - degraded=false: KMS/HSM signed (auditable by the public key).
//   - degraded=true:  KMS unavailable; SHA-256 stub used. Canonical writes preserved.
func (b *TwoListBase) signClosurePayload(
	ctx context.Context,
	periodID string,
	l1Root, l2Root []byte,
	total int64,
) (sig []byte, degraded bool, err error) {
	payload := verify.BuildSigningPayload(l1Root, l2Root, total, nil)

	if b.signer != nil {
		sig, err = b.signer.Sign(ctx, payload)
		if err != nil {
			b.logger.Error("KMS signer unavailable — HSM-unavailability fallback to SHA-256 stub",
				"period_id", periodID, "error", err)
			return payload, true, nil
		}
		b.logger.Info("Closure signed", "period_id", periodID)
		return sig, false, nil
	}

	b.logger.Info("Closure signed (SHA-256 stub — no KMS key configured)", "period_id", periodID)
	return payload, false, nil
}

// computeMerkleRoot builds a binary Merkle tree over a set of string leaves.
// Leaves are sorted for determinism.
func computeMerkleRoot(items []string) []byte {
	if len(items) == 0 {
		return make([]byte, 32)
	}
	sort.Strings(items)
	leaves := make([][]byte, len(items))
	for i, item := range items {
		h := sha256.Sum256([]byte(item))
		leaves[i] = h[:]
	}
	for len(leaves) > 1 {
		var next [][]byte
		for i := 0; i < len(leaves); i += 2 {
			if i+1 < len(leaves) {
				combined := append(leaves[i], leaves[i+1]...)
				h := sha256.Sum256(combined)
				next = append(next, h[:])
			} else {
				next = append(next, leaves[i])
			}
		}
		leaves = next
	}
	return leaves[0]
}

// submissionKey returns the in-memory map key for a List 1 entry.
func submissionKey(periodID, submissionID string) string {
	return periodID + ":" + submissionID
}

// participantKey returns the in-memory map key for a List 2 entry.
func participantKey(periodID, identityHash string) string {
	return periodID + ":" + identityHash
}

// sortedKeys returns the sorted keys of any map[string]*.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// prefixEnd returns the first key lexicographically after all keys with the
// given prefix, for use as the upper bound in a DB iterator.
func prefixEnd(prefix []byte) []byte {
	end := make([]byte, len(prefix))
	copy(end, prefix)
	for i := len(end) - 1; i >= 0; i-- {
		end[i]++
		if end[i] != 0 {
			return end[:i+1]
		}
	}
	return nil
}
