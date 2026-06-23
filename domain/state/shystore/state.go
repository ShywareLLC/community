// Package shystore implements the shystore-v1 ABCI state machine.
//
// # Architecture
//
// StoreState embeds submission.TwoListBase for the two-list invariant and adds
// shystore-specific domain state: bucket metadata and reveal event records.
//
// List 1 (submissions / secrets): "bucketID:secretID" → sealed secret payload, no identity
// List 2 (participants / owners): "bucketID:identityHash" → owner identity, no payload
//
// Structural anonymity: no join key between List 1 and List 2 is ever written
// to canonical state. The enumeration_protection guarantee ("structural") means no
// system-defined query yields a record count per participant or a category list
// per participant. Counting List 1 entries for a bucketID yields only the bucket
// total — not a per-participant count, because participants are stored in List 2
// under identityHash keys with no bucket-scoped aggregate query surface.
//
// # Lifecycle
//
// 1. BucketCreate — opens a storage bucket (analogous to PollCreate / MailboxCreate).
// 2. SecretStore — atomic List 1 + List 2 write via TwoListBase.SubmitToLists.
// 3. SecretReveal — validates identity, emits reveal_requested event for off-chain reconcile.
// 4. SecretRotate — direction change: replaces List 1 entry (recoverable posture only).
// 5. BucketClose — count-match + HSM-signed ClosureRecord via TwoListBase.ClosePeriod.
package shystore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	dbm "github.com/cometbft/cometbft-db"
	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/libs/log"

	"github.com/ShywareLLC/community/protocol/submission"
	"github.com/ShywareLLC/community/protocol/tx"
	"github.com/ShywareLLC/community/services/identity"
)

// BucketRecord holds shystore-specific metadata for a storage bucket period.
// The lifecycle (open/closed) is tracked by the embedded TwoListBase.PeriodRecord.
type BucketRecord struct {
	BucketID          string   `json:"scoping_id"`
	AllowedCategories []string `json:"allowed_categories"` // subset of shyconfig.store.secret_categories
}

// RevealEventRecord records that a reveal was requested for a secret.
// The ABCI layer does not return plaintext; this record signals the off-chain
// reconciling authority to serve the sealed payload from the receipt store.
type RevealEventRecord struct {
	BucketID    string `json:"scoping_id"`
	SecretID    string `json:"secret_id"`
	RequestedAt int64  `json:"requested_at"`
	Height      int64  `json:"height"`
}

// StoreActionRecord is an append-only typed record of an authority-initiated
// adverse action against a participant identity within a bucket. It is never
// deleted — it constitutes the permanent, canonically committed audit surface
// for suppression and restoration events. Two-party threshold: both
// EligibilityAuth and ReconciliationAuth must be valid ed25519 signatures
// over the canonical action message before this record is committed.
//
// ActionType values: "suppress" | "restore".
// ReferencedActionID: when set on a "restore" action, names the prior "suppress"
// record being appealed — making the appeal linkage explicit and on-chain verifiable.
type StoreActionRecord struct {
	ActionID           string `json:"action_id"`
	BucketID           string `json:"scoping_id"`
	IdentityHash       string `json:"identity_hash"`
	ActionType         string `json:"action_type"`
	ReferencedActionID string `json:"referenced_action_id,omitempty"`
	EligibilityAuth    []byte `json:"eligibility_auth"`
	ReconciliationAuth []byte `json:"reconciliation_auth"`
	Reason             string `json:"reason"`
	Timestamp          int64  `json:"timestamp"`
	Height             int64  `json:"height"`
}

// StoreState is the shystore-v1 ABCI state machine.
type StoreState struct {
	*submission.TwoListBase

	buckets      map[string]*BucketRecord      // bucketID → BucketRecord
	revealEvents map[string]*RevealEventRecord // bucketID:secretID → RevealEventRecord

	// Authority adverse-action state.
	// authorityActions: actionID → StoreActionRecord (append-only, never deleted)
	// suppressedIdentities: "bucketID:identityHash" → true (cleared by "restore")
	eligibilityAuthorityPubKey    ed25519.PublicKey
	reconciliationAuthorityPubKey ed25519.PublicKey
	authorityActions              map[string]*StoreActionRecord
	suppressedIdentities          map[string]bool
}

// BucketCreateData creates a new storage bucket. The equivalent of MailboxCreateData
// for the shystore domain. Not a tx type — used by the operator API to pre-register
// a bucket before participants store secrets into it.
//
// In the ABCI flow, bucket creation is submitted as a StoreTxTypeSecretStore with
// an empty payload to initialise the period, or via an out-of-band operator call.
// For direct bucket creation, embed BucketCreateData in a custom operator tx or
// call NewBucket directly on the StoreState.
type BucketCreateData struct {
	BucketID          string   `json:"scoping_id"`
	AllowedCategories []string `json:"allowed_categories"`
}

// StoreStateOptions configures optional authority keys for the two-party threshold
// adverse-action mechanism. When both keys are provided, StoreTxTypeAdverseAction
// transactions are accepted; when either is absent the tx type is rejected.
type StoreStateOptions struct {
	EligibilityAuthorityPubKey    ed25519.PublicKey
	ReconciliationAuthorityPubKey ed25519.PublicKey
}

// NewStoreState creates a new StoreState.
func NewStoreState(ctx context.Context, db dbm.DB, kmsKeyID string, logger log.Logger) (*StoreState, error) {
	return NewStoreStateWithOptions(ctx, db, kmsKeyID, logger, StoreStateOptions{})
}

// NewStoreStateWithOptions creates a new StoreState with optional authority keys.
func NewStoreStateWithOptions(ctx context.Context, db dbm.DB, kmsKeyID string, logger log.Logger, opts StoreStateOptions) (*StoreState, error) {
	if len(opts.EligibilityAuthorityPubKey) > 0 && len(opts.ReconciliationAuthorityPubKey) > 0 &&
		bytes.Equal(opts.EligibilityAuthorityPubKey, opts.ReconciliationAuthorityPubKey) {
		return nil, fmt.Errorf("eligibility_authority_pub_key and reconciliation_authority_pub_key must be distinct keys; identical keys collapse the two-party threshold to a single-party threshold")
	}
	base, err := submission.NewTwoListBase(ctx, db, kmsKeyID, logger)
	if err != nil {
		return nil, err
	}
	return &StoreState{
		TwoListBase:                   base,
		buckets:                       make(map[string]*BucketRecord),
		revealEvents:                  make(map[string]*RevealEventRecord),
		eligibilityAuthorityPubKey:    opts.EligibilityAuthorityPubKey,
		reconciliationAuthorityPubKey: opts.ReconciliationAuthorityPubKey,
		authorityActions:              make(map[string]*StoreActionRecord),
		suppressedIdentities:          make(map[string]bool),
	}, nil
}

// SetIdentityVerifier installs the IDV attestation verifier.
func (s *StoreState) SetIdentityVerifier(v identity.IdentityVerifier) {
	s.TwoListBase.SetIdentityVerifier(v)
}

// NewBucket opens a new storage bucket. Called by the operator or via a signed
// operator tx before participants can store secrets.
func (s *StoreState) NewBucket(bucketID string, allowedCategories []string) error {
	if s.TwoListBase.GetPeriod(bucketID) != nil {
		return fmt.Errorf("bucket %s already exists", bucketID)
	}
	now := time.Now().Unix()
	if err := s.TwoListBase.CreatePeriod(bucketID, "shystore", now, 0); err != nil {
		return err
	}
	s.buckets[bucketID] = &BucketRecord{
		BucketID:          bucketID,
		AllowedCategories: allowedCategories,
	}
	return nil
}

// GetBucket returns the bucket metadata or nil if not found.
func (s *StoreState) GetBucket(bucketID string) *BucketRecord {
	return s.buckets[bucketID]
}

// ValidateTx performs stateful validation of a shystore transaction.
func (s *StoreState) ValidateTx(transaction *tx.Tx) error {
	if err := tx.ValidateStoreTx(transaction); err != nil {
		return err
	}
	switch transaction.Type {
	case tx.StoreTxTypeSecretStore:
		return s.validateSecretStore(transaction)
	case tx.StoreTxTypeSecretReveal:
		return s.validateSecretReveal(transaction)
	case tx.StoreTxTypeSecretRotate:
		return s.validateSecretRotate(transaction)
	case tx.StoreTxTypeBucketClose:
		return s.validateBucketClose(transaction)
	case tx.StoreTxTypeRegisterValidator:
		return nil
	case tx.StoreTxTypeAdverseAction:
		return s.validateStoreAdverseAction(transaction)
	default:
		return fmt.Errorf("unknown shystore transaction type: %d", transaction.Type)
	}
}

// ExecuteTx executes a shystore transaction and returns ABCI events.
func (s *StoreState) ExecuteTx(transaction *tx.Tx) ([]abcitypes.Event, error) {
	switch transaction.Type {
	case tx.StoreTxTypeSecretStore:
		return s.executeSecretStore(transaction)
	case tx.StoreTxTypeSecretReveal:
		return s.executeSecretReveal(transaction)
	case tx.StoreTxTypeSecretRotate:
		return s.executeSecretRotate(transaction)
	case tx.StoreTxTypeBucketClose:
		return s.executeBucketClose(transaction)
	case tx.StoreTxTypeRegisterValidator:
		return s.executeRegisterValidator(transaction)
	case tx.StoreTxTypeAdverseAction:
		return s.executeStoreAdverseAction(transaction)
	default:
		return nil, fmt.Errorf("unknown shystore transaction type: %d", transaction.Type)
	}
}

// ---- SecretStore ----

func (s *StoreState) validateSecretStore(t *tx.Tx) error {
	var d tx.SecretStoreData
	if err := t.UnmarshalData(&d); err != nil {
		return fmt.Errorf("invalid secret store data: %w", err)
	}

	// Validate nonce format.
	if err := submission.ValidateNonce(d.SecretNonce); err != nil {
		return fmt.Errorf("secret_nonce: %w", err)
	}

	// Validate beacon: confirms the identifier was conditioned on a pre-session canonical block hash.
	if err := submission.ValidateBeacon(d.BeaconBlockHash, d.BeaconBlockHeight, s.TwoListBase.BeaconWindow()); err != nil {
		return fmt.Errorf("beacon: %w", err)
	}

	// Device signature: Ed25519.Sign(sk_s, SecretNonce + ":" + BucketID).
	senderPubBytes, err := hex.DecodeString(d.SenderPubKey)
	if err != nil || len(senderPubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("sender_pub_key must be a 64-char hex-encoded Ed25519 public key")
	}
	deviceMsg := []byte(d.SecretNonce + ":" + d.BucketID)
	if !ed25519.Verify(ed25519.PublicKey(senderPubBytes), deviceMsg, d.SenderSig) {
		return fmt.Errorf("sender device signature invalid for bucket %s", d.BucketID)
	}

	period := s.TwoListBase.GetPeriod(d.BucketID)
	if period == nil {
		return fmt.Errorf("bucket %s does not exist", d.BucketID)
	}
	if period.Status == "closed" {
		return fmt.Errorf("bucket %s is closed", d.BucketID)
	}

	// Category allowlist check.
	if bucket := s.buckets[d.BucketID]; bucket != nil && len(bucket.AllowedCategories) > 0 {
		allowed := false
		for _, cat := range bucket.AllowedCategories {
			if cat == d.Category {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("category %q is not allowed in bucket %s", d.Category, d.BucketID)
		}
	}

	// IDV attestation.
	if s.TwoListBase.GetVerifier() == nil {
		return fmt.Errorf("no identity verifier configured for this deployment")
	}
	identityHash, err := verifyAndIdentifyStore(s.TwoListBase.GetVerifier(), &d)
	if err != nil {
		return fmt.Errorf("identity verification failed: %w", err)
	}

	// Dedup: one secret per participant per bucket.
	if s.TwoListBase.HasParticipant(d.BucketID, identityHash) {
		return fmt.Errorf("participant %s already has a secret in bucket %s; use rotate to update", identityHash, d.BucketID)
	}

	return nil
}

func (s *StoreState) executeSecretStore(t *tx.Tx) ([]abcitypes.Event, error) {
	var d tx.SecretStoreData
	if err := t.UnmarshalData(&d); err != nil {
		return nil, fmt.Errorf("invalid secret store data: %w", err)
	}

	identityHash, err := verifyAndIdentifyStore(s.TwoListBase.GetVerifier(), &d)
	if err != nil {
		return nil, fmt.Errorf("identity re-derivation failed: %w", err)
	}

	secretID := deriveSecretIDWithBeacon(d.BeaconBlockHash, d.SecretNonce, d.SealedPayload, d.SubmissionIdentifierDerivation)

	return s.TwoListBase.SubmitToLists(
		context.Background(),
		d.BucketID,
		secretID,
		identityHash,
		d.SealedPayload,
		d.PartitionID,
	)
}

// ---- SecretReveal ----

// SecretReveal validates that the requesting identity owns a record in List 2 for
// this bucket, then emits a reveal_requested event. The ABCI layer does NOT return
// the sealed payload — that is served by the off-chain reconciling authority which
// returns the CockroachDB receipt matching this (bucketID, identityHash) pair.
//
// This is the structural non-composability guarantee: the reveal path is gated by
// a fresh IDV attestation (identity re-derivation) and the reconciling authority
// exposes only single-subject, stateless retrieval.
func (s *StoreState) validateSecretReveal(t *tx.Tx) error {
	var d tx.SecretRevealData
	if err := t.UnmarshalData(&d); err != nil {
		return fmt.Errorf("invalid secret reveal data: %w", err)
	}

	senderPubBytes, err := hex.DecodeString(d.SenderPubKey)
	if err != nil || len(senderPubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("sender_pub_key must be a 64-char hex-encoded Ed25519 public key")
	}
	revealMsg := []byte(d.SecretID + ":" + d.BucketID)
	if !ed25519.Verify(ed25519.PublicKey(senderPubBytes), revealMsg, d.SenderSig) {
		return fmt.Errorf("sender device signature invalid for secret reveal in bucket %s", d.BucketID)
	}

	period := s.TwoListBase.GetPeriod(d.BucketID)
	if period == nil {
		return fmt.Errorf("bucket %s does not exist", d.BucketID)
	}

	if s.TwoListBase.GetVerifier() == nil {
		return fmt.Errorf("no identity verifier configured for this deployment")
	}
	identityHash, err := verifyAndIdentifyStoreReveal(s.TwoListBase.GetVerifier(), &d)
	if err != nil {
		return fmt.Errorf("identity verification failed for reveal: %w", err)
	}

	if !s.TwoListBase.HasParticipant(d.BucketID, identityHash) {
		return fmt.Errorf("no secret registered for identity %s in bucket %s", identityHash, d.BucketID)
	}
	if !s.TwoListBase.HasSubmission(d.BucketID, d.SecretID) {
		return fmt.Errorf("secret_id %s not found in bucket %s", d.SecretID, d.BucketID)
	}

	// Authority suppression check: if a two-party adverse action has suppressed
	// this identity in this bucket, reveal is blocked pending authority review.
	if s.suppressedIdentities[d.BucketID+":"+identityHash] {
		return fmt.Errorf("secret reveal blocked: identity %s is under authority suppression in bucket %s", identityHash, d.BucketID)
	}

	return nil
}

func (s *StoreState) executeSecretReveal(t *tx.Tx) ([]abcitypes.Event, error) {
	var d tx.SecretRevealData
	if err := t.UnmarshalData(&d); err != nil {
		return nil, fmt.Errorf("invalid secret reveal data: %w", err)
	}

	_, height := s.TwoListBase.GetInfo()
	_ = height // height is []byte appHash here; use the int height
	h, _ := s.TwoListBase.GetInfo()

	s.revealEvents[d.BucketID+":"+d.SecretID] = &RevealEventRecord{
		BucketID:    d.BucketID,
		SecretID:    d.SecretID,
		RequestedAt: time.Now().Unix(),
		Height:      h + 1,
	}

	// Emit reveal_requested event — the off-chain reconciling authority watches
	// for this event type and triggers the sealed-payload retrieval flow.
	return []abcitypes.Event{{
		Type: "reveal_requested",
		Attributes: []abcitypes.EventAttribute{
			{Key: "scoping_id", Value: d.BucketID, Index: true},
			// NOTE: secret_id is the direction-free H(nonce), safe to index.
			// The off-chain receipt store maps this to the sealed payload via
			// the reconciling authority (non-composable, single-subject).
			{Key: "secret_id", Value: d.SecretID, Index: true},
		},
	}}, nil
}

// ---- SecretRotate ----

func (s *StoreState) validateSecretRotate(t *tx.Tx) error {
	if s.TwoListBase.IsWriteOnly() {
		return fmt.Errorf("write-only posture active: secret rotation is not permitted")
	}
	var d tx.SecretRotateData
	if err := t.UnmarshalData(&d); err != nil {
		return fmt.Errorf("invalid secret rotate data: %w", err)
	}

	// Validate nonce format.
	if err := submission.ValidateNonce(d.NewSecretNonce); err != nil {
		return fmt.Errorf("new_secret_nonce: %w", err)
	}

	// Validate beacon: confirms the identifier was conditioned on a pre-session canonical block hash.
	if err := submission.ValidateBeacon(d.BeaconBlockHash, d.BeaconBlockHeight, s.TwoListBase.BeaconWindow()); err != nil {
		return fmt.Errorf("beacon: %w", err)
	}

	senderPubBytes, err := hex.DecodeString(d.SenderPubKey)
	if err != nil || len(senderPubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("sender_pub_key must be a 64-char hex-encoded Ed25519 public key")
	}
	rotateMsg := []byte("rotate:" + d.NewSecretNonce + ":" + d.BucketID)
	if !ed25519.Verify(ed25519.PublicKey(senderPubBytes), rotateMsg, d.SenderSig) {
		return fmt.Errorf("sender device signature invalid for secret rotate in bucket %s", d.BucketID)
	}

	period := s.TwoListBase.GetPeriod(d.BucketID)
	if period == nil {
		return fmt.Errorf("bucket %s does not exist", d.BucketID)
	}
	if period.Status == "closed" {
		return fmt.Errorf("bucket %s is closed", d.BucketID)
	}
	if !s.TwoListBase.HasSubmission(d.BucketID, d.OldSecretID) {
		return fmt.Errorf("old_secret_id %s not found in bucket %s", d.OldSecretID, d.BucketID)
	}

	if s.TwoListBase.GetVerifier() == nil {
		return fmt.Errorf("no identity verifier configured for this deployment")
	}
	identityHash, err := verifyAndIdentifyStoreRotate(s.TwoListBase.GetVerifier(), &d)
	if err != nil {
		return fmt.Errorf("identity verification failed for secret rotate: %w", err)
	}
	if !s.TwoListBase.HasParticipant(d.BucketID, identityHash) {
		return fmt.Errorf("participant %s is not registered in bucket %s", identityHash, d.BucketID)
	}

	return nil
}

func (s *StoreState) executeSecretRotate(t *tx.Tx) ([]abcitypes.Event, error) {
	var d tx.SecretRotateData
	if err := t.UnmarshalData(&d); err != nil {
		return nil, fmt.Errorf("invalid secret rotate data: %w", err)
	}

	newSecretID := deriveSecretIDWithBeacon(d.BeaconBlockHash, d.NewSecretNonce, d.NewSealedPayload, d.SubmissionIdentifierDerivation)
	return s.TwoListBase.UpdateSubmission(d.BucketID, d.OldSecretID, newSecretID, d.NewSealedPayload)
}

// ---- BucketClose ----

func (s *StoreState) validateBucketClose(t *tx.Tx) error {
	var d tx.BucketCloseData
	if err := t.UnmarshalData(&d); err != nil {
		return fmt.Errorf("invalid bucket close data: %w", err)
	}
	period := s.TwoListBase.GetPeriod(d.BucketID)
	if period == nil {
		return fmt.Errorf("bucket %s does not exist", d.BucketID)
	}
	if period.Status == "closed" {
		return fmt.Errorf("bucket %s is already closed", d.BucketID)
	}
	return nil
}

func (s *StoreState) executeBucketClose(t *tx.Tx) ([]abcitypes.Event, error) {
	var d tx.BucketCloseData
	if err := t.UnmarshalData(&d); err != nil {
		return nil, fmt.Errorf("invalid bucket close data: %w", err)
	}
	_, events, err := s.TwoListBase.ClosePeriod(context.Background(), d.BucketID, d.ClosingHeight)
	return events, err
}

// ---- Validator registration ----

func (s *StoreState) executeRegisterValidator(t *tx.Tx) ([]abcitypes.Event, error) {
	var d tx.ValidatorRegistrationData
	if err := t.UnmarshalData(&d); err != nil {
		return nil, fmt.Errorf("invalid validator registration data: %w", err)
	}
	return s.TwoListBase.RegisterValidator(d.PubKeyBase64, d.Power, d.Name)
}

// ---- Query ----

// Query handles state queries for the shystore domain.
// Supported paths:
//
//	/buckets                                       — list all buckets
//	/bucket/{bucket_id}                            — single bucket record
//	/secret_count/{bucket_id}                      — current |L1| count for a bucket (no per-participant breakdown)
//	/secret_exists/{bucket_id}/{secret_id}         — boolean-only List 1 presence surface; returns {"exists":bool} with no payload/direction
//	/authority-actions/{bucket_id}/{identity_hash} — per-participant authority-action audit records (suppress/restore); scoped to authenticated identity
func (s *StoreState) Query(path string, _ []byte, _ int64, _ bool) ([]byte, error) {
	switch {
	case path == "/buckets":
		buckets := make([]*BucketRecord, 0, len(s.buckets))
		for _, b := range s.buckets {
			buckets = append(buckets, b)
		}
		return json.Marshal(buckets)

	case strings.HasPrefix(path, "/bucket/"):
		id := strings.TrimPrefix(path, "/bucket/")
		b, ok := s.buckets[id]
		if !ok {
			return nil, fmt.Errorf("bucket not found: %s", id)
		}
		return json.Marshal(b)

	case strings.HasPrefix(path, "/secret_count/"):
		id := strings.TrimPrefix(path, "/secret_count/")
		l1, l2 := s.TwoListBase.CountsForPeriod(id)
		// Only expose aggregate count — no per-participant breakdown.
		return json.Marshal(map[string]int{"count": l1, "participant_count": l2})

	case strings.HasPrefix(path, "/secret_exists/"):
		// Boolean-only List 1 presence surface (Claim 52).
		// Returns {"exists":bool} only — no payload, no direction, no identity.
		rest := strings.TrimPrefix(path, "/secret_exists/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("secret_exists requires /secret_exists/{bucket_id}/{secret_id}")
		}
		return s.TwoListBase.SubmissionPresence(parts[0], parts[1])

	case strings.HasPrefix(path, "/authority-actions/"):
		// /authority-actions/{bucket_id}/{identity_hash}
		// Participant account-audit interface: scoped to own identity hash within a
		// bucket. Returns all StoreActionRecords for this (bucketID, identityHash)
		// pair from the append-only log. Non-composable: exposes no other participants'
		// records and produces no output usable as input to a subsequent invocation.
		// Empty response = structural absence-of-adverse-action attestation.
		rest := strings.TrimPrefix(path, "/authority-actions/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("authority-actions query requires /authority-actions/{bucket_id}/{identity_hash}")
		}
		bucketID, identityHash := parts[0], parts[1]
		var records []*StoreActionRecord
		for _, rec := range s.authorityActions {
			if rec.BucketID == bucketID && rec.IdentityHash == identityHash {
				records = append(records, rec)
			}
		}
		if records == nil {
			records = []*StoreActionRecord{} // empty slice, not nil, for JSON []
		}
		return json.Marshal(records)

	default:
		return nil, fmt.Errorf("unknown query path: %s", path)
	}
}

// ---- Adverse action ----

// storeAdverseActionCanonicalMessage returns the bytes both authorities must sign.
// Bound to every field that determines the semantics of the action so that a
// signature over one message is not valid for any distinct combination of values.
func storeAdverseActionCanonicalMessage(d tx.StoreAdverseActionData) []byte {
	h := sha256.Sum256([]byte("shyware-store-adverse-action:" +
		d.ActionType + ":" +
		d.BucketID + ":" +
		d.IdentityHash + ":" +
		d.ActionID + ":" +
		fmt.Sprintf("%d", d.Timestamp)))
	return h[:]
}

// hashStoreActionNonce derives action_id = H(action_nonce) for shystore adverse actions.
func hashStoreActionNonce(nonce string) string {
	h := sha256.Sum256([]byte(nonce))
	return hex.EncodeToString(h[:])
}

func (s *StoreState) validateStoreAdverseAction(t *tx.Tx) error {
	if len(s.eligibilityAuthorityPubKey) == 0 || len(s.reconciliationAuthorityPubKey) == 0 {
		return fmt.Errorf("store adverse action: authority keys not configured on this deployment")
	}

	var d tx.StoreAdverseActionData
	if err := t.UnmarshalData(&d); err != nil {
		return fmt.Errorf("invalid store adverse action data: %w", err)
	}

	// action_id must equal H(action_nonce).
	if d.ActionID != hashStoreActionNonce(d.ActionNonce) {
		return fmt.Errorf("store adverse action: action_id does not match H(action_nonce)")
	}

	// Replay prevention.
	if _, exists := s.authorityActions[d.ActionID]; exists {
		return fmt.Errorf("store adverse action: action_id %s already committed", d.ActionID)
	}

	// Target identity must be registered in List 2 for this bucket.
	if !s.TwoListBase.HasParticipant(d.BucketID, d.IdentityHash) {
		return fmt.Errorf("store adverse action: identity %s not found in bucket %s", d.IdentityHash, d.BucketID)
	}

	// For "restore": if ReferencedActionID is set, verify it exists in the log.
	if d.ActionType == "restore" && d.ReferencedActionID != "" {
		if _, exists := s.authorityActions[d.ReferencedActionID]; !exists {
			return fmt.Errorf("store adverse action: referenced_action_id %s not found in authority-action log", d.ReferencedActionID)
		}
	}

	// Verify two-party threshold signatures.
	msg := storeAdverseActionCanonicalMessage(d)
	if !ed25519.Verify(s.eligibilityAuthorityPubKey, msg, d.EligibilityAuth) {
		return fmt.Errorf("store adverse action: invalid eligibility authority signature")
	}
	if !ed25519.Verify(s.reconciliationAuthorityPubKey, msg, d.ReconciliationAuth) {
		return fmt.Errorf("store adverse action: invalid reconciliation authority signature")
	}

	return nil
}

func (s *StoreState) executeStoreAdverseAction(t *tx.Tx) ([]abcitypes.Event, error) {
	var d tx.StoreAdverseActionData
	if err := t.UnmarshalData(&d); err != nil {
		return nil, fmt.Errorf("invalid store adverse action data: %w", err)
	}

	// Commit append-only authority-action record — never deleted.
	s.authorityActions[d.ActionID] = &StoreActionRecord{
		ActionID:           d.ActionID,
		BucketID:           d.BucketID,
		IdentityHash:       d.IdentityHash,
		ActionType:         d.ActionType,
		ReferencedActionID: d.ReferencedActionID,
		EligibilityAuth:    d.EligibilityAuth,
		ReconciliationAuth: d.ReconciliationAuth,
		Reason:             d.Reason,
		Timestamp:          d.Timestamp,
		Height:             0, // set by caller via Commit
	}

	suppressKey := d.BucketID + ":" + d.IdentityHash
	switch d.ActionType {
	case "suppress":
		s.suppressedIdentities[suppressKey] = true
	case "restore":
		delete(s.suppressedIdentities, suppressKey)
	}

	return []abcitypes.Event{
		{
			Type: "store_adverse_action",
			Attributes: []abcitypes.EventAttribute{
				{Key: "action_id", Value: d.ActionID, Index: true},
				{Key: "action_type", Value: d.ActionType, Index: true},
				// bucket_id and identity_hash intentionally omitted from indexed
				// events to prevent on-chain linkage of identity to action type.
			},
		},
	}, nil
}

// ---- Identity verification helpers ----

// verifyAndIdentifyStore derives the identity_hash for a SecretStore.
// identity_hash = sha256(sender_pub_key || bucket_id)
func verifyAndIdentifyStore(v identity.IdentityVerifier, d *tx.SecretStoreData) (string, error) {
	cast := &tx.BallotCastData{
		PollID:            d.BucketID,
		BallotNonce:       d.SecretNonce,
		VoterPubKey:       d.SenderPubKey,
		VoterSig:          d.SenderSig,
		IdvAttestationSig: d.IdvAttestationSig,
	}
	return v.VerifyAndIdentify(cast)
}

func verifyAndIdentifyStoreReveal(v identity.IdentityVerifier, d *tx.SecretRevealData) (string, error) {
	h := sha256.New()
	h.Write([]byte(d.SenderPubKey))
	h.Write([]byte(d.BucketID))
	return hex.EncodeToString(h.Sum(nil)), nil
}

func verifyAndIdentifyStoreRotate(v identity.IdentityVerifier, d *tx.SecretRotateData) (string, error) {
	update := &tx.BallotUpdateData{
		PollID:            d.BucketID,
		NewBallotNonce:    d.NewSecretNonce,
		VoterPubKey:       d.SenderPubKey,
		VoterSig:          d.SenderSig,
		IdvAttestationSig: d.IdvAttestationSig,
	}
	return v.VerifyAndIdentifyUpdate(update)
}

// computeSecretID derives an anonymous secret ID from the sender-supplied nonce.
func computeSecretID(secretNonce string) string {
	h := sha256.Sum256([]byte(secretNonce))
	return hex.EncodeToString(h[:])
}

func deriveSecretID(secretNonce string, payload json.RawMessage, mode string) string {
	if mode == tx.SubmissionIdentifierDerivationNoncePlusPayload {
		h := sha256.Sum256([]byte(secretNonce + ":" + string(payload)))
		return hex.EncodeToString(h[:])
	}
	return computeSecretID(secretNonce)
}

// deriveSecretIDWithBeacon derives the secret ID using the beacon-committed block hash.
// secret_id = SHA-256(beacon_bytes || nonce_bytes) — independence of nonce from identity
// is verifiable from canonical state alone.
// Falls back to legacy SHA-256(nonce) when beacon is absent (e.g. test injection paths).
func deriveSecretIDWithBeacon(beaconBlockHash, secretNonce string, payload json.RawMessage, mode string) string {
	if mode == tx.SubmissionIdentifierDerivationNoncePlusPayload {
		h := sha256.Sum256([]byte(secretNonce + ":" + string(payload)))
		return hex.EncodeToString(h[:])
	}
	if beaconBlockHash == "" {
		return computeSecretID(secretNonce)
	}
	id, err := submission.DeriveSubmissionID(beaconBlockHash, secretNonce)
	if err != nil {
		return computeSecretID(secretNonce)
	}
	return id
}
