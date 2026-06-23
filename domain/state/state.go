package state

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	dbm "github.com/cometbft/cometbft-db"
	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/libs/log"

	"github.com/ShywareLLC/community/services/identity"
	"github.com/ShywareLLC/community/services/kms"
	"github.com/ShywareLLC/community/services/signer"
	"github.com/ShywareLLC/community/protocol/submission"
	"github.com/ShywareLLC/community/protocol/tx"
	"github.com/ShywareLLC/community/protocol/types"
)

// State manages the canonical voting protocol state.
// All state transitions must be deterministic for consensus.
type State struct {
	db       dbm.DB
	logger   log.Logger
	signer   signer.Signer             // nil when no signing backend is configured (SHA-256 stub used)
	verifier identity.IdentityVerifier // required; set via SetIdentityVerifier before processing ballots

	// In-memory state (flushed on Commit).
	// Two separate maps enforce the anonymity separation on-chain:
	//   voteDirections (List 1): "pollID:ballotID" → VoteRecord  — choice only, no identity
	//   voterRegistry  (List 2): "pollID:identityHash" → VoterRecord — identity only, no choice
	polls          map[string]*types.Poll
	voteDirections map[string]*types.VoteRecord
	voterRegistry  map[string]*types.VoterRecord
	tallies        map[string]*types.Tally
	validators     map[string]*ValidatorRecord
	confirms       map[string]*types.ConfirmRecord  // "pollID:identityHash" → ConfirmRecord
	rescissions    map[string]*types.RescindRecord  // "pollID:ballotID" → RescindRecord (append-only audit log)
	restores       map[string]*types.RestoreRecord  // "pollID:identityHash" → RestoreRecord (append-only; grants re-cast permission)

	pendingValidatorUpdates []abcitypes.ValidatorUpdate

	// writeOnly is set when the deployment posture forbids ballot updates.
	// When true, TxTypeUpdateBallot is rejected at the ABCI validation layer
	// (Claim 6 — write-only enforcement structural, not caller-policy only).
	writeOnly bool

	// attestationMode controls when cryptographic attestations are committed.
	// "rolling" (default): attest every rollingThreshold submissions per poll.
	// "period_close": attest only at explicit close.
	// "none": no attestation — two-list invariant and recovery still enforced.
	attestationMode  string
	rollingThreshold int

	// submissionCounts tracks submissions since the last rolling attestation, per poll.
	submissionCounts map[string]int
	// checkpoints holds rolling attestations committed during active submission windows.
	checkpoints map[string][]*types.AttestationCheckpoint

	// beaconWindow holds the BeaconWindowSize most recent block hashes keyed by
	// height. Populated by RecordBeacon on every FinalizeBlock. Submission
	// validators call submission.ValidateBeacon against this window to prove that
	// the submission nonce was derived from publicly-committed canonical entropy,
	// making submission_id information-theoretically independent of identity inputs.
	beaconWindow map[int64]string

	height  int64
	appHash []byte
	dirty   bool
}

// NewState creates a new state manager.
//
// Signer resolution order (first non-nil/non-empty wins):
//  1. injectedSigner — caller-supplied signer.Signer (BYOL: GCP KMS, Vault, CloudHSM, etc.)
//  2. kmsKeyID — convenience: constructs an AWS KMS signer automatically
//  3. neither — SHA-256 stub (degraded, dev only)
//
// KMS construction is centralised here so no ABCI binary duplicates it.
func NewState(ctx context.Context, db dbm.DB, kmsKeyID string, injectedSigner signer.Signer, logger log.Logger) (*State, error) {
	s := &State{
		db:               db,
		logger:           logger,
		polls:            make(map[string]*types.Poll),
		voteDirections:   make(map[string]*types.VoteRecord),
		voterRegistry:    make(map[string]*types.VoterRecord),
		tallies:          make(map[string]*types.Tally),
		validators:       make(map[string]*ValidatorRecord),
		confirms:         make(map[string]*types.ConfirmRecord),
		rescissions:      make(map[string]*types.RescindRecord),
		restores:         make(map[string]*types.RestoreRecord),
		submissionCounts: make(map[string]int),
		checkpoints:      make(map[string][]*types.AttestationCheckpoint),
		attestationMode:  "rolling",
		rollingThreshold: 100,
		beaconWindow:     make(map[int64]string),
	}

	switch {
	case injectedSigner != nil:
		s.signer = injectedSigner
		logger.Info("BYOL signer injected", "type", fmt.Sprintf("%T", injectedSigner))
	case kmsKeyID != "":
		kmsSgn, err := kms.NewSigner(ctx, kmsKeyID)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize KMS signer: %w", err)
		}
		s.signer = kmsSgn
		logger.Info("AWS KMS signer initialized (FIPS 140-3 L3)", "key_id", kmsKeyID)
	default:
		logger.Info("No signer configured — tally signing will use SHA-256 stub (dev only)")
	}

	if err := s.loadState(); err != nil {
		return nil, fmt.Errorf("failed to load state: %w", err)
	}

	return s, nil
}

// GetInfo returns the current height and app hash.
func (s *State) GetInfo() (int64, []byte) {
	return s.height, s.appHash
}

// RecordBeacon records a block hash into the beacon window after each FinalizeBlock.
// Call from app.FinalizeBlock before returning — pass req.Height and hex(req.Hash).
// The window retains the most recent submission.BeaconWindowSize entries; older
// entries are pruned so the map stays bounded.
func (s *State) RecordBeacon(height int64, blockHashHex string) {
	s.beaconWindow[height] = blockHashHex
	// Prune entries older than BeaconWindowSize blocks.
	for h := range s.beaconWindow {
		if h < height-int64(submission.BeaconWindowSize) {
			delete(s.beaconWindow, h)
		}
	}
}

// BeaconWindow returns a read-only copy of the current beacon window.
// Used by validators; do not modify the returned map.
func (s *State) BeaconWindow() map[int64]string {
	return s.beaconWindow
}

// SetIdentityVerifier installs the IDV attestation verifier.
// Must be called before any ballot transactions are processed.
// The verifier is a deployment-time choice orthogonal to the voting type set —
// use identity.DiditVerifier, identity.ZKVerifier, identity.IdentusVerifier,
// or identity.WalletVerifier depending on the shyconfig identity_binding_mode.
func (s *State) SetIdentityVerifier(v identity.IdentityVerifier) {
	s.verifier = v
}

// SetAttestationMode configures how the state machine commits cryptographic
// attestations over the two-list state.
//   - "rolling" (default): commit an AttestationCheckpoint every threshold submissions.
//   - "period_close": commit attestation only when an explicit close transaction arrives.
//   - "none": no attestation committed; two-list invariant and recovery are preserved.
func (s *State) SetAttestationMode(mode string, threshold int) {
	s.attestationMode = mode
	if mode == "rolling" && threshold > 0 {
		s.rollingThreshold = threshold
	}
}

// SetWriteOnly configures the state machine to reject TxTypeUpdateBallot at the
// ABCI validation layer. Call at startup when the shyconfig deployment posture is
// "coercion_resistant" or when a runtime fallback signal is detected.
// This enforces write-only posture structurally (Claim 6), not just at the API layer.
func (s *State) SetWriteOnly(v bool) {
	s.writeOnly = v
}

// SetPollForTest injects a poll directly into state, bypassing validatePollCreate.
// Use in integration tests to create polls with past start times (already open).
// Not for production use.
func (s *State) SetPollForTest(pollID string, poll *types.Poll) {
	s.polls[pollID] = poll
}

// ValidateTx performs stateful validation of a transaction.
func (s *State) ValidateTx(transaction *tx.Tx) error {
	switch transaction.Type {
	case tx.TxTypePollCreate:
		return s.validatePollCreate(transaction)
	case tx.TxTypeBallotCast:
		return fmt.Errorf("direct ballot materialization disabled: submit ballots through the queued API and flush via batch transaction")
	case tx.TxTypePollClose:
		return s.validatePollClose(transaction)
	case tx.TxTypeRegisterValidator:
		return s.validateValidatorRegister(transaction)
	case tx.TxTypeConfirmReceipt:
		return s.validateConfirmReceipt(transaction)
	case tx.TxTypeUpdateBallot:
		return s.validateBallotUpdate(transaction)
	case tx.TxTypeBatchFlush:
		return s.validateBatchFlush(transaction)
	case tx.TxTypeResealVote:
		return s.validateResealVote(transaction)
	case tx.TxTypeAuthorityRescind:
		return s.validateAuthorityRescind(transaction)
	case tx.TxTypeAuthorityRestore:
		return s.validateAuthorityRestore(transaction)
	default:
		return fmt.Errorf("unknown transaction type: %d", transaction.Type)
	}
}

// ExecuteTx executes a transaction and returns events.
func (s *State) ExecuteTx(transaction *tx.Tx) ([]abcitypes.Event, error) {
	switch transaction.Type {
	case tx.TxTypePollCreate:
		return s.executePollCreate(transaction)
	case tx.TxTypeBallotCast:
		return nil, fmt.Errorf("direct ballot materialization disabled: submit ballots through the queued API and flush via batch transaction")
	case tx.TxTypePollClose:
		return s.executePollClose(transaction)
	case tx.TxTypeRegisterValidator:
		return s.executeValidatorRegister(transaction)
	case tx.TxTypeConfirmReceipt:
		return s.executeConfirmReceipt(transaction)
	case tx.TxTypeUpdateBallot:
		return s.executeBallotUpdate(transaction)
	case tx.TxTypeBatchFlush:
		return s.executeBatchFlush(transaction)
	case tx.TxTypeResealVote:
		return s.executeResealVote(transaction)
	case tx.TxTypeAuthorityRescind:
		return s.executeAuthorityRescind(transaction)
	case tx.TxTypeAuthorityRestore:
		return s.executeAuthorityRestore(transaction)
	default:
		return nil, fmt.Errorf("unknown transaction type: %d", transaction.Type)
	}
}

// Commit persists state to database and computes app hash.
func (s *State) Commit() ([]byte, error) {
	if !s.dirty {
		return s.appHash, nil
	}

	batch := s.db.NewBatch()
	defer batch.Close()

	for pollID, poll := range s.polls {
		data, err := json.Marshal(poll)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal poll %s: %w", pollID, err)
		}
		if err := batch.Set([]byte("poll:"+pollID), data); err != nil {
			return nil, err
		}
	}

	for ballotID, vote := range s.voteDirections {
		data, err := json.Marshal(vote)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal vote direction %s: %w", ballotID, err)
		}
		if err := batch.Set([]byte("vote:"+ballotID), data); err != nil {
			return nil, err
		}
	}

	for registryKey, voter := range s.voterRegistry {
		data, err := json.Marshal(voter)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal voter record %s: %w", registryKey, err)
		}
		if err := batch.Set([]byte("voter:"+registryKey), data); err != nil {
			return nil, err
		}
	}

	for tallyID, tally := range s.tallies {
		data, err := json.Marshal(tally)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal tally %s: %w", tallyID, err)
		}
		if err := batch.Set([]byte("tally:"+tallyID), data); err != nil {
			return nil, err
		}
	}

	for pubKey, val := range s.validators {
		data, err := json.Marshal(val)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal validator %s: %w", pubKey, err)
		}
		if err := batch.Set([]byte("validator:"+pubKey), data); err != nil {
			return nil, err
		}
	}

	for confirmKey, rec := range s.confirms {
		data, err := json.Marshal(rec)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal confirm record %s: %w", confirmKey, err)
		}
		if err := batch.Set([]byte("confirm:"+confirmKey), data); err != nil {
			return nil, err
		}
	}

	for rescindKey, rec := range s.rescissions {
		data, err := json.Marshal(rec)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal rescind record %s: %w", rescindKey, err)
		}
		if err := batch.Set([]byte("rescind:"+rescindKey), data); err != nil {
			return nil, err
		}
	}

	for restoreKey, rec := range s.restores {
		data, err := json.Marshal(rec)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal restore record %s: %w", restoreKey, err)
		}
		if err := batch.Set([]byte("restore:"+restoreKey), data); err != nil {
			return nil, err
		}
	}

	// computeAppHash must run after all dirty state is in the local maps
	// but before it is persisted, so it reflects the committed height.
	appHash, err := s.computeAppHash()
	if err != nil {
		return nil, fmt.Errorf("computing app hash: %w", err)
	}
	s.appHash = appHash
	s.height++

	if err := batch.Set([]byte("height"), []byte(fmt.Sprintf("%d", s.height))); err != nil {
		return nil, err
	}
	if err := batch.Set([]byte("app_hash"), s.appHash); err != nil {
		return nil, err
	}

	if err := batch.WriteSync(); err != nil {
		return nil, fmt.Errorf("failed to write batch: %w", err)
	}

	s.dirty = false
	s.logger.Info("State committed",
		"height", s.height,
		"app_hash", fmt.Sprintf("%x", s.appHash[:8]),
		"polls", len(s.polls),
		"votes", len(s.voteDirections),
		"voters", len(s.voterRegistry),
		"validators", len(s.validators),
	)
	return s.appHash, nil
}

// Query handles state queries.
// Supported paths:
//
//	/polls                                       — list all polls
//	/poll/{poll_id}                              — single poll
//	/tally/{poll_id}                             — tally for a closed poll
//	/vote/{ballot_id}                            — single vote record
//	/vote_exists/{ballot_id}                     — boolean-only List 1 presence surface; returns {"exists":bool} with no payload/direction
//	/votes/{poll_id}                             — all votes for a poll (ballot_id → choices, no identity)
//	/voter_count/{poll_id}                       — participant count for a poll
//	/confirms/{poll_id}                          — confirmed-count Sybil audit signal
//	/reattestation_audit/{poll_id}               — re-attestation count, voter count, deficit, and fabrication signal (Claims 11, 49, 65)
//	/idv_audit/{poll_id}                         — IDV-attested cast count vs. voter count; mismatch = fabrication signal (Claim 13, Claim 49)
//	/authority_actions/{poll_id}/{identity_hash} — per-participant authority-action records (rescissions + restores); scoped to authenticated identity only
func (s *State) Query(path string, data []byte, height int64, prove bool) ([]byte, error) {
	switch {
	case path == "/polls":
		polls := make([]*types.Poll, 0, len(s.polls))
		for _, p := range s.polls {
			polls = append(polls, p)
		}
		return json.Marshal(polls)

	case strings.HasPrefix(path, "/poll/"):
		pollID := strings.TrimPrefix(path, "/poll/")
		poll, exists := s.polls[pollID]
		if !exists {
			return nil, fmt.Errorf("poll not found: %s", pollID)
		}
		return json.Marshal(poll)

	case strings.HasPrefix(path, "/tally/"):
		pollID := strings.TrimPrefix(path, "/tally/")
		tally, exists := s.tallies[pollID]
		if !exists {
			return nil, fmt.Errorf("tally not found: %s", pollID)
		}
		return json.Marshal(tally)

	case strings.HasPrefix(path, "/vote_exists/"):
		// Boolean-only List 1 presence surface (Claim 52).
		// Returns {"exists":bool} only — no payload, no direction, no identity.
		// Structurally incapable of returning submission direction regardless of access controls.
		ballotID := strings.TrimPrefix(path, "/vote_exists/")
		_, exists := s.findVoteByBallotID(ballotID)
		return json.Marshal(map[string]bool{"exists": exists})

	case strings.HasPrefix(path, "/vote/"):
		ballotID := strings.TrimPrefix(path, "/vote/")
		vote, exists := s.findVoteByBallotID(ballotID)
		if !exists {
			return nil, fmt.Errorf("vote not found: %s", ballotID)
		}
		return json.Marshal(vote)

	case strings.HasPrefix(path, "/votes/"):
		pollID := strings.TrimPrefix(path, "/votes/")
		votes := make(map[string]*types.VoteRecord)
		prefix := pollID + ":"
		for storeKey, vote := range s.voteDirections {
			if strings.HasPrefix(storeKey, prefix) {
				votes[vote.BallotID] = vote
			}
		}
		return json.Marshal(votes)

	case strings.HasPrefix(path, "/voter_count/"):
		pollID := strings.TrimPrefix(path, "/voter_count/")
		count := 0
		prefix := pollID + ":"
		for key := range s.voterRegistry {
			if strings.HasPrefix(key, prefix) {
				count++
			}
		}
		return json.Marshal(map[string]int{"count": count})

	case strings.HasPrefix(path, "/confirms/"):
		pollID := strings.TrimPrefix(path, "/confirms/")
		if _, exists := s.polls[pollID]; !exists {
			return nil, fmt.Errorf("poll not found: %s", pollID)
		}
		return json.Marshal(map[string]int64{"confirmed_count": s.confirmedCountForPoll(pollID)})

	case strings.HasPrefix(path, "/reattestation_audit/"):
		// /reattestation_audit/{poll_id}
		// Re-attestation audit interface (Claims 11, 49, 65).
		// Reports the persistent re-attestation count vs. the current voter count.
		// deficit > 0 means some voters have not yet re-attested.
		// deficit_is_fabrication_signal = true means more confirms than voters were
		// accepted — structurally impossible due to the idempotency cap, but surfaced
		// as an explicit boolean for third-party auditors.
		pollID := strings.TrimPrefix(path, "/reattestation_audit/")
		poll, exists := s.polls[pollID]
		if !exists {
			return nil, fmt.Errorf("poll not found: %s", pollID)
		}
		voterCount := s.voterCountForPoll(pollID)
		reattestCount := poll.ReattestationCount
		deficit := voterCount - reattestCount
		if deficit < 0 {
			deficit = 0
		}
		fabricationSignal := reattestCount > voterCount
		return json.Marshal(map[string]interface{}{
			"reattestation_count":           reattestCount,
			"voter_count":                   voterCount,
			"deficit":                       deficit,
			"deficit_is_fabrication_signal": fabricationSignal,
		})

	case strings.HasPrefix(path, "/idv_audit/"):
		// /idv_audit/{poll_id}
		// IDV audit interface (Claims 50, 54).
		// Compares the IDV-attested cast count against the current voter count.
		// Before rescissions: idv_cast_count == voter_count (by construction).
		// After rescissions: idv_cast_count > voter_count — the divergence is the
		// fabrication-detection signal. The IDV provider can also compare
		// idv_cast_count with its own signing-log count for the same poll; if the
		// IDV log shows fewer signatures than idv_cast_count, that signals ballots
		// were materialised without passing through the IDV — fabrication.
		pollID := strings.TrimPrefix(path, "/idv_audit/")
		poll, exists := s.polls[pollID]
		if !exists {
			return nil, fmt.Errorf("poll not found: %s", pollID)
		}
		voterCount := s.voterCountForPoll(pollID)
		idvCastCount := poll.IDVCastCount
		mismatch := idvCastCount != voterCount
		return json.Marshal(map[string]interface{}{
			"idv_cast_count":  idvCastCount,
			"voter_count":     voterCount,
			"mismatch":        mismatch,
			"mismatch_signal": mismatch,
		})

	case strings.HasPrefix(path, "/authority_actions/"):
		// /authority_actions/{poll_id}/{identity_hash}
		// Per-participant authority-action audit interface (Claims 18, 50).
		// Returns only rescission and restore records bound to the given identity_hash
		// within the given poll. Response is scoped exclusively to this participant:
		// no invocation sequence constructs a cross-participant mapping.
		rest := strings.TrimPrefix(path, "/authority_actions/")
		sep := strings.Index(rest, "/")
		if sep < 0 {
			return nil, fmt.Errorf("authority_actions requires /poll_id/identity_hash")
		}
		pollID, identityHash := rest[:sep], rest[sep+1:]
		type authorityActionEntry struct {
			Type         string `json:"type"` // "rescission" | "restore"
			BallotID     string `json:"ballot_id,omitempty"`
			RevocationRef string `json:"revocation_ref,omitempty"`
			Height       int64  `json:"height"`
		}
		var entries []authorityActionEntry
		for _, r := range s.rescissions {
			if r.PollID == pollID && r.IdentityHash == identityHash {
				entries = append(entries, authorityActionEntry{
					Type:          "rescission",
					BallotID:      r.BallotID,
					RevocationRef: r.RevocationRef,
					Height:        r.Height,
				})
			}
		}
		for _, r := range s.restores {
			if r.PollID == pollID && r.IdentityHash == identityHash {
				entries = append(entries, authorityActionEntry{
					Type:          "restore",
					BallotID:      r.BallotID,
					RevocationRef: r.RevocationRef,
					Height:        r.Height,
				})
			}
		}
		if entries == nil {
			entries = []authorityActionEntry{}
		}
		return json.Marshal(entries)

	case strings.HasPrefix(path, "/voter_registered/"):
		// /voter_registered/{poll_id}/{identity_hash}
		// Returns {"registered": true|false}. Used by the API server to detect
		// post-flush duplicate submissions before queuing a second ballot.
		rest := strings.TrimPrefix(path, "/voter_registered/")
		sep := strings.Index(rest, "/")
		if sep < 0 {
			return nil, fmt.Errorf("voter_registered requires /poll_id/identity_hash")
		}
		pollID, identityHash := rest[:sep], rest[sep+1:]
		registryKey := pollID + ":" + identityHash
		_, registered := s.voterRegistry[registryKey]
		return json.Marshal(map[string]bool{"registered": registered})

	default:
		return nil, fmt.Errorf("unknown query path: %s", path)
	}
}

// loadState reloads all state from LevelDB on startup.
func (s *State) loadState() error {
	heightBytes, err := s.db.Get([]byte("height"))
	if err != nil {
		return err
	}
	if heightBytes != nil {
		if _, err := fmt.Sscanf(string(heightBytes), "%d", &s.height); err != nil {
			return fmt.Errorf("parsing stored height %q: %w", string(heightBytes), err)
		}
	}

	appHashBytes, err := s.db.Get([]byte("app_hash"))
	if err != nil {
		return err
	}
	if appHashBytes != nil {
		s.appHash = appHashBytes
	}

	if err := s.loadPrefix("poll:", func(_ string, val []byte) error {
		var poll types.Poll
		if err := json.Unmarshal(val, &poll); err != nil {
			return err
		}
		s.polls[poll.PollID] = &poll
		return nil
	}); err != nil {
		return fmt.Errorf("loading polls: %w", err)
	}

	if err := s.loadPrefix("vote:", func(key string, val []byte) error {
		var v types.VoteRecord
		if err := json.Unmarshal(val, &v); err != nil {
			return err
		}
		s.voteDirections[key] = &v
		return nil
	}); err != nil {
		return fmt.Errorf("loading vote directions: %w", err)
	}

	if err := s.loadPrefix("voter:", func(key string, val []byte) error {
		var v types.VoterRecord
		if err := json.Unmarshal(val, &v); err != nil {
			return err
		}
		s.voterRegistry[key] = &v
		return nil
	}); err != nil {
		return fmt.Errorf("loading voter registry: %w", err)
	}

	if err := s.loadPrefix("tally:", func(_ string, val []byte) error {
		var t types.Tally
		if err := json.Unmarshal(val, &t); err != nil {
			return err
		}
		s.tallies[t.PollID] = &t
		return nil
	}); err != nil {
		return fmt.Errorf("loading tallies: %w", err)
	}

	if err := s.loadPrefix("validator:", func(_ string, val []byte) error {
		var v ValidatorRecord
		if err := json.Unmarshal(val, &v); err != nil {
			return err
		}
		s.validators[v.PubKeyBase64] = &v
		return nil
	}); err != nil {
		return fmt.Errorf("loading validators: %w", err)
	}

	if err := s.loadPrefix("confirm:", func(_ string, val []byte) error {
		var r types.ConfirmRecord
		if err := json.Unmarshal(val, &r); err != nil {
			return err
		}
		s.confirms[r.PollID+":"+r.IdentityHash] = &r
		return nil
	}); err != nil {
		return fmt.Errorf("loading confirms: %w", err)
	}

	if err := s.loadPrefix("rescind:", func(_ string, val []byte) error {
		var r types.RescindRecord
		if err := json.Unmarshal(val, &r); err != nil {
			return err
		}
		s.rescissions[r.PollID+":"+r.BallotID] = &r
		return nil
	}); err != nil {
		return fmt.Errorf("loading rescissions: %w", err)
	}

	if err := s.loadPrefix("restore:", func(_ string, val []byte) error {
		var r types.RestoreRecord
		if err := json.Unmarshal(val, &r); err != nil {
			return err
		}
		s.restores[r.PollID+":"+r.IdentityHash] = &r
		return nil
	}); err != nil {
		return fmt.Errorf("loading restores: %w", err)
	}

	s.logger.Info("State loaded",
		"height", s.height,
		"polls", len(s.polls),
		"votes", len(s.voteDirections),
		"voters", len(s.voterRegistry),
		"tallies", len(s.tallies),
		"validators", len(s.validators),
	)
	return nil
}

// loadPrefix iterates all DB keys with the given prefix and calls fn with the
// suffix key and stored value.
func (s *State) loadPrefix(prefix string, fn func(string, []byte) error) error {
	start := []byte(prefix)
	end := prefixEnd(start)
	it, err := s.db.Iterator(start, end)
	if err != nil {
		return err
	}
	defer it.Close()
	for ; it.Valid(); it.Next() {
		fullKey := string(it.Key())
		key := strings.TrimPrefix(fullKey, prefix)
		if err := fn(key, it.Value()); err != nil {
			return fmt.Errorf("key %s: %w", it.Key(), err)
		}
	}
	return it.Error()
}

// computeAppHash hashes all state deterministically by sorting map keys.
// CometBFT requires app hashes to be identical across all validators for the
// same block, so the sort order must be stable.
func (s *State) computeAppHash() ([]byte, error) {
	h := sha256.New()

	pollKeys := sortedKeys(s.polls)
	for _, k := range pollKeys {
		data, err := json.Marshal(s.polls[k])
		if err != nil {
			return nil, fmt.Errorf("marshal poll %s: %w", k, err)
		}
		h.Write(data)
	}

	voteKeys := sortedKeys(s.voteDirections)
	for _, k := range voteKeys {
		data, err := json.Marshal(s.voteDirections[k])
		if err != nil {
			return nil, fmt.Errorf("marshal vote direction %s: %w", k, err)
		}
		h.Write(data)
	}

	voterKeys := sortedKeys(s.voterRegistry)
	for _, k := range voterKeys {
		data, err := json.Marshal(s.voterRegistry[k])
		if err != nil {
			return nil, fmt.Errorf("marshal voter record %s: %w", k, err)
		}
		h.Write(data)
	}

	tallyKeys := sortedKeys(s.tallies)
	for _, k := range tallyKeys {
		data, err := json.Marshal(s.tallies[k])
		if err != nil {
			return nil, fmt.Errorf("marshal tally %s: %w", k, err)
		}
		h.Write(data)
	}

	validatorKeys := sortedKeys(s.validators)
	for _, k := range validatorKeys {
		data, err := json.Marshal(s.validators[k])
		if err != nil {
			return nil, fmt.Errorf("marshal validator %s: %w", k, err)
		}
		h.Write(data)
	}

	confirmKeys := sortedKeys(s.confirms)
	for _, k := range confirmKeys {
		data, err := json.Marshal(s.confirms[k])
		if err != nil {
			return nil, fmt.Errorf("marshal confirm record %s: %w", k, err)
		}
		h.Write(data)
	}

	rescindKeys := sortedKeys(s.rescissions)
	for _, k := range rescindKeys {
		data, err := json.Marshal(s.rescissions[k])
		if err != nil {
			return nil, fmt.Errorf("marshal rescind record %s: %w", k, err)
		}
		h.Write(data)
	}

	return h.Sum(nil), nil
}

func (s *State) voterCountForPoll(pollID string) int64 {
	var count int64
	prefix := pollID + ":"
	for key := range s.voterRegistry {
		if strings.HasPrefix(key, prefix) {
			count++
		}
	}
	return count
}

func (s *State) confirmedCountForPoll(pollID string) int64 {
	var count int64
	prefix := pollID + ":"
	for key := range s.confirms {
		if strings.HasPrefix(key, prefix) {
			count++
		}
	}
	return count
}

func voteStoreKey(pollID, ballotID string) string {
	return pollID + ":" + ballotID
}

func (s *State) findVoteByBallotID(ballotID string) (*types.VoteRecord, bool) {
	suffix := ":" + ballotID
	for key, vote := range s.voteDirections {
		if strings.HasSuffix(key, suffix) {
			return vote, true
		}
	}
	return nil, false
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

// prefixEnd returns the first key that is lexicographically after all keys
// with the given prefix, for use as the upper bound in an iterator.
func prefixEnd(prefix []byte) []byte {
	end := make([]byte, len(prefix))
	copy(end, prefix)
	for i := len(end) - 1; i >= 0; i-- {
		end[i]++
		if end[i] != 0 {
			return end[:i+1]
		}
	}
	return nil // prefix is all 0xFF — no upper bound, iterate to end
}
