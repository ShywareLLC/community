package state

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/ShywareLLC/community/protocol/submission"
	"github.com/ShywareLLC/community/protocol/tx"
	"github.com/ShywareLLC/community/protocol/types"
)

// validateBallotCast validates a ballot transaction.
//
// The voter device signature (sk_v over ballotNonce:pollID) is verified first —
// this is the oracle-forgery prevention property: the IDV provider cannot forge
// a ballot because it never holds sk_v.
//
// IDV attestation and identity_hash derivation are then delegated to s.verifier,
// which is set at startup from the shyconfig identity_binding_mode.
func (s *State) validateBallotCast(transaction *tx.Tx) error {
	var data tx.BallotCastData
	if err := transaction.UnmarshalData(&data); err != nil {
		return fmt.Errorf("invalid ballot cast data: %w", err)
	}

	// Validate nonce format.
	if err := submission.ValidateNonce(data.BallotNonce); err != nil {
		return fmt.Errorf("ballot_nonce: %w", err)
	}

	// Validate beacon: confirms the identifier was conditioned on a pre-session canonical block hash.
	if err := submission.ValidateBeacon(data.BeaconBlockHash, data.BeaconBlockHeight, s.beaconWindow); err != nil {
		return fmt.Errorf("beacon: %w", err)
	}

	// Decode voter public key (hex → 32-byte Ed25519)
	voterPubBytes, err := hex.DecodeString(data.VoterPubKey)
	if err != nil || len(voterPubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("voter_pub_key must be a 64-char hex-encoded Ed25519 public key")
	}

	// Verify voter device signature: sign(sk_v, ballotNonce:pollId).
	// Oracle-prevention: IDV knows identity_hash but never holds sk_v.
	deviceMsg := voterDeviceSigMessage(data.BallotNonce, data.PollID)
	if !ed25519.Verify(ed25519.PublicKey(voterPubBytes), deviceMsg, data.VoterSig) {
		return fmt.Errorf("voter device signature invalid for poll %s", data.PollID)
	}

	// IDV attestation + identity_hash derivation — provider-agnostic.
	if s.verifier == nil {
		return fmt.Errorf("no identity verifier configured for this deployment")
	}

	// Poll must exist and be open
	poll, exists := s.polls[data.PollID]
	if !exists {
		return &types.ErrorInvalidPoll{Message: fmt.Sprintf("poll %s does not exist", data.PollID)}
	}
	now := time.Now().Unix()
	if now < poll.StartTime {
		return &types.ErrorInvalidPoll{Message: "poll has not started yet"}
	}
	if now >= poll.EndTime {
		return &types.ErrorInvalidPoll{Message: "poll has ended"}
	}
	if poll.Status == "closed" {
		return &types.ErrorInvalidPoll{Message: "poll is closed"}
	}
	if poll.Status == "pending" && now >= poll.StartTime {
		poll.Status = "open"
	}

	if err := validateChoices(poll, data.Choices); err != nil {
		return err
	}

	// IDV attestation; identity_hash is derived here for dedup check.
	identityHash, err := s.verifier.VerifyAndIdentify(&data)
	if err != nil {
		return fmt.Errorf("identity verification failed: %w", err)
	}

	// Dedup on identity_hash (one ballot per voter per poll).
	// Exception: if a TxTypeAuthorityRestore grant exists for this (pollID, identityHash),
	// the participant was wrongfully rescinded and their re-cast is authorized. The
	// rescission already removed their L2 entry, so the registry will be absent —
	// skip the duplicate check and allow re-cast to restore count-match parity.
	registryKey := fmt.Sprintf("%s:%s", data.PollID, identityHash)
	if _, exists := s.voterRegistry[registryKey]; exists {
		if !s.HasRestoreGrant(data.PollID, identityHash) {
			return &types.ErrorDuplicateVote{
				PollID:       data.PollID,
				IdentityHash: identityHash,
			}
		}
	}

	return nil
}

// executeBallotCast atomically writes two unlinked records:
//   - List 1 (voteDirections): key poll_id:ballot_id, value ballot_id + choice, no identity
//   - List 2 (voterRegistry):  key poll_id:identity_hash, value identity_hash, no choice
//
// Public observability is intentionally opaque. Aggregate attestation events may
// be emitted separately, but a direct ballot execution path does not expose a
// paired identity-side and payload-side event surface.
func (s *State) executeBallotCast(transaction *tx.Tx) ([]abcitypes.Event, error) {
	var data tx.BallotCastData
	if err := transaction.UnmarshalData(&data); err != nil {
		return nil, fmt.Errorf("invalid ballot cast data: %w", err)
	}

	// Re-derive identity_hash (already validated — this cannot fail).
	identityHash, err := s.verifier.VerifyAndIdentify(&data)
	if err != nil {
		return nil, fmt.Errorf("identity re-derivation failed: %w", err)
	}

	ballotID := deriveBallotIDWithBeacon(data.BeaconBlockHash, data.BallotNonce, data.Choices, data.SubmissionIdentifierDerivation)
	voteKey := voteStoreKey(data.PollID, ballotID)
	registryKey := fmt.Sprintf("%s:%s", data.PollID, identityHash)

	// List 1: anonymous vote direction — no identity.
	// VoterPubKeyHash is a domain-separated one-way hash of the voter's Ed25519
	// public key, stored exclusively to authenticate the partition-migration path
	// (TxTypeResealVote). The domain separator and argument order differ from the
	// L2 identity_hash derivation (sha256(voter_pub_key || poll_id)), so no allowed
	// operation over canonical state can derive one from the other. The raw public
	// key is not written to canonical state.
	migrationAuthInput := "partition-migration-auth:" + data.VoterPubKey + ":" + data.PollID
	migrationAuthHash := sha256.Sum256([]byte(migrationAuthInput))
	s.voteDirections[voteKey] = &types.VoteRecord{
		BallotID:        ballotID,
		Choices:         data.Choices,
		PartitionID:     data.PartitionID,
		Superseded:      false,
		VoterPubKeyHash: hex.EncodeToString(migrationAuthHash[:]),
	}

	// List 2: voter participation — identity only, no choice, no transactional
	// metadata. Height is intentionally absent so no field shared with L1 can
	// be used to pair this record with its corresponding anonymous submission record.
	s.voterRegistry[registryKey] = &types.VoterRecord{
		IdentityHash: identityHash,
	}

	// Increment the IDV-attested cast counter. Each unique ballot cast = one IDV
	// attestation at the ABCI validation layer. Updates are not counted — they do
	// not add to |L2|. At any point before rescissions: IDVCastCount == |L2|.
	// After rescissions: IDVCastCount > |L2|, exposing the divergence through
	// /idv_audit/{poll_id} as the fabrication-detection interface (Claim 13, Claim 49).
	if p, exists := s.polls[data.PollID]; exists {
		p.IDVCastCount++
	}

	s.dirty = true
	s.logger.Info("Ballot cast", "scoping_id", data.PollID, "submission_id", ballotID)

	events := []abcitypes.Event{
		{
			Type: "submission_accepted",
			Attributes: []abcitypes.EventAttribute{
				{Key: "scoping_id", Value: data.PollID, Index: true},
				{Key: "status", Value: "accepted", Index: false},
			},
		},
	}

	// Rolling attestation: commit a checkpoint every rollingThreshold submissions.
	if s.attestationMode == "rolling" && s.rollingThreshold > 0 {
		s.submissionCounts[data.PollID]++
		if s.submissionCounts[data.PollID] >= s.rollingThreshold {
			s.submissionCounts[data.PollID] = 0
			if cpEvents, err := s.commitRollingAttestation(context.Background(), data.PollID); err != nil {
				s.logger.Error("rolling attestation failed", "scoping_id", data.PollID, "error", err)
			} else {
				events = append(events, cpEvents...)
			}
		}
	}

	return events, nil
}

// ballotUpdateDeviceSigMessage is the message the voter's device signs for a ballot update:
//
//	"update:" + newBallotNonce + ":" + pollID
//
// The "update:" prefix prevents a BallotCast device signature from being replayed
// as a BallotUpdate, since the original cast message has no prefix.
func ballotUpdateDeviceSigMessage(newBallotNonce, pollID string) []byte {
	return []byte("update:" + newBallotNonce + ":" + pollID)
}

// validateBallotUpdate validates a ballot-update transaction.
//
// Preconditions:
//   - Poll is open (same as BallotCast).
//   - OldBallotID exists in List 1 (voteDirections).
//   - The voter's identity_hash is in List 2 (voterRegistry) for this poll —
//     i.e., the voter has previously cast a ballot.
//   - Identity attestation and device signature are valid.
//
// Write-only posture: ballot updates (direction changes and bilateral withdrawals)
// are permitted under write-only posture. Write-only posture suppresses only
// participant-facing reconcile and receipt-readback paths — it does not block
// payload changes. Under coercion the victim must be able to change or retract a
// forced submission; blocking updates would remove the only effective counter to a
// coerced cast. Readback suppression already denies the coercer confirmation of
// submission direction.
func (s *State) validateBallotUpdate(transaction *tx.Tx) error {
	var data tx.BallotUpdateData
	if err := transaction.UnmarshalData(&data); err != nil {
		return fmt.Errorf("invalid ballot update data: %w", err)
	}

	// Validate nonce format.
	if err := submission.ValidateNonce(data.NewBallotNonce); err != nil {
		return fmt.Errorf("new_ballot_nonce: %w", err)
	}

	// Validate beacon: confirms the identifier was conditioned on a pre-session canonical block hash.
	if err := submission.ValidateBeacon(data.BeaconBlockHash, data.BeaconBlockHeight, s.beaconWindow); err != nil {
		return fmt.Errorf("beacon: %w", err)
	}

	// Decode voter public key
	voterPubBytes, err := hex.DecodeString(data.VoterPubKey)
	if err != nil || len(voterPubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("voter_pub_key must be a 64-char hex-encoded Ed25519 public key")
	}

	// Verify update device signature: sign(sk_v, "update:" + newBallotNonce + ":" + pollID)
	updateMsg := ballotUpdateDeviceSigMessage(data.NewBallotNonce, data.PollID)
	if !ed25519.Verify(ed25519.PublicKey(voterPubBytes), updateMsg, data.VoterSig) {
		return fmt.Errorf("voter device signature invalid for ballot update on poll %s", data.PollID)
	}

	// IDV attestation + identity_hash derivation — provider-agnostic.
	if s.verifier == nil {
		return fmt.Errorf("no identity verifier configured for this deployment")
	}
	identityHash, err := s.verifier.VerifyAndIdentifyUpdate(&data)
	if err != nil {
		return fmt.Errorf("identity verification failed for ballot update: %w", err)
	}

	// Poll must exist and be open
	poll, exists := s.polls[data.PollID]
	if !exists {
		return &types.ErrorInvalidPoll{Message: fmt.Sprintf("poll %s does not exist", data.PollID)}
	}
	now := time.Now().Unix()
	if now < poll.StartTime {
		return &types.ErrorInvalidPoll{Message: "poll has not started yet"}
	}
	if now >= poll.EndTime {
		return &types.ErrorInvalidPoll{Message: "poll has ended"}
	}
	if poll.Status == "closed" {
		return &types.ErrorInvalidPoll{Message: "poll is closed"}
	}

	// Old ballot must exist in List 1
	oldVoteKey := voteStoreKey(data.PollID, data.OldBallotID)
	if _, exists := s.voteDirections[oldVoteKey]; !exists {
		return fmt.Errorf("old_ballot_id %s not found — cannot update a ballot that was not cast", data.OldBallotID)
	}

	// Voter must already be registered in List 2 for this poll
	registryKey := fmt.Sprintf("%s:%s", data.PollID, identityHash)
	if _, exists := s.voterRegistry[registryKey]; !exists {
		return fmt.Errorf("voter is not registered for poll %s — cannot update an uncast ballot", data.PollID)
	}

	// Empty NewChoices = bilateral withdrawal (re-abstain). No choice validation needed.
	if len(data.NewChoices) > 0 {
		if err := validateChoices(poll, data.NewChoices); err != nil {
			return err
		}
	}

	return nil
}

// executeBallotUpdate handles two cases:
//
//  1. Direction change (len(NewChoices) > 0): atomically replaces the L1 entry.
//     L2 unchanged. |L1| = |L2| held constant.
//
//  2. Bilateral withdrawal / re-abstain (len(NewChoices) == 0): deletes the L1
//     entry AND the corresponding L2 entry. Both lists shrink by one; the invariant
//     |L1| = |L2| is maintained. The voter leaves no on-chain trace. History of
//     participation is retained in the off-chain CRDB receipt store.
//
//     The L2 entry is located by deriving identity_hash from the attestation fields
//     in the tx — the same derivation used during cast. No explicit join key is
//     written to the chain; the state machine derives it transiently and deletes.
//     After withdrawal the voter's identity_hash is no longer in L2, so they may
//     re-cast using the same attestation (new keypair, new ballot nonce).
func (s *State) executeBallotUpdate(transaction *tx.Tx) ([]abcitypes.Event, error) {
	var data tx.BallotUpdateData
	if err := transaction.UnmarshalData(&data); err != nil {
		return nil, fmt.Errorf("invalid ballot update data: %w", err)
	}

	// Re-derive identity_hash (already validated — this cannot fail).
	identityHash, err := s.verifier.VerifyAndIdentifyUpdate(&data)
	if err != nil {
		return nil, fmt.Errorf("identity re-derivation failed: %w", err)
	}

	s.dirty = true

	if len(data.NewChoices) == 0 {
		// Bilateral withdrawal: remove from both lists. |L1| and |L2| decrease by 1.
		registryKey := fmt.Sprintf("%s:%s", data.PollID, identityHash)
		confirmKey := registryKey
		delete(s.voteDirections, voteStoreKey(data.PollID, data.OldBallotID))
		delete(s.voterRegistry, registryKey)
		delete(s.confirms, confirmKey)

		if t, exists := s.tallies[data.PollID]; exists {
			t.ConfirmedCount = s.confirmedCountForPoll(data.PollID)
		}

		s.logger.Info("Ballot withdrawn (re-abstain)",
			"scoping_id", data.PollID,
			"old_ballot_id", data.OldBallotID,
		)

		return []abcitypes.Event{
			{
				Type: "ballot_withdrawn",
				Attributes: []abcitypes.EventAttribute{
					{Key: "scoping_id", Value: data.PollID, Index: true},
					{Key: "old_ballot_id", Value: data.OldBallotID, Index: true},
					{Key: "timestamp", Value: fmt.Sprintf("%d", data.Timestamp), Index: false},
				},
			},
		}, nil
	}

	// Direction change: replace L1 entry. L2 unchanged. |L1| held constant.
	newBallotID := deriveBallotIDWithBeacon(data.BeaconBlockHash, data.NewBallotNonce, data.NewChoices, data.SubmissionIdentifierDerivation)

	delete(s.voteDirections, voteStoreKey(data.PollID, data.OldBallotID))
	s.voteDirections[voteStoreKey(data.PollID, newBallotID)] = &types.VoteRecord{
		BallotID: newBallotID,
		Choices:  data.NewChoices,
	}

	s.logger.Info("Ballot updated",
		"scoping_id", data.PollID,
		"old_ballot_id", data.OldBallotID,
		"new_ballot_id", newBallotID,
	)

	return []abcitypes.Event{
		{
			Type: "ballot_updated",
			Attributes: []abcitypes.EventAttribute{
				{Key: "scoping_id", Value: data.PollID, Index: true},
				{Key: "old_ballot_id", Value: data.OldBallotID, Index: true},
				{Key: "new_ballot_id", Value: newBallotID, Index: true},
				{Key: "choices", Value: strings.Join(data.NewChoices, ","), Index: false},
				{Key: "timestamp", Value: fmt.Sprintf("%d", data.Timestamp), Index: false},
			},
		},
	}, nil
}

// validateChoices checks that the supplied choices are valid for the poll's VotingMethod.
func validateChoices(poll *types.Poll, choices []string) error {
	if len(choices) == 0 {
		return &types.ErrorInvalidPoll{Message: "choices must not be empty"}
	}

	method := poll.VotingMethod
	if method == "" {
		method = types.VotingMethodPlurality
	}

	optionSet := make(map[string]bool, len(poll.Options))
	for _, o := range poll.Options {
		optionSet[o] = true
	}

	seen := make(map[string]bool, len(choices))
	for _, c := range choices {
		if !optionSet[c] {
			return &types.ErrorInvalidPoll{Message: fmt.Sprintf("invalid choice: %q is not a poll option", c)}
		}
		if seen[c] {
			return &types.ErrorInvalidPoll{Message: fmt.Sprintf("duplicate choice: %q", c)}
		}
		seen[c] = true
	}

	if method == types.VotingMethodPlurality && len(choices) != 1 {
		return &types.ErrorInvalidPoll{Message: fmt.Sprintf("plurality poll requires exactly 1 choice, got %d", len(choices))}
	}

	return nil
}

// computeBallotID derives an anonymous ballot ID from a beacon block hash and
// client-supplied nonce:
//
//	ballot_id = SHA-256(beacon_bytes || nonce_bytes)
//
// The beacon is a recent canonical block hash committed by BFT consensus before
// the submission session began. This makes ballot_id information-theoretically
// independent of all identity inputs: SHA-256(public_canonical_entropy || x) is
// statistically independent of x regardless of the distribution of x.
// Falls back to SHA-256(nonce) when beaconBlockHash is empty (test/legacy paths).
func computeBallotID(ballotNonce string) string {
	h := sha256.Sum256([]byte(ballotNonce))
	return hex.EncodeToString(h[:])
}

func computeBallotIDWithBeacon(beaconBlockHash, ballotNonce string) string {
	if beaconBlockHash == "" {
		return computeBallotID(ballotNonce)
	}
	id, err := submission.DeriveSubmissionID(beaconBlockHash, ballotNonce)
	if err != nil {
		// ValidateBeacon already ran; this path is unreachable in production.
		return computeBallotID(ballotNonce)
	}
	return id
}

func deriveBallotID(ballotNonce string, choices []string, mode string) string {
	if mode == tx.SubmissionIdentifierDerivationNoncePlusPayload {
		payloadBytes, _ := json.Marshal(choices)
		h := sha256.Sum256([]byte(ballotNonce + ":" + string(payloadBytes)))
		return hex.EncodeToString(h[:])
	}
	return computeBallotID(ballotNonce)
}

func deriveBallotIDWithBeacon(beaconBlockHash, ballotNonce string, choices []string, mode string) string {
	if mode == tx.SubmissionIdentifierDerivationNoncePlusPayload {
		payloadBytes, _ := json.Marshal(choices)
		h := sha256.Sum256([]byte(ballotNonce + ":" + string(payloadBytes)))
		return hex.EncodeToString(h[:])
	}
	return computeBallotIDWithBeacon(beaconBlockHash, ballotNonce)
}

// voterDeviceSigMessage is the message the voter's device signs at submission time:
//
//	"ballotNonce:pollId"
//
// Binds the signature to this specific nonce and poll — prevents replay across polls.
func voterDeviceSigMessage(ballotNonce, pollID string) []byte {
	return []byte(ballotNonce + ":" + pollID)
}
