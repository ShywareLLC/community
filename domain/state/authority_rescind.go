package state

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/ShywareLLC/community/protocol/tx"
	"github.com/ShywareLLC/community/protocol/types"
)

// rescindMessage returns the canonical signed message for a rescission.
// Both the eligibility authority and the reconciling authority sign this byte
// slice. Binding all four identifying fields prevents cross-rescission replay —
// a sig over one (pollID, ballotID, identityHash, revocationRef) tuple is
// invalid for any other tuple.
func rescindMessage(pollID, ballotID, identityHash, revocationRef string) []byte {
	return []byte("authority-rescind:" + pollID + ":" + ballotID + ":" + identityHash + ":" + revocationRef)
}

// validateAuthorityRescind performs stateful validation of a TxTypeAuthorityRescind
// transaction.
//
// This transaction type addresses Sybil-write threats that arise specifically in
// count-match deployments: a participant who purchased a biometric credential,
// benefited from IDV collusion, or exploited a device-attestation gap can write
// a structurally valid L1+L2 pair that inflates the count. The eligibility
// authority (defaults to operator; may be any operator-designated party) and the
// reconciling authority (off-chain linkage store operator) must both co-sign the
// rescission message. Neither can unilaterally remove an entry from canonical state.
//
// TxTypeAuthorityRescind is NOT applicable to sealer-governed deployments
// (shychat-v1, shystore-v1). Those deployments do not enforce unique-person
// count-match — multiple accounts per person are permitted and the sealer's
// access control is the operative guarantee. Omitting both rescission keys at
// poll creation disables this tx type entirely for that poll.
//
// Verifies:
//  1. Poll exists and has both rescission keys registered.
//  2. L1 entry (voteDirections) for BallotID exists.
//  3. L2 entry (voterRegistry) for IdentityHash exists.
//  4. EligibilitySig is a valid Ed25519 signature over the canonical rescind message.
//  5. ReconcilingSig is a valid Ed25519 signature over the canonical rescind message.
//  6. No prior rescission record exists for this BallotID (idempotency guard).
func (s *State) validateAuthorityRescind(transaction *tx.Tx) error {
	var data tx.AuthorityRescindData
	if err := transaction.UnmarshalData(&data); err != nil {
		return fmt.Errorf("invalid authority rescind data: %w", err)
	}

	// 1. Poll must exist and have both rescission keys registered.
	poll, ok := s.polls[data.PollID]
	if !ok {
		return fmt.Errorf("poll not found: %s", data.PollID)
	}
	if poll.EligibilityAuthorityPubKey == "" || poll.ReconcilingAuthorityPubKey == "" {
		// Rescission is only available for count-match deployments where both keys
		// were registered at poll creation. Sealer-governed deployments (shychat,
		// shystore) omit these keys; their access-control guarantee comes from the
		// sealer, not from unique-entry count-match enforcement.
		return fmt.Errorf("poll %s has no rescission keys registered: TxTypeAuthorityRescind is only available for count-match deployments (shyvoting-v1 and equivalents) with both eligibility and reconciling authority keys registered at creation", data.PollID)
	}

	eligPubKeyBytes, err := base64.StdEncoding.DecodeString(poll.EligibilityAuthorityPubKey)
	if err != nil {
		return fmt.Errorf("stored eligibility_authority_pub_key is not valid base64: %w", err)
	}
	if len(eligPubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("stored eligibility_authority_pub_key has wrong length: %d", len(eligPubKeyBytes))
	}

	reconcilePubKeyBytes, err := base64.StdEncoding.DecodeString(poll.ReconcilingAuthorityPubKey)
	if err != nil {
		return fmt.Errorf("stored reconciling_authority_pub_key is not valid base64: %w", err)
	}
	if len(reconcilePubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("stored reconciling_authority_pub_key has wrong length: %d", len(reconcilePubKeyBytes))
	}

	// 2. L1 entry must exist.
	l1Key := data.PollID + ":" + data.BallotID
	if _, exists := s.voteDirections[l1Key]; !exists {
		return fmt.Errorf("ballot not found in List 1: poll=%s ballot=%s", data.PollID, data.BallotID)
	}

	// 3. L2 entry must exist.
	l2Key := data.PollID + ":" + data.IdentityHash
	if _, exists := s.voterRegistry[l2Key]; !exists {
		return fmt.Errorf("identity not found in List 2: poll=%s identity=%s", data.PollID, data.IdentityHash)
	}

	msg := rescindMessage(data.PollID, data.BallotID, data.IdentityHash, data.RevocationRef)

	// 4. Verify eligibility authority signature.
	if !ed25519.Verify(ed25519.PublicKey(eligPubKeyBytes), msg, data.EligibilitySig) {
		return fmt.Errorf("eligibility authority signature verification failed")
	}

	// 5. Verify reconciling authority signature.
	if !ed25519.Verify(ed25519.PublicKey(reconcilePubKeyBytes), msg, data.ReconcilingSig) {
		return fmt.Errorf("reconciling authority signature verification failed")
	}

	// 6. Idempotency: reject if already rescinded.
	rescindKey := data.PollID + ":" + data.BallotID
	if _, exists := s.rescissions[rescindKey]; exists {
		return fmt.Errorf("ballot already rescinded: poll=%s ballot=%s", data.PollID, data.BallotID)
	}

	return nil
}

// executeAuthorityRescind atomically applies a validated TxTypeAuthorityRescind:
//  1. Reads the L1 VoteRecord (needed to decrement tally counts if poll is closed).
//  2. Deletes the L1 entry from voteDirections.
//  3. Deletes the L2 entry from voterRegistry.
//  4. Deletes any ConfirmRecord for this identity.
//  5. If the rescinded L1 record was in the sealed partition, decrements Poll.SealedCount
//     to preserve the sealed-partition global invariant: |L2| = counted-L1 + SealedCount.
//  6. If poll is closed: decrements TotalVotes and Counts, increments RescissionCount,
//     marks AttestationDegraded (original HSM sig no longer matches current counts).
//  7. Writes an append-only RescindRecord to s.rescissions.
//  8. Marks state dirty and emits audit events.
//
// Count-match invariant is preserved: both L1 and L2 shrink by exactly one.
// Delete-only invariant is preserved: no new L1 or L2 entries are written.
func (s *State) executeAuthorityRescind(transaction *tx.Tx) ([]abcitypes.Event, error) {
	var data tx.AuthorityRescindData
	if err := transaction.UnmarshalData(&data); err != nil {
		return nil, fmt.Errorf("invalid authority rescind data: %w", err)
	}

	l1Key := data.PollID + ":" + data.BallotID
	l2Key := data.PollID + ":" + data.IdentityHash

	// 1. Read L1 before deletion (needed for tally adjustment on closed polls).
	voteRecord := s.voteDirections[l1Key]

	// 2. Delete L1 (List 1 — direction, no identity).
	delete(s.voteDirections, l1Key)

	// 3. Delete L2 (List 2 — identity, no direction).
	delete(s.voterRegistry, l2Key)

	// 4. Delete confirm record if present; if present, also decrement
	// ReattestationCount to preserve the structural invariant
	// ReattestationCount ≤ |L2| after this rescission removes the L2 entry.
	// Without this, rescinding a participant who had already re-attested would
	// leave ReattestationCount > |L2|, violating Claim 11's structural cap.
	confirmKey := data.PollID + ":" + data.IdentityHash
	if _, hadConfirm := s.confirms[confirmKey]; hadConfirm {
		delete(s.confirms, confirmKey)
		if p, exists := s.polls[data.PollID]; exists && p.ReattestationCount > 0 {
			p.ReattestationCount--
		}
	}

	// 5. If the rescinded L1 record was in the sealed partition, decrement SealedCount.
	// Preserves the global count-match invariant: |L2| = counted-partition-|L1| + SealedCount.
	// Without this, rescinding a sealed record would cause |L2| to drop by one while
	// SealedCount remains unchanged, breaking the invariant.
	if voteRecord != nil && voteRecord.PartitionID == "sealed" {
		if p, exists := s.polls[data.PollID]; exists && p.SealedCount > 0 {
			p.SealedCount--
		}
	}

	// 6. Update closed-poll tally if present.
	if tally, exists := s.tallies[data.PollID]; exists {
		tally.TotalVotes--
		poll := s.polls[data.PollID]
		if poll != nil && poll.VotingMethod == "ranked" {
			if len(voteRecord.Choices) > 0 {
				tally.Counts[voteRecord.Choices[0]]--
			}
		} else {
			for _, choice := range voteRecord.Choices {
				tally.Counts[choice]--
			}
		}
		tally.RescissionCount++
		tally.AttestationDegraded = true
	}

	// 7. Append-only rescission audit record.
	rescindKey := data.PollID + ":" + data.BallotID
	s.rescissions[rescindKey] = &types.RescindRecord{
		PollID:        data.PollID,
		BallotID:      data.BallotID,
		IdentityHash:  data.IdentityHash,
		RevocationRef: data.RevocationRef,
		Height:        s.height,
	}

	s.dirty = true

	events := []abcitypes.Event{
		{
			Type: "authority_rescind",
			Attributes: []abcitypes.EventAttribute{
				{Key: "scoping_id", Value: data.PollID, Index: true},
				{Key: "submission_id", Value: data.BallotID, Index: true},
				{Key: "identity_hash", Value: data.IdentityHash, Index: false},
				{Key: "revocation_ref", Value: data.RevocationRef, Index: true},
				{Key: "height", Value: fmt.Sprintf("%d", s.height), Index: false},
			},
		},
	}

	s.logger.Info("Two-party authority rescission applied",
		"scoping_id", data.PollID,
		"submission_id", data.BallotID,
		"revocation_ref", data.RevocationRef,
		"height", s.height,
	)

	return events, nil
}

// restoreMessage returns the canonical signed message for a restoration.
// Uses the same four binding fields as rescindMessage so that the restore
// is cross-referenceable to the original rescission without replay risk.
func restoreMessage(pollID, ballotID, identityHash, revocationRef string) []byte {
	return []byte("authority-restore:" + pollID + ":" + ballotID + ":" + identityHash + ":" + revocationRef)
}

// validateAuthorityRestore performs stateful validation of a TxTypeAuthorityRestore.
//
// Verifies:
//  1. Poll exists and has both authority keys registered.
//  2. A RescindRecord exists for this (pollID, ballotID) — restoration presupposes a rescission.
//  3. No RestoreRecord already exists for this (pollID, identityHash) — idempotency guard.
//  4. EligibilitySig is a valid Ed25519 signature over the canonical restore message.
//  5. ReconcilingSig is a valid Ed25519 signature over the canonical restore message.
func (s *State) validateAuthorityRestore(transaction *tx.Tx) error {
	var data tx.AuthorityRestoreData
	if err := transaction.UnmarshalData(&data); err != nil {
		return fmt.Errorf("invalid authority restore data: %w", err)
	}

	poll, ok := s.polls[data.PollID]
	if !ok {
		return fmt.Errorf("poll not found: %s", data.PollID)
	}
	if poll.EligibilityAuthorityPubKey == "" || poll.ReconcilingAuthorityPubKey == "" {
		return fmt.Errorf("poll %s has no authority keys registered: TxTypeAuthorityRestore is only available for count-match deployments with both authority keys", data.PollID)
	}

	eligPubKeyBytes, err := base64.StdEncoding.DecodeString(poll.EligibilityAuthorityPubKey)
	if err != nil || len(eligPubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("stored eligibility_authority_pub_key is invalid")
	}
	reconcilePubKeyBytes, err := base64.StdEncoding.DecodeString(poll.ReconcilingAuthorityPubKey)
	if err != nil || len(reconcilePubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("stored reconciling_authority_pub_key is invalid")
	}

	// A rescission must exist for this ballotID — restore presupposes a prior rescission.
	rescindKey := data.PollID + ":" + data.BallotID
	if _, exists := s.rescissions[rescindKey]; !exists {
		return fmt.Errorf("authority restore: no rescission found for poll=%s ballot=%s; restore presupposes a prior rescission", data.PollID, data.BallotID)
	}

	// Idempotency: reject if a restore already exists for this identity in this poll.
	restoreKey := data.PollID + ":" + data.IdentityHash
	if _, exists := s.restores[restoreKey]; exists {
		return fmt.Errorf("authority restore: restore already granted for identity %s in poll %s", data.IdentityHash, data.PollID)
	}

	msg := restoreMessage(data.PollID, data.BallotID, data.IdentityHash, data.RevocationRef)
	if !ed25519.Verify(ed25519.PublicKey(eligPubKeyBytes), msg, data.EligibilitySig) {
		return fmt.Errorf("authority restore: eligibility authority signature verification failed")
	}
	if !ed25519.Verify(ed25519.PublicKey(reconcilePubKeyBytes), msg, data.ReconcilingSig) {
		return fmt.Errorf("authority restore: reconciling authority signature verification failed")
	}

	return nil
}

// executeAuthorityRestore commits an append-only RestoreRecord granting the
// wrongfully-rescinded participant permission to re-cast. It does NOT directly
// re-insert L1 or L2 entries; the re-cast goes through the normal BallotCast
// path (which checks for a restore grant and bypasses the duplicate-L2 rejection).
// Count-match invariant is preserved throughout: rescission decremented both
// |L1| and |L2|; the subsequent re-cast will increment both atomically.
func (s *State) executeAuthorityRestore(transaction *tx.Tx) ([]abcitypes.Event, error) {
	var data tx.AuthorityRestoreData
	if err := transaction.UnmarshalData(&data); err != nil {
		return nil, fmt.Errorf("invalid authority restore data: %w", err)
	}

	restoreKey := data.PollID + ":" + data.IdentityHash
	s.restores[restoreKey] = &types.RestoreRecord{
		PollID:         data.PollID,
		BallotID:       data.BallotID,
		IdentityHash:   data.IdentityHash,
		RevocationRef:  data.RevocationRef,
		EligibilitySig: data.EligibilitySig,
		ReconcilingSig: data.ReconcilingSig,
		Height:         s.height,
	}

	s.dirty = true

	return []abcitypes.Event{
		{
			Type: "authority_restore",
			Attributes: []abcitypes.EventAttribute{
				{Key: "scoping_id", Value: data.PollID, Index: true},
				{Key: "submission_id", Value: data.BallotID, Index: true},
				// identity_hash intentionally not indexed — prevents on-chain linkage.
				{Key: "revocation_ref", Value: data.RevocationRef, Index: true},
				{Key: "height", Value: fmt.Sprintf("%d", s.height), Index: false},
			},
		},
	}, nil
}

// HasRestoreGrant returns true if a TxTypeAuthorityRestore has been committed
// for this (pollID, identityHash) pair. Used by the BallotCast path to allow
// a wrongfully-rescinded participant to re-cast without triggering the duplicate-L2
// rejection that would normally block a second submission.
func (s *State) HasRestoreGrant(pollID, identityHash string) bool {
	_, ok := s.restores[pollID+":"+identityHash]
	return ok
}

// GetRescissions returns all rescission records for a given poll, for audit use.
func (s *State) GetRescissions(pollID string) []*types.RescindRecord {
	var out []*types.RescindRecord
	prefix := pollID + ":"
	for key, rec := range s.rescissions {
		if len(key) > len(prefix) && key[:len(prefix)] == prefix {
			out = append(out, rec)
		}
	}
	return out
}

// marshalRescissions is a helper used by Commit.
func marshalRescissions(rescissions map[string]*types.RescindRecord) (map[string][]byte, error) {
	out := make(map[string][]byte, len(rescissions))
	for k, r := range rescissions {
		b, err := json.Marshal(r)
		if err != nil {
			return nil, fmt.Errorf("marshal rescind record %s: %w", k, err)
		}
		out[k] = b
	}
	return out, nil
}
