package state

import (
	"fmt"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/ShywareLLC/community/protocol/tx"
	"github.com/ShywareLLC/community/protocol/types"
)

// validateConfirmReceipt validates a confirm-receipt transaction.
//
// Rules:
//  1. Poll must exist and have started.
//  2. A valid IDV attestation must be present (Didit, Identus, ZK, or Wallet).
//     This proves a genuine biometric re-authentication occurred — the
//     confirmed-count Sybil signal is structural, not behavioral.
//  3. The identity_hash derived from the attestation must match a registered
//     entry in the voter registry.
//  4. Must not already be confirmed.
func (s *State) validateConfirmReceipt(transaction *tx.Tx) error {
	var data tx.ConfirmReceiptData
	if err := transaction.UnmarshalData(&data); err != nil {
		return fmt.Errorf("invalid confirm receipt data: %w", err)
	}

	poll, exists := s.polls[data.PollID]
	if !exists {
		return fmt.Errorf("poll not found: %s", data.PollID)
	}
	if time.Now().Unix() < poll.StartTime {
		return fmt.Errorf("poll %s has not started; receipts cannot be confirmed yet", data.PollID)
	}

	if s.verifier == nil {
		return fmt.Errorf("no identity verifier configured for this deployment")
	}

	// IDV attestation + identity_hash derivation — provider-agnostic.
	identityHash, err := s.verifier.VerifyAndIdentifyConfirm(&data)
	if err != nil {
		return fmt.Errorf("confirm-receipt attestation invalid for poll %s: %w", data.PollID, err)
	}

	// Registry lookup uses the state-machine-derived identity_hash, not the client hint.
	registryKey := data.PollID + ":" + identityHash
	if _, exists := s.voterRegistry[registryKey]; !exists {
		return fmt.Errorf("identity_hash %s has no ballot in poll %s", identityHash, data.PollID)
	}

	if _, exists := s.confirms[registryKey]; exists {
		return fmt.Errorf("receipt already confirmed for identity_hash %s in poll %s", identityHash, data.PollID)
	}

	return nil
}

// executeConfirmReceipt writes a ConfirmRecord, updates any final tally already
// present for the poll, marks state dirty, and emits an opaque aggregate event.
func (s *State) executeConfirmReceipt(transaction *tx.Tx) ([]abcitypes.Event, error) {
	var data tx.ConfirmReceiptData
	if err := transaction.UnmarshalData(&data); err != nil {
		return nil, fmt.Errorf("invalid confirm receipt data: %w", err)
	}

	// Re-derive identity_hash (already validated — this cannot fail).
	identityHash, err := s.verifier.VerifyAndIdentifyConfirm(&data)
	if err != nil {
		return nil, fmt.Errorf("confirm-receipt attestation error during execute: %w", err)
	}

	confirmKey := data.PollID + ":" + identityHash
	nextHeight := s.height + 1

	s.confirms[confirmKey] = &types.ConfirmRecord{
		PollID:       data.PollID,
		IdentityHash: identityHash,
		Height:       nextHeight,
	}

	// Increment the persistent re-attestation counter on the poll record.
	// ReattestationCount is structurally capped at |L2| by the idempotency
	// check in validateConfirmReceipt — a second confirm for the same
	// identity_hash is rejected before this path is reached (Claim 9, Claim 49).
	if p, exists := s.polls[data.PollID]; exists {
		p.ReattestationCount++
	}

	if t, exists := s.tallies[data.PollID]; exists {
		t.ConfirmedCount = s.confirmedCountForPoll(data.PollID)
	}

	s.dirty = true

	s.logger.Info("Receipt confirmed",
		"scoping_id", data.PollID,
		"identity_hash", identityHash,
	)

	return []abcitypes.Event{{
		Type: "confirmation_processed",
		Attributes: []abcitypes.EventAttribute{
			{Key: "scoping_id", Value: data.PollID, Index: true},
		},
	}}, nil
}
