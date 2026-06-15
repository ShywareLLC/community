package state

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/ShywareLLC/community/shywire/tx"
	"github.com/ShywareLLC/community/shywire/types"
)

// adverseActionCanonicalMessage returns the bytes that both the eligibility
// authority and the reconciling authority must sign. The message is bound to
// every field that determines the semantics of the action (type, target, scope,
// identity, timestamp) so that neither authority can be replayed across actions.
//
// Neither auth field is included (they are the outputs, not inputs).
func adverseActionCanonicalMessage(d tx.AdverseActionData) []byte {
	msg := "shyware-adverse-action:" +
		d.ActionType + ":" +
		d.AccountCommitment + ":" +
		d.AssetID + ":" +
		d.ActionID + ":" +
		strconv.FormatInt(d.Timestamp, 10)
	h := sha256.Sum256([]byte(msg))
	return h[:]
}

// validateAdverseAction enforces the two-party threshold invariant:
//  1. action_id must equal H(action_nonce) — binds the identifier to the nonce.
//  2. Both eligibility authority and reconciling authority signatures must be valid
//     over the canonical action message.
//  3. The target account must exist in canonical state.
//  4. The action_id must not already be in the authority-action log (replay prevention).
func (s *State) validateAdverseAction(transaction *tx.Tx) error {
	if len(s.eligibilityAuthorityPubKey) == 0 || len(s.reconciliationAuthorityPubKey) == 0 {
		return fmt.Errorf("adverse action: authority keys not configured on this deployment")
	}

	var d tx.AdverseActionData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return fmt.Errorf("invalid adverse action data: %w", err)
	}

	// Verify action_id == H(action_nonce).
	expectedID := hashNonce(d.ActionNonce)
	if d.ActionID != expectedID {
		return fmt.Errorf("adverse action: action_id does not match H(action_nonce)")
	}

	// Replay prevention: action_id must not already exist.
	if _, exists := s.authorityActions[d.ActionID]; exists {
		return fmt.Errorf("adverse action: action_id %s already committed", d.ActionID)
	}

	// Target account must exist (at least the sentinel registration).
	// Check the sentinel key first; asset-scoped keys are updated by executeAdverseAction.
	if _, ok := s.accounts["_:"+d.AccountCommitment]; !ok {
		return fmt.Errorf("adverse action: account not found: %s", d.AccountCommitment)
	}

	// For "restore" actions: if ReferencedActionID is set, verify it exists in the
	// append-only log. This makes the appeal linkage explicit and on-chain verifiable —
	// the participant presents the prior action record as evidence; the restoring
	// authorities bind their signatures to that specific action_id.
	if d.ActionType == "restore" && d.ReferencedActionID != "" {
		if _, exists := s.authorityActions[d.ReferencedActionID]; !exists {
			return fmt.Errorf("adverse action: referenced_action_id %s not found in authority-action log", d.ReferencedActionID)
		}
	}

	// Verify two-party threshold signatures.
	msg := adverseActionCanonicalMessage(d)
	if !ed25519.Verify(s.eligibilityAuthorityPubKey, msg, d.EligibilityAuth) {
		return fmt.Errorf("adverse action: invalid eligibility authority signature")
	}
	if !ed25519.Verify(s.reconciliationAuthorityPubKey, msg, d.ReconciliationAuth) {
		return fmt.Errorf("adverse action: invalid reconciliation authority signature")
	}

	return nil
}

// executeAdverseAction commits an append-only AuthorityActionRecord and updates
// the Disabled / Frozen flags on all matching AccountRecord entries.
//
// The record is never deleted — it is the permanent on-chain evidence of the action.
// A subsequent "restore" action clears the flags but does not remove earlier records.
func (s *State) executeAdverseAction(transaction *tx.Tx) ([]abcitypes.Event, error) {
	var d tx.AdverseActionData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return nil, fmt.Errorf("invalid adverse action data: %w", err)
	}

	now := time.Now().Unix()

	// Write the append-only authority-action record.
	s.authorityActions[d.ActionID] = &types.AuthorityActionRecord{
		ActionID:           d.ActionID,
		AccountCommitment:  d.AccountCommitment,
		AssetID:            d.AssetID,
		ActionType:         d.ActionType,
		ReferencedActionID: d.ReferencedActionID,
		EligibilityAuth:    d.EligibilityAuth,
		ReconciliationAuth: d.ReconciliationAuth,
		Reason:             d.Reason,
		Timestamp:          now,
		Height:             s.height,
	}

	// Apply the action to every matching AccountRecord.
	// If AssetID is empty, the action applies to all assets for this commitment.
	for key, acct := range s.accounts {
		if acct.AccountCommitment != d.AccountCommitment {
			continue
		}
		if d.AssetID != "" && acct.AssetID != d.AssetID {
			continue
		}
		switch d.ActionType {
		case "disable", "rescind":
			acct.Disabled = true
			acct.Frozen = false // disabled supersedes frozen
		case "freeze":
			if !acct.Disabled {
				acct.Frozen = true
			}
		case "restore":
			acct.Disabled = false
			acct.Frozen = false
		case "redeem_forced":
			// Forced redemption: mark disabled and zero the balance.
			// The value-bearing history (transferRecords) is preserved.
			// Full settlement requires a subsequent Burn tx issued by the operator.
			acct.Disabled = true
			acct.Balance = 0
		}
		acct.Height = s.height
		s.accounts[key] = acct
	}

	s.dirty = true

	return []abcitypes.Event{
		{
			Type: "adverse_action",
			Attributes: []abcitypes.EventAttribute{
				{Key: "action_id", Value: d.ActionID, Index: true},
				{Key: "action_type", Value: d.ActionType, Index: true},
				// account_commitment and asset_id are intentionally omitted from
				// indexed events to prevent on-chain linkage of identity to action.
			},
		},
	}, nil
}
