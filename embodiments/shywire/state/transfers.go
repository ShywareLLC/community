package state

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/ShywareLLC/community/shywire/tx"
	"github.com/ShywareLLC/community/shywire/types"
)

// validateTransfer enforces the two-list invariants and value conservation.
func (s *State) validateTransfer(transaction *tx.Tx) error {
	var d tx.TransferData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return fmt.Errorf("invalid transfer data: %w", err)
	}

	// Asset must exist.
	if _, ok := s.assets[d.AssetID]; !ok {
		return &types.ErrorUnknownAsset{AssetID: d.AssetID}
	}

	// Nullifier deduplication — List 2 invariant.
	// The same (wallet, transfer_id) pair can never be used twice.
	if _, exists := s.participants[d.Nullifier]; exists {
		return &types.ErrorDuplicateTransfer{IdentityHash: d.Nullifier}
	}

	// Sender account must exist, be active, and have sufficient balance.
	senderKey := d.AssetID + ":" + d.SenderCommitment
	acct, ok := s.accounts[senderKey]
	if !ok {
		return fmt.Errorf("sender account not found: %s", d.SenderCommitment)
	}
	if acct.Disabled {
		return &types.ErrorAccountDisabled{AccountCommitment: d.SenderCommitment}
	}
	if acct.Frozen {
		return &types.ErrorAccountFrozen{AccountCommitment: d.SenderCommitment}
	}
	if acct.Balance < d.Amount {
		return &types.ErrorInsufficientBalance{
			AccountCommitment: d.SenderCommitment,
			AssetID:           d.AssetID,
			Have:              acct.Balance,
			Need:              d.Amount,
		}
	}

	// Recipient account must be registered and not disabled.
	// Frozen accounts may still receive (AML hold blocks sends, not receives).
	recipientKey := d.AssetID + ":" + d.RecipientCommitment
	recipAcct, ok := s.accounts[recipientKey]
	if !ok {
		return fmt.Errorf("recipient account not registered: %s", d.RecipientCommitment)
	}
	if recipAcct.Disabled {
		return &types.ErrorAccountDisabled{AccountCommitment: d.RecipientCommitment}
	}

	return nil
}

// executeTransfer applies the two-list transfer:
//
//	List 1: transfer_id = H(TransferNonce) → TransferRecord{amount, asset}
//	List 2: nullifier                       → ParticipantRecord{identity only}
//
// Value conservation: sender.Balance -= Amount, recipient.Balance += Amount.
// The two deltas are equal; no value is created or destroyed.
func (s *State) executeTransfer(transaction *tx.Tx) ([]abcitypes.Event, error) {
	var d tx.TransferData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return nil, fmt.Errorf("invalid transfer data: %w", err)
	}

	now := time.Now().Unix()

	// List 1: anonymous transfer record — amount and asset, no identity.
	transferID := hashNonce(d.TransferNonce)
	s.transferRecords[transferID] = &types.TransferRecord{
		TransferID: transferID,
		AssetID:    d.AssetID,
		Amount:     d.Amount,
		Timestamp:  now,
		Height:     s.height,
	}

	// List 2: participant record — who transferred, no amount.
	s.participants[d.Nullifier] = &types.ParticipantRecord{
		TransferID:   transferID,
		IdentityHash: d.Nullifier,
		Height:       s.height,
	}

	// Value conservation: debit sender, credit recipient.
	senderKey := d.AssetID + ":" + d.SenderCommitment
	s.accounts[senderKey].Balance -= d.Amount
	s.accounts[senderKey].Height = s.height

	recipientKey := d.AssetID + ":" + d.RecipientCommitment
	s.accounts[recipientKey].Balance += d.Amount
	s.accounts[recipientKey].Height = s.height

	s.dirty = true

	// Events: emit asset_id and transfer_id only — never amount, sender, or recipient.
	return []abcitypes.Event{
		{
			Type: "transfer",
			Attributes: []abcitypes.EventAttribute{
				{Key: "asset_id", Value: d.AssetID, Index: true},
				{Key: "transfer_id", Value: transferID, Index: true},
			},
		},
	}, nil
}

// validateRegisterAccount checks the account commitment is not already registered.
func (s *State) validateRegisterAccount(transaction *tx.Tx) error {
	var d tx.RegisterAccountData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return fmt.Errorf("invalid register account data: %w", err)
	}
	if err := verifyRegisterAccountWalletProof(d); err != nil {
		return fmt.Errorf("wallet ownership proof rejected: %w", err)
	}
	if err := verifyRegisterAccountEnrollment(d, s.enrollmentAuthorityPubKey, s.enrollmentRecords); err != nil {
		return err
	}
	// Allow registering for multiple assets; key includes asset_id.
	// Registration without asset_id registers the commitment itself.
	if _, exists := s.accounts["_:"+d.AccountCommitment]; exists {
		return fmt.Errorf("account already registered: %s", d.AccountCommitment)
	}
	return nil
}

// executeRegisterAccount registers an account_commitment on-chain.
// The wallet_address is never stored — only H(wallet_address).
func (s *State) executeRegisterAccount(transaction *tx.Tx) ([]abcitypes.Event, error) {
	var d tx.RegisterAccountData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return nil, fmt.Errorf("invalid register account data: %w", err)
	}

	// Register the commitment in the accounts map under a sentinel asset key.
	// When an asset is minted to this commitment, a proper asset-scoped entry is created.
	s.accounts["_:"+d.AccountCommitment] = &types.AccountRecord{
		AccountCommitment: d.AccountCommitment,
		AssetID:           "_",
		Balance:           0,
		Height:            s.height,
	}
	if d.EnrollmentToken != "" {
		s.enrollmentRecords[d.EnrollmentToken] = &types.EnrollmentRecord{
			Token:             d.EnrollmentToken,
			AccountCommitment: d.AccountCommitment,
			Height:            s.height,
		}
	}

	s.dirty = true
	return []abcitypes.Event{
		{
			Type: "register_account",
			Attributes: []abcitypes.EventAttribute{
				{Key: "account_commitment", Value: d.AccountCommitment, Index: true},
			},
		},
	}, nil
}

// hashNonce returns H(nonce) as a hex string — the transfer_id / ballot_id equivalent.
func hashNonce(nonce string) string {
	h := sha256.Sum256([]byte(nonce))
	return fmt.Sprintf("%x", h)
}
