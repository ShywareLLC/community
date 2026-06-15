package state

import (
	"encoding/json"
	"fmt"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/ShywareLLC/community/shywire/tx"
	"github.com/ShywareLLC/community/shywire/types"
)

func (s *State) validateRegisterAsset(transaction *tx.Tx) error {
	var d tx.RegisterAssetData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return fmt.Errorf("invalid register asset data: %w", err)
	}
	if _, exists := s.assets[d.AssetID]; exists {
		return fmt.Errorf("asset already registered: %s", d.AssetID)
	}
	return nil
}

func (s *State) executeRegisterAsset(transaction *tx.Tx) ([]abcitypes.Event, error) {
	var d tx.RegisterAssetData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return nil, fmt.Errorf("invalid register asset data: %w", err)
	}

	now := time.Now().Unix()
	s.assets[d.AssetID] = &types.AssetRecord{
		AssetID:     d.AssetID,
		Name:        d.Name,
		Decimals:    d.Decimals,
		TotalSupply: 0,
		CreatedAt:   now,
	}
	s.supply[d.AssetID] = &types.SupplyRecord{
		AssetID:     d.AssetID,
		TotalMinted: 0,
		TotalBurned: 0,
		TotalSupply: 0,
		UpdatedAt:   now,
	}

	s.dirty = true
	return []abcitypes.Event{
		{Type: "register_asset", Attributes: []abcitypes.EventAttribute{
			{Key: "asset_id", Value: d.AssetID, Index: true},
		}},
	}, nil
}

func (s *State) validateMint(transaction *tx.Tx) error {
	var d tx.MintData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return fmt.Errorf("invalid mint data: %w", err)
	}
	if _, ok := s.assets[d.AssetID]; !ok {
		return &types.ErrorUnknownAsset{AssetID: d.AssetID}
	}
	return nil
}

// executeMint credits amount to account and increases supply.
// Supply invariant: TotalSupply = TotalMinted - TotalBurned.
func (s *State) executeMint(transaction *tx.Tx) ([]abcitypes.Event, error) {
	var d tx.MintData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return nil, fmt.Errorf("invalid mint data: %w", err)
	}

	now := time.Now().Unix()
	key := d.AssetID + ":" + d.AccountCommitment

	if _, ok := s.accounts[key]; !ok {
		s.accounts[key] = &types.AccountRecord{
			AccountCommitment: d.AccountCommitment,
			AssetID:           d.AssetID,
			Balance:           0,
			Height:            s.height,
		}
	}
	s.accounts[key].Balance += d.Amount
	s.accounts[key].UpdatedAt = now
	s.accounts[key].Height = s.height

	sup := s.supply[d.AssetID]
	sup.TotalMinted += d.Amount
	sup.TotalSupply = sup.TotalMinted - sup.TotalBurned
	sup.UpdatedAt = now
	s.assets[d.AssetID].TotalSupply = sup.TotalSupply

	s.dirty = true
	return []abcitypes.Event{
		{Type: "mint", Attributes: []abcitypes.EventAttribute{
			{Key: "asset_id", Value: d.AssetID, Index: true},
			// Do NOT emit account_commitment or amount in events — privacy guardrail.
		}},
	}, nil
}

func (s *State) validateBurn(transaction *tx.Tx) error {
	var d tx.BurnData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return fmt.Errorf("invalid burn data: %w", err)
	}
	if _, ok := s.assets[d.AssetID]; !ok {
		return &types.ErrorUnknownAsset{AssetID: d.AssetID}
	}
	key := d.AssetID + ":" + d.AccountCommitment
	acct, ok := s.accounts[key]
	if !ok {
		return fmt.Errorf("account not found: %s", d.AccountCommitment)
	}
	if acct.Balance < d.Amount {
		return &types.ErrorInsufficientBalance{
			AccountCommitment: d.AccountCommitment,
			AssetID:           d.AssetID,
			Have:              acct.Balance,
			Need:              d.Amount,
		}
	}
	return nil
}

func (s *State) executeBurn(transaction *tx.Tx) ([]abcitypes.Event, error) {
	var d tx.BurnData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return nil, fmt.Errorf("invalid burn data: %w", err)
	}

	now := time.Now().Unix()
	key := d.AssetID + ":" + d.AccountCommitment
	s.accounts[key].Balance -= d.Amount
	s.accounts[key].UpdatedAt = now
	s.accounts[key].Height = s.height

	sup := s.supply[d.AssetID]
	sup.TotalBurned += d.Amount
	sup.TotalSupply = sup.TotalMinted - sup.TotalBurned
	sup.UpdatedAt = now
	s.assets[d.AssetID].TotalSupply = sup.TotalSupply

	s.dirty = true
	return []abcitypes.Event{
		{Type: "burn", Attributes: []abcitypes.EventAttribute{
			{Key: "asset_id", Value: d.AssetID, Index: true},
		}},
	}, nil
}
