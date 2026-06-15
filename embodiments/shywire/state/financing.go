package state

import (
	"encoding/json"
	"fmt"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/ShywareLLC/community/shywire/tx"
	"github.com/ShywareLLC/community/shywire/types"
)

func (s *State) validateRegisterContract(transaction *tx.Tx) error {
	var d tx.RegisterContractData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return fmt.Errorf("invalid contract data: %w", err)
	}
	if _, exists := s.contracts[d.ContractID]; exists {
		return &types.ErrorDuplicateContract{ContractID: d.ContractID}
	}
	if d.AssetID != "" {
		if _, ok := s.assets[d.AssetID]; !ok {
			return &types.ErrorUnknownAsset{AssetID: d.AssetID}
		}
	}
	for _, p := range d.Parties {
		if p.Commitment == "" {
			continue
		}
		key := "_:" + p.Commitment
		if d.AssetID != "" {
			key = d.AssetID + ":" + p.Commitment
		}
		if _, ok := s.accounts[key]; !ok {
			return fmt.Errorf("party account not registered: %s (role: %s)", p.Commitment, p.Role)
		}
	}
	return nil
}

func (s *State) executeRegisterContract(transaction *tx.Tx) ([]abcitypes.Event, error) {
	var d tx.RegisterContractData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return nil, fmt.Errorf("invalid contract data: %w", err)
	}

	now := time.Now().Unix()
	status := "active"
	if d.PendingCondition {
		status = "pending_condition"
	}

	parties := make([]types.ContractPartyRecord, len(d.Parties))
	for i, p := range d.Parties {
		parties[i] = types.ContractPartyRecord{
			Role:          p.Role,
			Commitment:    p.Commitment,
			AllocationBps: p.AllocationBps,
			Seniority:     p.Seniority,
		}
	}

	s.contracts[d.ContractID] = &types.ContractRecord{
		ContractID:      d.ContractID,
		AssetID:         d.AssetID,
		ContractType:    d.ContractType,
		ContractHash:    d.ContractHash,
		Parties:         parties,
		Metadata:        d.Metadata,
		ExpiryTimestamp: d.ExpiryTimestamp,
		Status:          status,
		CreatedAt:       now,
		UpdatedAt:       now,
		Height:          s.height,
	}

	s.dirty = true
	return []abcitypes.Event{
		{
			Type: "register_contract",
			Attributes: []abcitypes.EventAttribute{
				{Key: "contract_id",   Value: d.ContractID,   Index: true},
				{Key: "contract_type", Value: d.ContractType,  Index: true},
				{Key: "asset_id",      Value: d.AssetID,       Index: true},
			},
		},
	}, nil
}

func (s *State) validateActivateContract(transaction *tx.Tx) error {
	var d tx.ActivateContractData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return fmt.Errorf("invalid contract activation data: %w", err)
	}
	contract, ok := s.contracts[d.ContractID]
	if !ok {
		return &types.ErrorUnknownContract{ContractID: d.ContractID}
	}
	if contract.Status != "pending_condition" {
		return fmt.Errorf("contract is not pending activation: %s (status: %s)", d.ContractID, contract.Status)
	}
	return nil
}

func (s *State) executeActivateContract(transaction *tx.Tx) ([]abcitypes.Event, error) {
	var d tx.ActivateContractData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return nil, fmt.Errorf("invalid contract activation data: %w", err)
	}

	contract := s.contracts[d.ContractID]
	contract.ConditionHash = d.EvidenceHash
	contract.ConditionType = d.EvidenceType
	contract.ActivatedAt   = d.ActivatedAt
	contract.Status        = "active"
	contract.UpdatedAt     = time.Now().Unix()
	contract.Height        = s.height

	s.dirty = true
	return []abcitypes.Event{
		{
			Type: "activate_contract",
			Attributes: []abcitypes.EventAttribute{
				{Key: "contract_id",    Value: d.ContractID,   Index: true},
				{Key: "evidence_type",  Value: d.EvidenceType,  Index: true},
			},
		},
	}, nil
}

func (s *State) validateExecuteContract(transaction *tx.Tx) error {
	var d tx.ExecuteContractData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return fmt.Errorf("invalid contract execution data: %w", err)
	}

	contract, ok := s.contracts[d.ContractID]
	if !ok {
		return &types.ErrorUnknownContract{ContractID: d.ContractID}
	}
	if contract.Status != "active" {
		return &types.ErrorContractNotActive{ContractID: d.ContractID}
	}
	if contract.ExpiryTimestamp > 0 && d.Timestamp > contract.ExpiryTimestamp {
		return &types.ErrorContractExpired{ContractID: d.ContractID}
	}
	if _, exists := s.participants[d.Nullifier]; exists {
		return &types.ErrorDuplicateTransfer{IdentityHash: d.Nullifier}
	}

	// Value-bearing executions: validate balance.
	if d.AssetID != "" && d.Amount > 0 {
		if contract.AssetID != "" && contract.AssetID != d.AssetID {
			return fmt.Errorf("asset mismatch for contract %s", d.ContractID)
		}
		senderKey := d.AssetID + ":" + d.PartyCommitment
		acct, ok := s.accounts[senderKey]
		if !ok {
			return fmt.Errorf("party account not found: %s", d.PartyCommitment)
		}
		if acct.Balance < d.Amount {
			return &types.ErrorInsufficientBalance{
				AccountCommitment: d.PartyCommitment,
				AssetID:           d.AssetID,
				Have:              acct.Balance,
				Need:              d.Amount,
			}
		}
		if d.CounterpartyCommitment != "" {
			recipientKey := d.AssetID + ":" + d.CounterpartyCommitment
			if _, ok := s.accounts[recipientKey]; !ok {
				return fmt.Errorf("counterparty account not registered: %s", d.CounterpartyCommitment)
			}
		}
	}

	return nil
}

func (s *State) executeExecuteContract(transaction *tx.Tx) ([]abcitypes.Event, error) {
	var d tx.ExecuteContractData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return nil, fmt.Errorf("invalid contract execution data: %w", err)
	}

	now := time.Now().Unix()
	executionID := hashNonce(d.TransferNonce)

	// List 1 — execution record (no party identity)
	s.transferRecords[executionID] = &types.TransferRecord{
		TransferID: executionID,
		AssetID:    d.AssetID,
		Amount:     d.Amount,
		Timestamp:  now,
		Height:     s.height,
	}

	// List 2 — party identity (no execution payload)
	s.participants[d.Nullifier] = &types.ParticipantRecord{
		TransferID:   executionID,
		IdentityHash: d.Nullifier,
		Height:       s.height,
	}

	// Indexed execution overlay
	s.contractExecutions[executionID] = &types.ContractExecutionRecord{
		ExecutionID:   executionID,
		ContractID:    d.ContractID,
		AssetID:       d.AssetID,
		ExecutionType: d.ExecutionType,
		SourceRef:     d.SourceRef,
		Amount:        d.Amount,
		Payload:       d.Payload,
		Timestamp:     now,
		Height:        s.height,
	}

	// Value movement
	if d.AssetID != "" && d.Amount > 0 {
		senderKey := d.AssetID + ":" + d.PartyCommitment
		s.accounts[senderKey].Balance -= d.Amount
		s.accounts[senderKey].UpdatedAt = now
		s.accounts[senderKey].Height = s.height

		if d.CounterpartyCommitment != "" {
			recipientKey := d.AssetID + ":" + d.CounterpartyCommitment
			s.accounts[recipientKey].Balance += d.Amount
			s.accounts[recipientKey].UpdatedAt = now
			s.accounts[recipientKey].Height = s.height
		}
	}

	contract := s.contracts[d.ContractID]
	contract.ExecutionCount++
	contract.TotalExecuted += d.Amount
	contract.UpdatedAt = now
	contract.Height = s.height

	s.dirty = true
	return []abcitypes.Event{
		{
			Type: "contract_execution",
			Attributes: []abcitypes.EventAttribute{
				{Key: "contract_id",    Value: d.ContractID,    Index: true},
				{Key: "execution_id",   Value: executionID,     Index: true},
				{Key: "execution_type", Value: d.ExecutionType, Index: true},
				{Key: "source_ref",     Value: d.SourceRef,     Index: true},
			},
		},
	}, nil
}
