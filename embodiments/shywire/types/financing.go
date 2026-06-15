package types

import "encoding/json"

// ContractPartyRecord captures an anonymous party's role and commitment in a contract.
type ContractPartyRecord struct {
	Role          string `json:"role"`
	Commitment    string `json:"commitment"`
	AllocationBps uint32 `json:"allocation_bps"`
	Seniority     uint32 `json:"seniority"`
}

// ContractRecord anchors an anonymous contract on-chain.
// Commercial terms remain off-chain; ContractHash binds them without revealing them.
// Metadata is domain-specific (e.g. RBF fields) written to canonical state as-is.
// ExecutionCount tracks |L1(contractID)| = |L2(contractID)| — each execution atomically
// writes one transferRecord (List 1) and one participant (List 2) entry.
type ContractRecord struct {
	ContractID      string                `json:"contract_id"`
	AssetID         string                `json:"asset_id,omitempty"`
	ContractType    string                `json:"contract_type"`
	ContractHash    string                `json:"contract_hash"`
	Parties         []ContractPartyRecord `json:"parties"`
	Metadata        json.RawMessage       `json:"metadata,omitempty"`
	ConditionHash   string                `json:"condition_hash,omitempty"`
	ConditionType   string                `json:"condition_type,omitempty"`
	ActivatedAt     int64                 `json:"activated_at,omitempty"`
	ExecutionCount  int64                 `json:"execution_count"`
	TotalExecuted   int64                 `json:"total_executed,omitempty"`
	ExpiryTimestamp int64                 `json:"expiry_timestamp,omitempty"`
	Status          string                `json:"status"` // pending_condition | active | completed | expired
	CreatedAt       int64                 `json:"created_at"`
	UpdatedAt       int64                 `json:"updated_at"`
	Height          int64                 `json:"height"`
}

// ContractExecutionRecord is an indexed overlay on the standard transfer list.
// TransferRecord (List 1) holds asset_id + amount with no identity.
// This record links the execution to a contract and carries domain payload.
type ContractExecutionRecord struct {
	ExecutionID   string          `json:"execution_id"`
	ContractID    string          `json:"contract_id"`
	AssetID       string          `json:"asset_id,omitempty"`
	ExecutionType string          `json:"execution_type"`
	SourceRef     string          `json:"source_ref"`
	Amount        int64           `json:"amount,omitempty"`
	Payload       json.RawMessage `json:"payload,omitempty"`
	Timestamp     int64           `json:"timestamp"`
	Height        int64           `json:"height"`
}

type ErrorDuplicateContract struct{ ContractID string }

func (e *ErrorDuplicateContract) Error() string { return "duplicate contract: " + e.ContractID }

type ErrorUnknownContract struct{ ContractID string }

func (e *ErrorUnknownContract) Error() string { return "unknown contract: " + e.ContractID }

type ErrorContractNotActive struct{ ContractID string }

func (e *ErrorContractNotActive) Error() string {
	return "contract is not active: " + e.ContractID
}

type ErrorContractExpired struct{ ContractID string }

func (e *ErrorContractExpired) Error() string { return "contract expired: " + e.ContractID }
