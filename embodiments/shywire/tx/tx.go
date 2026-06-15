package tx

import (
	"encoding/json"
	"fmt"
)

// Wire-format discriminators for shyware transactions.
const (
	TxTypeRegisterAsset             uint8 = 1 // operator registers a new asset
	TxTypeMint                      uint8 = 2 // operator mints supply to an account
	TxTypeBurn                      uint8 = 3 // operator burns supply from an account
	TxTypeTransfer                  uint8 = 4 // anonymous transfer between accounts
	TxTypeRegisterAccount           uint8 = 5 // register an account commitment on-chain
	TxTypeRegisterValidator         uint8 = 6 // add or remove a consensus validator
	TxTypeRegisterContract uint8 = 7 // register an anonymous contract with parties and off-chain terms hash
	TxTypeExecuteContract  uint8 = 8 // record a contract execution event (value-bearing or pure state)
	TxTypeActivateContract uint8 = 9 // transition contract from pending_condition to active
	TxTypeRegisterConsortiumPolicy  uint8 = 10
	TxTypeRegisterWarehouseOperator uint8 = 11
	TxTypeRegisterAcceptedSkuClass  uint8 = 12
	TxTypeRecordCustodyIntakeLot    uint8 = 13
	TxTypeRequestCustodyRedemption  uint8 = 14
	TxTypeSettleCustodyRedemption   uint8 = 15
	TxTypeApplyCustodyDemurrage     uint8 = 16
	TxTypeAdverseAction             uint8 = 17 // two-party threshold authority action against an account
)

// Tx is the canonical transaction envelope, identical in structure to protocol/tx.Tx.
type Tx struct {
	Type      uint8           `json:"type"`
	Signature []byte          `json:"signature"`
	Data      json.RawMessage `json:"data"`
}

type RegisterAssetData struct {
	AssetID  string `json:"asset_id"`
	Name     string `json:"name"`
	Decimals uint8  `json:"decimals"`
}

type MintData struct {
	AssetID           string `json:"asset_id"`
	AccountCommitment string `json:"account_commitment"`
	Amount            int64  `json:"amount"`
	Timestamp         int64  `json:"timestamp"`
}

type BurnData struct {
	AssetID           string `json:"asset_id"`
	AccountCommitment string `json:"account_commitment"`
	Amount            int64  `json:"amount"`
	Timestamp         int64  `json:"timestamp"`
}

// TransferData is an anonymous transfer between two accounts.
// TODO(circuit): SenderProof will carry the Pedersen commitment proof that
// proves balance >= Amount without revealing either balance or amount.
type TransferData struct {
	AssetID             string `json:"asset_id"`
	SenderCommitment    string `json:"sender_commitment"`
	RecipientCommitment string `json:"recipient_commitment"`
	Amount              int64  `json:"amount"`
	Nullifier           string `json:"nullifier"`
	TransferNonce       string `json:"submission_nonce"`
	SenderProof         []byte `json:"sender_proof"`
	Timestamp           int64  `json:"timestamp"`
}

type RegisterAccountData struct {
	AccountCommitment string `json:"account_commitment"`
	WalletProof       []byte `json:"wallet_proof"`
	EnrollmentToken   string `json:"enrollment_token,omitempty"`
	EnrollmentProof   []byte `json:"enrollment_proof,omitempty"`
}

type ValidatorRegistrationData struct {
	PubKeyBase64 string `json:"pub_key_base64"`
	Power        int64  `json:"power"`
	Name         string `json:"name"`
}

type ContractParty struct {
	Role          string `json:"role"`
	Commitment    string `json:"commitment"`
	AllocationBps uint32 `json:"allocation_bps"`
	Seniority     uint32 `json:"seniority"`
}

// RegisterContractData anchors an anonymous contract on-chain.
// Parties carry role labels and commitments. ContractHash binds to off-chain terms.
// Metadata is domain-specific and written to canonical state as-is.
// PendingCondition=true starts the contract in pending_condition state;
// a subsequent TxTypeActivateContract with evidence is required to make it active.
type RegisterContractData struct {
	ContractID       string          `json:"contract_id"`
	AssetID          string          `json:"asset_id,omitempty"`
	ContractType     string          `json:"contract_type"`
	ContractHash     string          `json:"contract_hash"`
	Parties          []ContractParty `json:"parties"`
	Metadata         json.RawMessage `json:"metadata,omitempty"`
	PendingCondition bool            `json:"pending_condition,omitempty"`
	ExpiryTimestamp  int64           `json:"expiry_timestamp"`
	Timestamp        int64           `json:"timestamp"`
}

// ActivateContractData transitions a contract from pending_condition to active.
type ActivateContractData struct {
	ContractID    string `json:"contract_id"`
	EvidenceHash  string `json:"evidence_hash"`
	EvidenceType  string `json:"evidence_type"`
	ActivatedAt   int64  `json:"activated_at"`
}

// ExecuteContractData records a contract execution event on-chain.
// Value-bearing executions include AssetID and Amount; pure state executions omit them.
// Nullifier = H(PartyCommitment:ContractID:SourceRef) — idempotent on SourceRef.
type ExecuteContractData struct {
	ContractID             string          `json:"contract_id"`
	AssetID                string          `json:"asset_id,omitempty"`
	PartyCommitment        string          `json:"party_commitment"`
	CounterpartyCommitment string          `json:"counterparty_commitment,omitempty"`
	ExecutionType          string          `json:"execution_type"`
	SourceRef              string          `json:"source_ref"`
	Amount                 int64           `json:"amount,omitempty"`
	Payload                json.RawMessage `json:"payload,omitempty"`
	Nullifier              string          `json:"nullifier"`
	TransferNonce          string          `json:"transfer_nonce"`
	Timestamp              int64           `json:"timestamp"`
}

type RegisterConsortiumPolicyData struct {
	PolicyID              string   `json:"policy_id"`
	AssetID               string   `json:"asset_id"`
	Name                  string   `json:"name"`
	ActiveOperatorIDs     []string `json:"active_operator_ids"`
	AcceptedSkuClassIDs   []string `json:"accepted_sku_class_ids"`
	UnitOfMeasure         string   `json:"unit_of_measure"`
	QuantityNormalization string   `json:"quantity_normalization"`
	ShippingAdjustmentRef string   `json:"shipping_adjustment_ref"`
	DemurrageRateBps      uint32   `json:"demurrage_rate_bps"`
	OperatorFeeBps        uint32   `json:"operator_fee_bps"`
	RedemptionMode        string   `json:"redemption_mode"`
	RedemptionRouting     string   `json:"redemption_routing"`
	EvidenceRequirements  []string `json:"evidence_requirements"`
	Timestamp             int64    `json:"timestamp"`
}

type RegisterWarehouseOperatorData struct {
	OperatorID     string `json:"operator_id"`
	Name           string `json:"name"`
	WarehouseID    string `json:"warehouse_id"`
	Region         string `json:"region"`
	VideoStreamRef string `json:"video_stream_ref"`
	Status         string `json:"status"`
	Timestamp      int64  `json:"timestamp"`
}

type RegisterAcceptedSkuClassData struct {
	SkuClassID          string `json:"sku_class_id"`
	Name                string `json:"name"`
	GradeBand           string `json:"grade_band"`
	UnitOfMeasure       string `json:"unit_of_measure"`
	NormalizedFactorBps uint32 `json:"normalized_factor_bps"`
	StorageClass        string `json:"storage_class"`
	Status              string `json:"status"`
	Timestamp           int64  `json:"timestamp"`
}

type RecordCustodyIntakeLotData struct {
	LotID                string   `json:"lot_id"`
	PolicyID             string   `json:"policy_id"`
	AssetID              string   `json:"asset_id"`
	OperatorID           string   `json:"operator_id"`
	WarehouseID          string   `json:"warehouse_id"`
	AccountCommitment    string   `json:"account_commitment"`
	SkuClassID           string   `json:"sku_class_id"`
	Quantity             int64    `json:"quantity"`
	MintedAmount         int64    `json:"minted_amount"`
	OperatorFeeAmount    int64    `json:"operator_fee_amount"`
	ShippingCostAmount   int64    `json:"shipping_cost_amount"`
	StorageReserveAmount int64    `json:"storage_reserve_amount"`
	VideoSessionRef      string   `json:"video_session_ref"`
	EvidenceRefs         []string `json:"evidence_refs"`
	Timestamp            int64    `json:"timestamp"`
}

type RequestCustodyRedemptionData struct {
	RequestID         string `json:"request_id"`
	AssetID           string `json:"asset_id"`
	AccountCommitment string `json:"account_commitment"`
	WarehouseID       string `json:"warehouse_id"`
	SkuClassID        string `json:"sku_class_id"`
	SiloAmount        int64  `json:"silo_amount"`
	RequestedQuantity int64  `json:"requested_quantity"`
	DestinationRef    string `json:"destination_ref"`
	Timestamp         int64  `json:"timestamp"`
}

type SettleCustodyRedemptionData struct {
	SettlementID    string `json:"settlement_id"`
	RequestID       string `json:"request_id"`
	OperatorID      string `json:"operator_id"`
	WarehouseID     string `json:"warehouse_id"`
	FulfillmentRef  string `json:"fulfillment_ref"`
	BurnAmount      int64  `json:"burn_amount"`
	SettledQuantity int64  `json:"settled_quantity"`
	SettledAt       int64  `json:"settled_at"`
}

// AdverseActionData carries a two-party threshold authority action against an
// account commitment. Both EligibilityAuth and ReconciliationAuth must be valid
// ed25519 signatures over the canonical action message for the transaction to commit.
// ActionID must equal H(ActionNonce). The resulting AuthorityActionRecord is
// written to canonical state and never deleted.
//
// ActionType values: "disable" | "freeze" | "rescind" | "restore" | "redeem_forced"
//   - disable:       blocks all sends and receives; reversible via "restore"
//   - freeze:        blocks sends only (AML hold); reversible via "restore"
//   - rescind:       blocks all sends and receives; signals wrongful enrollment
//   - restore:       clears disabled and frozen flags; requires two-party auth
//   - redeem_forced: operator-initiated forced redemption (future: integrates with Burn)
//
// ReferencedActionID is optional. When set on a "restore" action, it must equal the
// ActionID of a prior adverse action in the append-only log — making the appeal linkage
// explicit and verifiable on-chain. The participant presents the referenced record (from
// their audit-interface query) as evidence of wrongful action; the restoring authorities
// bind their signatures to that specific prior action_id.
type AdverseActionData struct {
	ActionID           string `json:"action_id"`                       // H(ActionNonce) — caller-derived, verified by validator
	ActionNonce        string `json:"action_nonce"`                    // random nonce; used to derive ActionID
	AccountCommitment  string `json:"account_commitment"`              // target account
	AssetID            string `json:"asset_id"`                        // empty = all assets for this commitment
	ActionType         string `json:"action_type"`                     // see ActionType values above
	ReferencedActionID string `json:"referenced_action_id,omitempty"` // for "restore": action_id being appealed
	EligibilityAuth    []byte `json:"eligibility_auth"`                // ed25519 sig from eligibility authority
	ReconciliationAuth []byte `json:"reconciliation_auth"`             // ed25519 sig from reconciling authority
	Reason             string `json:"reason"`                          // attestation reason; no PII
	Timestamp          int64  `json:"timestamp"`
}

type ApplyCustodyDemurrageData struct {
	AssessmentID      string `json:"assessment_id"`
	AssetID           string `json:"asset_id"`
	AccountCommitment string `json:"account_commitment"`
	PolicyID          string `json:"policy_id"`
	Amount            int64  `json:"amount"`
	PeriodStart       int64  `json:"period_start"`
	PeriodEnd         int64  `json:"period_end"`
	Reason            string `json:"reason"`
	AppliedAt         int64  `json:"applied_at"`
}

func DecodeTx(txBytes []byte) (*Tx, error) {
	var t Tx
	if err := json.Unmarshal(txBytes, &t); err != nil {
		return nil, fmt.Errorf("failed to decode tx: %w", err)
	}
	return &t, nil
}

func EncodeTx(t *Tx) ([]byte, error) {
	data, err := json.Marshal(t)
	if err != nil {
		return nil, fmt.Errorf("failed to encode tx: %w", err)
	}
	return data, nil
}

func (t *Tx) Validate() error {
	valid := t.Type >= TxTypeRegisterAsset && t.Type <= TxTypeAdverseAction
	if !valid {
		return fmt.Errorf("invalid tx type: %d", t.Type)
	}
	if len(t.Signature) == 0 {
		return fmt.Errorf("missing signature")
	}
	if len(t.Data) == 0 {
		return fmt.Errorf("missing data")
	}

	switch t.Type {
	case TxTypeRegisterAsset:
		var d RegisterAssetData
		if err := json.Unmarshal(t.Data, &d); err != nil {
			return fmt.Errorf("invalid register asset data: %w", err)
		}
		if d.AssetID == "" {
			return fmt.Errorf("missing asset_id")
		}

	case TxTypeMint, TxTypeBurn:
		var d MintData
		if err := json.Unmarshal(t.Data, &d); err != nil {
			return fmt.Errorf("invalid mint/burn data: %w", err)
		}
		if d.AssetID == "" || d.AccountCommitment == "" || d.Amount <= 0 {
			return fmt.Errorf("invalid mint/burn payload")
		}

	case TxTypeTransfer:
		var d TransferData
		if err := json.Unmarshal(t.Data, &d); err != nil {
			return fmt.Errorf("invalid transfer data: %w", err)
		}
		if d.AssetID == "" || d.SenderCommitment == "" || d.RecipientCommitment == "" {
			return fmt.Errorf("missing transfer commitments")
		}
		if d.Amount <= 0 || d.Nullifier == "" || d.TransferNonce == "" {
			return fmt.Errorf("invalid transfer payload")
		}

	case TxTypeRegisterAccount:
		var d RegisterAccountData
		if err := json.Unmarshal(t.Data, &d); err != nil {
			return fmt.Errorf("invalid register account data: %w", err)
		}
		if d.AccountCommitment == "" || len(d.WalletProof) == 0 {
			return fmt.Errorf("invalid register account payload")
		}
		if (d.EnrollmentToken == "") != (len(d.EnrollmentProof) == 0) {
			return fmt.Errorf("enrollment_token and enrollment_proof must both be present or both be omitted")
		}

	case TxTypeRegisterContract:
		var d RegisterContractData
		if err := json.Unmarshal(t.Data, &d); err != nil {
			return fmt.Errorf("invalid contract data: %w", err)
		}
		if d.ContractID == "" {
			return fmt.Errorf("missing contract_id")
		}
		if d.ContractHash == "" {
			return fmt.Errorf("missing contract_hash")
		}
		if d.ContractType == "" {
			return fmt.Errorf("missing contract_type")
		}
		if len(d.Parties) == 0 {
			return fmt.Errorf("contract must have at least one party")
		}
		for _, p := range d.Parties {
			if p.Commitment == "" {
				return fmt.Errorf("party commitment must not be empty")
			}
		}

	case TxTypeActivateContract:
		var d ActivateContractData
		if err := json.Unmarshal(t.Data, &d); err != nil {
			return fmt.Errorf("invalid contract activation data: %w", err)
		}
		if d.ContractID == "" || d.EvidenceHash == "" {
			return fmt.Errorf("missing contract_id or evidence_hash")
		}

	case TxTypeExecuteContract:
		var d ExecuteContractData
		if err := json.Unmarshal(t.Data, &d); err != nil {
			return fmt.Errorf("invalid contract execution data: %w", err)
		}
		if d.ContractID == "" || d.PartyCommitment == "" {
			return fmt.Errorf("missing contract_id or party_commitment")
		}
		if d.SourceRef == "" {
			return fmt.Errorf("missing source_ref")
		}
		if d.Nullifier == "" || d.TransferNonce == "" {
			return fmt.Errorf("missing nullifier or transfer_nonce")
		}

	case TxTypeRegisterConsortiumPolicy:
		var d RegisterConsortiumPolicyData
		if err := json.Unmarshal(t.Data, &d); err != nil {
			return fmt.Errorf("invalid consortium policy data: %w", err)
		}
		if d.PolicyID == "" || d.AssetID == "" || d.Name == "" {
			return fmt.Errorf("missing consortium policy identity")
		}
		if len(d.ActiveOperatorIDs) == 0 || len(d.AcceptedSkuClassIDs) == 0 {
			return fmt.Errorf("policy must declare operators and accepted sku classes")
		}
		if d.UnitOfMeasure == "" || d.QuantityNormalization == "" || d.RedemptionMode == "" || d.RedemptionRouting == "" {
			return fmt.Errorf("missing consortium policy mechanics")
		}

	case TxTypeRegisterWarehouseOperator:
		var d RegisterWarehouseOperatorData
		if err := json.Unmarshal(t.Data, &d); err != nil {
			return fmt.Errorf("invalid warehouse operator data: %w", err)
		}
		if d.OperatorID == "" || d.Name == "" || d.WarehouseID == "" || d.Status == "" {
			return fmt.Errorf("missing warehouse operator identity")
		}

	case TxTypeRegisterAcceptedSkuClass:
		var d RegisterAcceptedSkuClassData
		if err := json.Unmarshal(t.Data, &d); err != nil {
			return fmt.Errorf("invalid accepted sku data: %w", err)
		}
		if d.SkuClassID == "" || d.Name == "" || d.GradeBand == "" || d.UnitOfMeasure == "" || d.Status == "" {
			return fmt.Errorf("missing accepted sku metadata")
		}
		if d.NormalizedFactorBps == 0 {
			return fmt.Errorf("normalized_factor_bps must be > 0")
		}

	case TxTypeRecordCustodyIntakeLot:
		var d RecordCustodyIntakeLotData
		if err := json.Unmarshal(t.Data, &d); err != nil {
			return fmt.Errorf("invalid custody intake lot data: %w", err)
		}
		if d.LotID == "" || d.PolicyID == "" || d.AssetID == "" || d.OperatorID == "" || d.WarehouseID == "" || d.AccountCommitment == "" || d.SkuClassID == "" {
			return fmt.Errorf("missing custody intake lot identity")
		}
		if d.Quantity <= 0 || d.MintedAmount <= 0 {
			return fmt.Errorf("custody intake lot quantity and minted amount must be > 0")
		}
		if d.VideoSessionRef == "" || len(d.EvidenceRefs) == 0 {
			return fmt.Errorf("custody intake lot requires evidence references")
		}

	case TxTypeRequestCustodyRedemption:
		var d RequestCustodyRedemptionData
		if err := json.Unmarshal(t.Data, &d); err != nil {
			return fmt.Errorf("invalid custody redemption request data: %w", err)
		}
		if d.RequestID == "" || d.AssetID == "" || d.AccountCommitment == "" || d.WarehouseID == "" || d.SkuClassID == "" {
			return fmt.Errorf("missing custody redemption request identity")
		}
		if d.SiloAmount <= 0 || d.RequestedQuantity <= 0 {
			return fmt.Errorf("custody redemption amounts must be > 0")
		}

	case TxTypeSettleCustodyRedemption:
		var d SettleCustodyRedemptionData
		if err := json.Unmarshal(t.Data, &d); err != nil {
			return fmt.Errorf("invalid custody redemption settlement data: %w", err)
		}
		if d.SettlementID == "" || d.RequestID == "" || d.OperatorID == "" || d.WarehouseID == "" || d.FulfillmentRef == "" {
			return fmt.Errorf("missing custody settlement identity")
		}
		if d.BurnAmount <= 0 || d.SettledQuantity <= 0 || d.SettledAt <= 0 {
			return fmt.Errorf("custody settlement amounts must be > 0")
		}

	case TxTypeApplyCustodyDemurrage:
		var d ApplyCustodyDemurrageData
		if err := json.Unmarshal(t.Data, &d); err != nil {
			return fmt.Errorf("invalid custody demurrage data: %w", err)
		}
		if d.AssessmentID == "" || d.AssetID == "" || d.AccountCommitment == "" || d.PolicyID == "" || d.Reason == "" {
			return fmt.Errorf("missing custody demurrage identity")
		}
		if d.Amount <= 0 || d.AppliedAt <= 0 || d.PeriodEnd <= d.PeriodStart {
			return fmt.Errorf("invalid custody demurrage payload")
		}

	case TxTypeAdverseAction:
		var d AdverseActionData
		if err := json.Unmarshal(t.Data, &d); err != nil {
			return fmt.Errorf("invalid adverse action data: %w", err)
		}
		if d.ActionID == "" || d.ActionNonce == "" {
			return fmt.Errorf("adverse action: action_id and action_nonce are required")
		}
		if d.AccountCommitment == "" {
			return fmt.Errorf("adverse action: account_commitment is required")
		}
		if d.Reason == "" {
			return fmt.Errorf("adverse action: reason is required")
		}
		if d.Timestamp <= 0 {
			return fmt.Errorf("adverse action: timestamp is required")
		}
		switch d.ActionType {
		case "disable", "freeze", "rescind", "restore", "redeem_forced":
		default:
			return fmt.Errorf("adverse action: unknown action_type %q", d.ActionType)
		}
		if len(d.EligibilityAuth) == 0 || len(d.ReconciliationAuth) == 0 {
			return fmt.Errorf("adverse action: both eligibility_auth and reconciliation_auth are required")
		}
	}

	return nil
}

func (t *Tx) UnmarshalData(v interface{}) error {
	return json.Unmarshal(t.Data, v)
}
