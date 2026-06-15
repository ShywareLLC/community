package types

type LotAllocation struct {
	LotID    string `json:"lot_id"`
	Quantity int64  `json:"quantity"`
}

// ConsortiumPolicyRecord publishes the active custody policy for a silo asset.
type ConsortiumPolicyRecord struct {
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
	Status                string   `json:"status"`
	PublishedAt           int64    `json:"published_at"`
	UpdatedAt             int64    `json:"updated_at"`
	Height                int64    `json:"height"`
}

type WarehouseOperatorRecord struct {
	OperatorID     string `json:"operator_id"`
	Name           string `json:"name"`
	WarehouseID    string `json:"warehouse_id"`
	Region         string `json:"region"`
	VideoStreamRef string `json:"video_stream_ref"`
	Status         string `json:"status"`
	CreatedAt      int64  `json:"created_at"`
	UpdatedAt      int64  `json:"updated_at"`
	Height         int64  `json:"height"`
}

type AcceptedSkuClassRecord struct {
	SkuClassID          string `json:"sku_class_id"`
	Name                string `json:"name"`
	GradeBand           string `json:"grade_band"`
	UnitOfMeasure       string `json:"unit_of_measure"`
	NormalizedFactorBps uint32 `json:"normalized_factor_bps"`
	StorageClass        string `json:"storage_class"`
	Status              string `json:"status"`
	CreatedAt           int64  `json:"created_at"`
	UpdatedAt           int64  `json:"updated_at"`
	Height              int64  `json:"height"`
}

type IntakeLotRecord struct {
	LotID                string   `json:"lot_id"`
	PolicyID             string   `json:"policy_id"`
	AssetID              string   `json:"asset_id"`
	OperatorID           string   `json:"operator_id"`
	WarehouseID          string   `json:"warehouse_id"`
	AccountCommitment    string   `json:"account_commitment"`
	SkuClassID           string   `json:"sku_class_id"`
	Quantity             int64    `json:"quantity"`
	RemainingQuantity    int64    `json:"remaining_quantity"`
	MintedAmount         int64    `json:"minted_amount"`
	OperatorFeeAmount    int64    `json:"operator_fee_amount"`
	ShippingCostAmount   int64    `json:"shipping_cost_amount"`
	StorageReserveAmount int64    `json:"storage_reserve_amount"`
	VideoSessionRef      string   `json:"video_session_ref"`
	EvidenceRefs         []string `json:"evidence_refs"`
	Status               string   `json:"status"`
	CreatedAt            int64    `json:"created_at"`
	UpdatedAt            int64    `json:"updated_at"`
	Height               int64    `json:"height"`
}

type RedemptionRequestRecord struct {
	RequestID         string `json:"request_id"`
	AssetID           string `json:"asset_id"`
	AccountCommitment string `json:"account_commitment"`
	WarehouseID       string `json:"warehouse_id"`
	SkuClassID        string `json:"sku_class_id"`
	SiloAmount        int64  `json:"silo_amount"`
	RequestedQuantity int64  `json:"requested_quantity"`
	DestinationRef    string `json:"destination_ref"`
	Status            string `json:"status"`
	CreatedAt         int64  `json:"created_at"`
	UpdatedAt         int64  `json:"updated_at"`
	Height            int64  `json:"height"`
}

type RedemptionSettlementRecord struct {
	SettlementID    string          `json:"settlement_id"`
	RequestID       string          `json:"request_id"`
	OperatorID      string          `json:"operator_id"`
	WarehouseID     string          `json:"warehouse_id"`
	AllocatedLots   []LotAllocation `json:"allocated_lots"`
	FulfillmentRef  string          `json:"fulfillment_ref"`
	BurnAmount      int64           `json:"burn_amount"`
	SettledQuantity int64           `json:"settled_quantity"`
	SettledAt       int64           `json:"settled_at"`
	Height          int64           `json:"height"`
}

type DemurrageAssessmentRecord struct {
	AssessmentID      string `json:"assessment_id"`
	AssetID           string `json:"asset_id"`
	AccountCommitment string `json:"account_commitment"`
	PolicyID          string `json:"policy_id"`
	Amount            int64  `json:"amount"`
	PeriodStart       int64  `json:"period_start"`
	PeriodEnd         int64  `json:"period_end"`
	Reason            string `json:"reason"`
	AppliedAt         int64  `json:"applied_at"`
	Height            int64  `json:"height"`
}
