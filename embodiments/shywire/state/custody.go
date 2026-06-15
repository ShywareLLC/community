package state

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/ShywareLLC/community/shywire/tx"
	"github.com/ShywareLLC/community/shywire/types"
)

func (s *State) validateRegisterWarehouseOperator(transaction *tx.Tx) error {
	var d tx.RegisterWarehouseOperatorData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return fmt.Errorf("invalid warehouse operator data: %w", err)
	}
	if _, exists := s.warehouseOperators[d.OperatorID]; exists {
		return fmt.Errorf("warehouse operator already registered: %s", d.OperatorID)
	}
	return nil
}

func (s *State) executeRegisterWarehouseOperator(transaction *tx.Tx) ([]abcitypes.Event, error) {
	var d tx.RegisterWarehouseOperatorData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return nil, fmt.Errorf("invalid warehouse operator data: %w", err)
	}

	now := time.Now().Unix()
	s.warehouseOperators[d.OperatorID] = &types.WarehouseOperatorRecord{
		OperatorID:     d.OperatorID,
		Name:           d.Name,
		WarehouseID:    d.WarehouseID,
		Region:         d.Region,
		VideoStreamRef: d.VideoStreamRef,
		Status:         d.Status,
		CreatedAt:      now,
		UpdatedAt:      now,
		Height:         s.height,
	}

	s.dirty = true
	return []abcitypes.Event{{
		Type: "register_custody_operator",
		Attributes: []abcitypes.EventAttribute{
			{Key: "operator_id", Value: d.OperatorID, Index: true},
			{Key: "warehouse_id", Value: d.WarehouseID, Index: true},
		},
	}}, nil
}

func (s *State) validateRegisterAcceptedSkuClass(transaction *tx.Tx) error {
	var d tx.RegisterAcceptedSkuClassData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return fmt.Errorf("invalid accepted sku class data: %w", err)
	}
	if _, exists := s.acceptedSkuClasses[d.SkuClassID]; exists {
		return fmt.Errorf("accepted sku class already registered: %s", d.SkuClassID)
	}
	return nil
}

func (s *State) executeRegisterAcceptedSkuClass(transaction *tx.Tx) ([]abcitypes.Event, error) {
	var d tx.RegisterAcceptedSkuClassData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return nil, fmt.Errorf("invalid accepted sku class data: %w", err)
	}

	now := time.Now().Unix()
	s.acceptedSkuClasses[d.SkuClassID] = &types.AcceptedSkuClassRecord{
		SkuClassID:          d.SkuClassID,
		Name:                d.Name,
		GradeBand:           d.GradeBand,
		UnitOfMeasure:       d.UnitOfMeasure,
		NormalizedFactorBps: d.NormalizedFactorBps,
		StorageClass:        d.StorageClass,
		Status:              d.Status,
		CreatedAt:           now,
		UpdatedAt:           now,
		Height:              s.height,
	}

	s.dirty = true
	return []abcitypes.Event{{
		Type: "register_custody_sku_class",
		Attributes: []abcitypes.EventAttribute{
			{Key: "sku_class_id", Value: d.SkuClassID, Index: true},
			{Key: "grade_band", Value: d.GradeBand, Index: true},
		},
	}}, nil
}

func (s *State) validateRegisterConsortiumPolicy(transaction *tx.Tx) error {
	var d tx.RegisterConsortiumPolicyData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return fmt.Errorf("invalid consortium policy data: %w", err)
	}
	if _, exists := s.consortiumPolicies[d.PolicyID]; exists {
		return fmt.Errorf("consortium policy already registered: %s", d.PolicyID)
	}
	if _, ok := s.assets[d.AssetID]; !ok {
		return &types.ErrorUnknownAsset{AssetID: d.AssetID}
	}
	for _, operatorID := range d.ActiveOperatorIDs {
		operator, ok := s.warehouseOperators[operatorID]
		if !ok {
			return fmt.Errorf("unknown custody operator: %s", operatorID)
		}
		if operator.Status != "active" {
			return fmt.Errorf("custody operator not active: %s", operatorID)
		}
	}
	for _, skuID := range d.AcceptedSkuClassIDs {
		sku, ok := s.acceptedSkuClasses[skuID]
		if !ok {
			return fmt.Errorf("unknown accepted sku class: %s", skuID)
		}
		if sku.Status != "active" {
			return fmt.Errorf("accepted sku class not active: %s", skuID)
		}
	}
	return nil
}

func (s *State) executeRegisterConsortiumPolicy(transaction *tx.Tx) ([]abcitypes.Event, error) {
	var d tx.RegisterConsortiumPolicyData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return nil, fmt.Errorf("invalid consortium policy data: %w", err)
	}

	now := time.Now().Unix()
	if s.currentCustodyPolicyID != "" {
		if current, ok := s.consortiumPolicies[s.currentCustodyPolicyID]; ok {
			current.Status = "superseded"
			current.UpdatedAt = now
			current.Height = s.height
		}
	}

	s.consortiumPolicies[d.PolicyID] = &types.ConsortiumPolicyRecord{
		PolicyID:              d.PolicyID,
		AssetID:               d.AssetID,
		Name:                  d.Name,
		ActiveOperatorIDs:     append([]string(nil), d.ActiveOperatorIDs...),
		AcceptedSkuClassIDs:   append([]string(nil), d.AcceptedSkuClassIDs...),
		UnitOfMeasure:         d.UnitOfMeasure,
		QuantityNormalization: d.QuantityNormalization,
		ShippingAdjustmentRef: d.ShippingAdjustmentRef,
		DemurrageRateBps:      d.DemurrageRateBps,
		OperatorFeeBps:        d.OperatorFeeBps,
		RedemptionMode:        d.RedemptionMode,
		RedemptionRouting:     d.RedemptionRouting,
		EvidenceRequirements:  append([]string(nil), d.EvidenceRequirements...),
		Status:                "active",
		PublishedAt:           now,
		UpdatedAt:             now,
		Height:                s.height,
	}
	s.currentCustodyPolicyID = d.PolicyID

	s.dirty = true
	return []abcitypes.Event{{
		Type: "register_custody_policy",
		Attributes: []abcitypes.EventAttribute{
			{Key: "policy_id", Value: d.PolicyID, Index: true},
			{Key: "asset_id", Value: d.AssetID, Index: true},
		},
	}}, nil
}

func (s *State) validateRecordCustodyIntakeLot(transaction *tx.Tx) error {
	var d tx.RecordCustodyIntakeLotData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return fmt.Errorf("invalid custody intake lot data: %w", err)
	}
	if _, exists := s.intakeLots[d.LotID]; exists {
		return fmt.Errorf("custody intake lot already exists: %s", d.LotID)
	}
	policy, ok := s.consortiumPolicies[d.PolicyID]
	if !ok {
		return fmt.Errorf("unknown custody policy: %s", d.PolicyID)
	}
	if policy.Status != "active" {
		return fmt.Errorf("custody policy not active: %s", d.PolicyID)
	}
	if policy.AssetID != d.AssetID {
		return fmt.Errorf("custody intake lot asset mismatch for policy %s", d.PolicyID)
	}
	if _, ok := s.assets[d.AssetID]; !ok {
		return &types.ErrorUnknownAsset{AssetID: d.AssetID}
	}
	operator, ok := s.warehouseOperators[d.OperatorID]
	if !ok {
		return fmt.Errorf("unknown custody operator: %s", d.OperatorID)
	}
	if operator.Status != "active" {
		return fmt.Errorf("custody operator not active: %s", d.OperatorID)
	}
	if operator.WarehouseID != d.WarehouseID {
		return fmt.Errorf("warehouse mismatch for operator %s", d.OperatorID)
	}
	if !containsString(policy.ActiveOperatorIDs, d.OperatorID) {
		return fmt.Errorf("operator %s not allowed by policy %s", d.OperatorID, d.PolicyID)
	}
	if _, ok := s.acceptedSkuClasses[d.SkuClassID]; !ok {
		return fmt.Errorf("unknown accepted sku class: %s", d.SkuClassID)
	}
	if !containsString(policy.AcceptedSkuClassIDs, d.SkuClassID) {
		return fmt.Errorf("sku class %s not allowed by policy %s", d.SkuClassID, d.PolicyID)
	}
	if _, ok := s.accounts["_:"+d.AccountCommitment]; !ok {
		return fmt.Errorf("account commitment not registered: %s", d.AccountCommitment)
	}
	return nil
}

func (s *State) executeRecordCustodyIntakeLot(transaction *tx.Tx) ([]abcitypes.Event, error) {
	var d tx.RecordCustodyIntakeLotData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return nil, fmt.Errorf("invalid custody intake lot data: %w", err)
	}

	now := time.Now().Unix()
	s.intakeLots[d.LotID] = &types.IntakeLotRecord{
		LotID:                d.LotID,
		PolicyID:             d.PolicyID,
		AssetID:              d.AssetID,
		OperatorID:           d.OperatorID,
		WarehouseID:          d.WarehouseID,
		AccountCommitment:    d.AccountCommitment,
		SkuClassID:           d.SkuClassID,
		Quantity:             d.Quantity,
		RemainingQuantity:    d.Quantity,
		MintedAmount:         d.MintedAmount,
		OperatorFeeAmount:    d.OperatorFeeAmount,
		ShippingCostAmount:   d.ShippingCostAmount,
		StorageReserveAmount: d.StorageReserveAmount,
		VideoSessionRef:      d.VideoSessionRef,
		EvidenceRefs:         append([]string(nil), d.EvidenceRefs...),
		Status:               "recorded",
		CreatedAt:            now,
		UpdatedAt:            now,
		Height:               s.height,
	}

	s.dirty = true
	return []abcitypes.Event{{
		Type: "record_custody_intake_lot",
		Attributes: []abcitypes.EventAttribute{
			{Key: "lot_id", Value: d.LotID, Index: true},
			{Key: "policy_id", Value: d.PolicyID, Index: true},
			{Key: "warehouse_id", Value: d.WarehouseID, Index: true},
		},
	}}, nil
}

func (s *State) validateRequestCustodyRedemption(transaction *tx.Tx) error {
	var d tx.RequestCustodyRedemptionData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return fmt.Errorf("invalid custody redemption request data: %w", err)
	}
	if _, exists := s.redemptionRequests[d.RequestID]; exists {
		return fmt.Errorf("custody redemption request already exists: %s", d.RequestID)
	}
	if _, ok := s.assets[d.AssetID]; !ok {
		return &types.ErrorUnknownAsset{AssetID: d.AssetID}
	}
	if _, ok := s.accounts["_:"+d.AccountCommitment]; !ok {
		return fmt.Errorf("account commitment not registered: %s", d.AccountCommitment)
	}
	if acct, ok := s.accounts[d.AssetID+":"+d.AccountCommitment]; !ok || acct.Balance < d.SiloAmount {
		if ok {
			return &types.ErrorInsufficientBalance{
				AccountCommitment: d.AccountCommitment,
				AssetID:           d.AssetID,
				Have:              acct.Balance,
				Need:              d.SiloAmount,
			}
		}
		return fmt.Errorf("asset-scoped account not found: %s", d.AccountCommitment)
	}
	if _, ok := s.acceptedSkuClasses[d.SkuClassID]; !ok {
		return fmt.Errorf("unknown accepted sku class: %s", d.SkuClassID)
	}
	if !s.hasActiveWarehouse(d.WarehouseID) {
		return fmt.Errorf("warehouse not active or not found: %s", d.WarehouseID)
	}
	if s.availableCustodyInventory(d.AssetID, d.WarehouseID, d.SkuClassID) < d.RequestedQuantity {
		return fmt.Errorf("insufficient pooled inventory for warehouse %s and sku %s", d.WarehouseID, d.SkuClassID)
	}
	return nil
}

func (s *State) executeRequestCustodyRedemption(transaction *tx.Tx) ([]abcitypes.Event, error) {
	var d tx.RequestCustodyRedemptionData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return nil, fmt.Errorf("invalid custody redemption request data: %w", err)
	}

	now := time.Now().Unix()
	s.redemptionRequests[d.RequestID] = &types.RedemptionRequestRecord{
		RequestID:         d.RequestID,
		AssetID:           d.AssetID,
		AccountCommitment: d.AccountCommitment,
		WarehouseID:       d.WarehouseID,
		SkuClassID:        d.SkuClassID,
		SiloAmount:        d.SiloAmount,
		RequestedQuantity: d.RequestedQuantity,
		DestinationRef:    d.DestinationRef,
		Status:            "pending",
		CreatedAt:         now,
		UpdatedAt:         now,
		Height:            s.height,
	}

	s.dirty = true
	return []abcitypes.Event{{
		Type: "request_custody_redemption",
		Attributes: []abcitypes.EventAttribute{
			{Key: "request_id", Value: d.RequestID, Index: true},
			{Key: "warehouse_id", Value: d.WarehouseID, Index: true},
			{Key: "sku_class_id", Value: d.SkuClassID, Index: true},
		},
	}}, nil
}

func (s *State) validateSettleCustodyRedemption(transaction *tx.Tx) error {
	var d tx.SettleCustodyRedemptionData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return fmt.Errorf("invalid custody redemption settlement data: %w", err)
	}
	if _, exists := s.redemptionSettlements[d.SettlementID]; exists {
		return fmt.Errorf("custody redemption settlement already exists: %s", d.SettlementID)
	}
	request, ok := s.redemptionRequests[d.RequestID]
	if !ok {
		return fmt.Errorf("unknown custody redemption request: %s", d.RequestID)
	}
	if request.Status != "pending" {
		return fmt.Errorf("custody redemption request not pending: %s", d.RequestID)
	}
	operator, ok := s.warehouseOperators[d.OperatorID]
	if !ok {
		return fmt.Errorf("unknown custody operator: %s", d.OperatorID)
	}
	if operator.Status != "active" {
		return fmt.Errorf("custody operator not active: %s", d.OperatorID)
	}
	if operator.WarehouseID != d.WarehouseID || request.WarehouseID != d.WarehouseID {
		return fmt.Errorf("warehouse mismatch for redemption request %s", d.RequestID)
	}
	if d.SettledQuantity > request.RequestedQuantity {
		return fmt.Errorf("settled quantity exceeds redemption request %s", d.RequestID)
	}
	if d.BurnAmount > request.SiloAmount {
		return fmt.Errorf("burn amount exceeds redemption request %s", d.RequestID)
	}
	if s.availableCustodyInventory(request.AssetID, d.WarehouseID, request.SkuClassID) < d.SettledQuantity {
		return fmt.Errorf("insufficient pooled inventory for redemption settlement %s", d.SettlementID)
	}
	key := request.AssetID + ":" + request.AccountCommitment
	acct, ok := s.accounts[key]
	if !ok {
		return fmt.Errorf("redeemer account not found: %s", request.AccountCommitment)
	}
	if acct.Balance < d.BurnAmount {
		return &types.ErrorInsufficientBalance{
			AccountCommitment: request.AccountCommitment,
			AssetID:           request.AssetID,
			Have:              acct.Balance,
			Need:              d.BurnAmount,
		}
	}
	return nil
}

func (s *State) executeSettleCustodyRedemption(transaction *tx.Tx) ([]abcitypes.Event, error) {
	var d tx.SettleCustodyRedemptionData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return nil, fmt.Errorf("invalid custody redemption settlement data: %w", err)
	}

	request := s.redemptionRequests[d.RequestID]
	now := time.Now().Unix()
	allocatedLots := s.allocateCustodyInventory(request.AssetID, d.WarehouseID, request.SkuClassID, d.SettledQuantity, now)

	key := request.AssetID + ":" + request.AccountCommitment
	s.accounts[key].Balance -= d.BurnAmount
	s.accounts[key].UpdatedAt = now
	s.accounts[key].Height = s.height

	sup := s.supply[request.AssetID]
	sup.TotalBurned += d.BurnAmount
	sup.TotalSupply = sup.TotalMinted - sup.TotalBurned
	sup.UpdatedAt = now
	s.assets[request.AssetID].TotalSupply = sup.TotalSupply

	request.Status = "settled"
	request.UpdatedAt = now
	request.Height = s.height

	s.redemptionSettlements[d.SettlementID] = &types.RedemptionSettlementRecord{
		SettlementID:    d.SettlementID,
		RequestID:       d.RequestID,
		OperatorID:      d.OperatorID,
		WarehouseID:     d.WarehouseID,
		AllocatedLots:   allocatedLots,
		FulfillmentRef:  d.FulfillmentRef,
		BurnAmount:      d.BurnAmount,
		SettledQuantity: d.SettledQuantity,
		SettledAt:       d.SettledAt,
		Height:          s.height,
	}

	s.dirty = true
	return []abcitypes.Event{{
		Type: "settle_custody_redemption",
		Attributes: []abcitypes.EventAttribute{
			{Key: "settlement_id", Value: d.SettlementID, Index: true},
			{Key: "request_id", Value: d.RequestID, Index: true},
			{Key: "warehouse_id", Value: d.WarehouseID, Index: true},
		},
	}}, nil
}

func (s *State) validateApplyCustodyDemurrage(transaction *tx.Tx) error {
	var d tx.ApplyCustodyDemurrageData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return fmt.Errorf("invalid custody demurrage data: %w", err)
	}
	if _, exists := s.demurrageAssessments[d.AssessmentID]; exists {
		return fmt.Errorf("custody demurrage assessment already exists: %s", d.AssessmentID)
	}
	policy, ok := s.consortiumPolicies[d.PolicyID]
	if !ok {
		return fmt.Errorf("unknown custody policy: %s", d.PolicyID)
	}
	if policy.AssetID != d.AssetID {
		return fmt.Errorf("custody demurrage asset mismatch for policy %s", d.PolicyID)
	}
	key := d.AssetID + ":" + d.AccountCommitment
	acct, ok := s.accounts[key]
	if !ok {
		return fmt.Errorf("account not found for custody demurrage: %s", d.AccountCommitment)
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

func (s *State) executeApplyCustodyDemurrage(transaction *tx.Tx) ([]abcitypes.Event, error) {
	var d tx.ApplyCustodyDemurrageData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return nil, fmt.Errorf("invalid custody demurrage data: %w", err)
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

	s.demurrageAssessments[d.AssessmentID] = &types.DemurrageAssessmentRecord{
		AssessmentID:      d.AssessmentID,
		AssetID:           d.AssetID,
		AccountCommitment: d.AccountCommitment,
		PolicyID:          d.PolicyID,
		Amount:            d.Amount,
		PeriodStart:       d.PeriodStart,
		PeriodEnd:         d.PeriodEnd,
		Reason:            d.Reason,
		AppliedAt:         d.AppliedAt,
		Height:            s.height,
	}

	s.dirty = true
	return []abcitypes.Event{{
		Type: "apply_custody_demurrage",
		Attributes: []abcitypes.EventAttribute{
			{Key: "assessment_id", Value: d.AssessmentID, Index: true},
			{Key: "asset_id", Value: d.AssetID, Index: true},
		},
	}}, nil
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func (s *State) hasActiveWarehouse(warehouseID string) bool {
	for _, operator := range s.warehouseOperators {
		if operator.WarehouseID == warehouseID && operator.Status == "active" {
			return true
		}
	}
	return false
}

func (s *State) availableCustodyInventory(assetID, warehouseID, skuClassID string) int64 {
	var total int64
	for _, lot := range s.inventoryLots(assetID, warehouseID, skuClassID) {
		total += lot.RemainingQuantity
	}
	return total
}

func (s *State) inventoryLots(assetID, warehouseID, skuClassID string) []*types.IntakeLotRecord {
	lots := make([]*types.IntakeLotRecord, 0)
	for _, lot := range s.intakeLots {
		if lot.AssetID != assetID || lot.WarehouseID != warehouseID || lot.SkuClassID != skuClassID {
			continue
		}
		if lot.RemainingQuantity <= 0 || lot.Status == "exhausted" {
			continue
		}
		lots = append(lots, lot)
	}

	sort.Slice(lots, func(i, j int) bool {
		if lots[i].CreatedAt == lots[j].CreatedAt {
			return lots[i].LotID < lots[j].LotID
		}
		return lots[i].CreatedAt < lots[j].CreatedAt
	})

	return lots
}

func (s *State) allocateCustodyInventory(assetID, warehouseID, skuClassID string, quantity int64, now int64) []types.LotAllocation {
	if quantity <= 0 {
		return nil
	}

	remaining := quantity
	allocations := make([]types.LotAllocation, 0)
	for _, lot := range s.inventoryLots(assetID, warehouseID, skuClassID) {
		if remaining == 0 {
			break
		}
		consume := lot.RemainingQuantity
		if consume > remaining {
			consume = remaining
		}
		lot.RemainingQuantity -= consume
		lot.UpdatedAt = now
		lot.Height = s.height
		s.refreshLotStatus(lot)
		allocations = append(allocations, types.LotAllocation{LotID: lot.LotID, Quantity: consume})
		remaining -= consume
	}

	return allocations
}

func (s *State) refreshLotStatus(lot *types.IntakeLotRecord) {
	switch {
	case lot.RemainingQuantity <= 0:
		lot.Status = "exhausted"
	case lot.RemainingQuantity < lot.Quantity:
		lot.Status = "partially_allocated"
	default:
		lot.Status = "recorded"
	}
}
