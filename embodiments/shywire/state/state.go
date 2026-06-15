package state

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	dbm "github.com/cometbft/cometbft-db"
	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/libs/log"

	"github.com/ShywareLLC/community/shywire/tx"
	"github.com/ShywareLLC/community/shywire/types"
)

// State manages the two-list anonymous transfer protocol state.
//
// Two maps enforce the anonymity separation on-chain:
//
//	transferRecords (List 1): transfer_id → TransferRecord  — amount only, no identity
//	participants    (List 2): nullifier   → ParticipantRecord — identity only, no amount
//
// Value conservation invariant: for every Transfer tx,
// sender.Balance decreases by Amount AND recipient.Balance increases by Amount.
// The two deltas are equal — no value is created or destroyed by a transfer.
//
// Supply invariant: TotalSupply == TotalMinted - TotalBurned, enforced on every
// Mint and Burn tx. Only the operator (validator key) may mint or burn.
type State struct {
	db     dbm.DB
	logger log.Logger

	enrollmentAuthorityPubKey      ed25519.PublicKey
	eligibilityAuthorityPubKey     ed25519.PublicKey
	reconciliationAuthorityPubKey  ed25519.PublicKey

	// In-memory state (flushed on Commit).
	assets                 map[string]*types.AssetRecord               // asset_id → AssetRecord
	accounts               map[string]*types.AccountRecord             // "asset_id:account_commitment" → AccountRecord
	supply                 map[string]*types.SupplyRecord              // asset_id → SupplyRecord
	transferRecords        map[string]*types.TransferRecord            // transfer_id → TransferRecord (List 1)
	participants           map[string]*types.ParticipantRecord         // nullifier → ParticipantRecord (List 2)
	contracts          map[string]*types.ContractRecord          // contract_id → ContractRecord
	contractExecutions map[string]*types.ContractExecutionRecord // execution_id → ContractExecutionRecord
	consortiumPolicies     map[string]*types.ConsortiumPolicyRecord
	warehouseOperators     map[string]*types.WarehouseOperatorRecord
	acceptedSkuClasses     map[string]*types.AcceptedSkuClassRecord
	intakeLots             map[string]*types.IntakeLotRecord
	redemptionRequests     map[string]*types.RedemptionRequestRecord
	redemptionSettlements  map[string]*types.RedemptionSettlementRecord
	demurrageAssessments   map[string]*types.DemurrageAssessmentRecord
	enrollmentRecords      map[string]*types.EnrollmentRecord
	authorityActions       map[string]*types.AuthorityActionRecord // append-only adverse-action log
	validators             map[string]*ValidatorRecord
	currentCustodyPolicyID string

	pendingValidatorUpdates []abcitypes.ValidatorUpdate

	height  int64
	appHash []byte
	dirty   bool
}

type Options struct {
	EnrollmentAuthorityPubKey     ed25519.PublicKey
	EligibilityAuthorityPubKey    ed25519.PublicKey // required for TxTypeAdverseAction
	ReconciliationAuthorityPubKey ed25519.PublicKey // required for TxTypeAdverseAction
}

// NewState creates a new shyware state manager.
func NewState(db dbm.DB, logger log.Logger) (*State, error) {
	return NewStateWithOptions(db, logger, Options{})
}

// NewStateWithOptions creates a new shyware state manager with optional
// deployment gates such as enrollment authorization.
func NewStateWithOptions(db dbm.DB, logger log.Logger, opts Options) (*State, error) {
	if len(opts.EligibilityAuthorityPubKey) > 0 && len(opts.ReconciliationAuthorityPubKey) > 0 &&
		bytes.Equal(opts.EligibilityAuthorityPubKey, opts.ReconciliationAuthorityPubKey) {
		return nil, fmt.Errorf("eligibility_authority_pub_key and reconciliation_authority_pub_key must be distinct keys; identical keys collapse the two-party threshold to a single-party threshold")
	}
	s := &State{
		db:                            db,
		logger:                        logger,
		enrollmentAuthorityPubKey:     opts.EnrollmentAuthorityPubKey,
		eligibilityAuthorityPubKey:    opts.EligibilityAuthorityPubKey,
		reconciliationAuthorityPubKey: opts.ReconciliationAuthorityPubKey,
		assets:                    make(map[string]*types.AssetRecord),
		accounts:                  make(map[string]*types.AccountRecord),
		supply:                    make(map[string]*types.SupplyRecord),
		transferRecords:           make(map[string]*types.TransferRecord),
		participants:              make(map[string]*types.ParticipantRecord),
		contracts:        make(map[string]*types.ContractRecord),
		contractExecutions:      make(map[string]*types.ContractExecutionRecord),
		consortiumPolicies:        make(map[string]*types.ConsortiumPolicyRecord),
		warehouseOperators:        make(map[string]*types.WarehouseOperatorRecord),
		acceptedSkuClasses:        make(map[string]*types.AcceptedSkuClassRecord),
		intakeLots:                make(map[string]*types.IntakeLotRecord),
		redemptionRequests:        make(map[string]*types.RedemptionRequestRecord),
		redemptionSettlements:     make(map[string]*types.RedemptionSettlementRecord),
		demurrageAssessments:      make(map[string]*types.DemurrageAssessmentRecord),
		enrollmentRecords:         make(map[string]*types.EnrollmentRecord),
		authorityActions:          make(map[string]*types.AuthorityActionRecord),
		validators:                make(map[string]*ValidatorRecord),
	}

	if err := s.loadState(); err != nil {
		return nil, fmt.Errorf("failed to load state: %w", err)
	}

	return s, nil
}

func (s *State) GetInfo() (int64, []byte) {
	return s.height, s.appHash
}

func (s *State) GetPendingValidatorUpdates() []abcitypes.ValidatorUpdate {
	updates := s.pendingValidatorUpdates
	s.pendingValidatorUpdates = nil
	return updates
}

// ValidateTx performs stateful validation of a transaction.
func (s *State) ValidateTx(transaction *tx.Tx) error {
	switch transaction.Type {
	case tx.TxTypeRegisterAsset:
		return s.validateRegisterAsset(transaction)
	case tx.TxTypeMint:
		return s.validateMint(transaction)
	case tx.TxTypeBurn:
		return s.validateBurn(transaction)
	case tx.TxTypeTransfer:
		return s.validateTransfer(transaction)
	case tx.TxTypeRegisterAccount:
		return s.validateRegisterAccount(transaction)
	case tx.TxTypeRegisterValidator:
		return nil // stateless only
	case tx.TxTypeRegisterContract:
		return s.validateRegisterContract(transaction)
	case tx.TxTypeExecuteContract:
		return s.validateExecuteContract(transaction)
	case tx.TxTypeActivateContract:
		return s.validateActivateContract(transaction)
	case tx.TxTypeRegisterConsortiumPolicy:
		return s.validateRegisterConsortiumPolicy(transaction)
	case tx.TxTypeRegisterWarehouseOperator:
		return s.validateRegisterWarehouseOperator(transaction)
	case tx.TxTypeRegisterAcceptedSkuClass:
		return s.validateRegisterAcceptedSkuClass(transaction)
	case tx.TxTypeRecordCustodyIntakeLot:
		return s.validateRecordCustodyIntakeLot(transaction)
	case tx.TxTypeRequestCustodyRedemption:
		return s.validateRequestCustodyRedemption(transaction)
	case tx.TxTypeSettleCustodyRedemption:
		return s.validateSettleCustodyRedemption(transaction)
	case tx.TxTypeApplyCustodyDemurrage:
		return s.validateApplyCustodyDemurrage(transaction)
	case tx.TxTypeAdverseAction:
		return s.validateAdverseAction(transaction)
	default:
		return fmt.Errorf("unknown tx type: %d", transaction.Type)
	}
}

// ExecuteTx executes a transaction and returns events.
func (s *State) ExecuteTx(transaction *tx.Tx) ([]abcitypes.Event, error) {
	switch transaction.Type {
	case tx.TxTypeRegisterAsset:
		return s.executeRegisterAsset(transaction)
	case tx.TxTypeMint:
		return s.executeMint(transaction)
	case tx.TxTypeBurn:
		return s.executeBurn(transaction)
	case tx.TxTypeTransfer:
		return s.executeTransfer(transaction)
	case tx.TxTypeRegisterAccount:
		return s.executeRegisterAccount(transaction)
	case tx.TxTypeRegisterValidator:
		return s.executeRegisterValidator(transaction)
	case tx.TxTypeRegisterContract:
		return s.executeRegisterContract(transaction)
	case tx.TxTypeExecuteContract:
		return s.executeExecuteContract(transaction)
	case tx.TxTypeActivateContract:
		return s.executeActivateContract(transaction)
	case tx.TxTypeRegisterConsortiumPolicy:
		return s.executeRegisterConsortiumPolicy(transaction)
	case tx.TxTypeRegisterWarehouseOperator:
		return s.executeRegisterWarehouseOperator(transaction)
	case tx.TxTypeRegisterAcceptedSkuClass:
		return s.executeRegisterAcceptedSkuClass(transaction)
	case tx.TxTypeRecordCustodyIntakeLot:
		return s.executeRecordCustodyIntakeLot(transaction)
	case tx.TxTypeRequestCustodyRedemption:
		return s.executeRequestCustodyRedemption(transaction)
	case tx.TxTypeSettleCustodyRedemption:
		return s.executeSettleCustodyRedemption(transaction)
	case tx.TxTypeApplyCustodyDemurrage:
		return s.executeApplyCustodyDemurrage(transaction)
	case tx.TxTypeAdverseAction:
		return s.executeAdverseAction(transaction)
	default:
		return nil, fmt.Errorf("unknown tx type: %d", transaction.Type)
	}
}

// Query handles state queries.
func (s *State) Query(path string, _ []byte, _ int64, _ bool) ([]byte, error) {
	switch {
	case strings.HasPrefix(path, "/asset/"):
		id := strings.TrimPrefix(path, "/asset/")
		a, ok := s.assets[id]
		if !ok {
			return nil, fmt.Errorf("asset not found: %s", id)
		}
		return json.Marshal(a)

	case strings.HasPrefix(path, "/supply/"):
		id := strings.TrimPrefix(path, "/supply/")
		sup, ok := s.supply[id]
		if !ok {
			return nil, fmt.Errorf("supply not found: %s", id)
		}
		return json.Marshal(sup)

	case strings.HasPrefix(path, "/balance/"):
		// /balance/{asset_id}/{account_commitment}
		rest := strings.TrimPrefix(path, "/balance/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid balance query path: %s", path)
		}
		key := parts[0] + ":" + parts[1]
		acct, ok := s.accounts[key]
		if !ok {
			return nil, fmt.Errorf("account not found: %s", key)
		}
		return json.Marshal(acct)

	case strings.HasPrefix(path, "/transfer_exists/"):
		// Boolean-only List 1 presence surface (Claim 52).
		// Returns {"exists":bool} only — no payload, no amount, no identity.
		id := strings.TrimPrefix(path, "/transfer_exists/")
		_, exists := s.transferRecords[id]
		return json.Marshal(map[string]bool{"exists": exists})

	case strings.HasPrefix(path, "/transfer/"):
		id := strings.TrimPrefix(path, "/transfer/")
		rec, ok := s.transferRecords[id]
		if !ok {
			return nil, fmt.Errorf("transfer not found: %s", id)
		}
		return json.Marshal(types.PublicTransferRecord{
			TransferID: rec.TransferID,
			AssetID:    rec.AssetID,
			Timestamp:  rec.Timestamp,
			Height:     rec.Height,
		})

	case strings.HasPrefix(path, "/contract/"):
		id := strings.TrimPrefix(path, "/contract/")
		rec, ok := s.contracts[id]
		if !ok {
			return nil, fmt.Errorf("contract not found: %s", id)
		}
		return json.Marshal(rec)

	case strings.HasPrefix(path, "/contract/execution/"):
		id := strings.TrimPrefix(path, "/contract/execution/")
		rec, ok := s.contractExecutions[id]
		if !ok {
			return nil, fmt.Errorf("contract execution not found: %s", id)
		}
		return json.Marshal(rec)

	case path == "/custody/policies":
		return json.Marshal(sortedRecords(s.consortiumPolicies))

	case path == "/custody/policies/current":
		if s.currentCustodyPolicyID == "" {
			return nil, fmt.Errorf("no current custody policy")
		}
		rec, ok := s.consortiumPolicies[s.currentCustodyPolicyID]
		if !ok {
			return nil, fmt.Errorf("current custody policy not found: %s", s.currentCustodyPolicyID)
		}
		return json.Marshal(rec)

	case strings.HasPrefix(path, "/custody/policies/"):
		id := strings.TrimPrefix(path, "/custody/policies/")
		rec, ok := s.consortiumPolicies[id]
		if !ok {
			return nil, fmt.Errorf("custody policy not found: %s", id)
		}
		return json.Marshal(rec)

	case path == "/custody/operators":
		return json.Marshal(sortedRecords(s.warehouseOperators))

	case strings.HasPrefix(path, "/custody/operators/"):
		id := strings.TrimPrefix(path, "/custody/operators/")
		rec, ok := s.warehouseOperators[id]
		if !ok {
			return nil, fmt.Errorf("warehouse operator not found: %s", id)
		}
		return json.Marshal(rec)

	case path == "/custody/skus":
		return json.Marshal(sortedRecords(s.acceptedSkuClasses))

	case strings.HasPrefix(path, "/custody/skus/"):
		id := strings.TrimPrefix(path, "/custody/skus/")
		rec, ok := s.acceptedSkuClasses[id]
		if !ok {
			return nil, fmt.Errorf("accepted sku class not found: %s", id)
		}
		return json.Marshal(rec)

	case path == "/custody/lots":
		return json.Marshal(sortedRecords(s.intakeLots))

	case strings.HasPrefix(path, "/custody/lots/"):
		id := strings.TrimPrefix(path, "/custody/lots/")
		rec, ok := s.intakeLots[id]
		if !ok {
			return nil, fmt.Errorf("custody intake lot not found: %s", id)
		}
		return json.Marshal(rec)

	case path == "/custody/redemptions":
		return json.Marshal(sortedRecords(s.redemptionRequests))

	case strings.HasPrefix(path, "/custody/redemptions/"):
		id := strings.TrimPrefix(path, "/custody/redemptions/")
		rec, ok := s.redemptionRequests[id]
		if !ok {
			return nil, fmt.Errorf("custody redemption request not found: %s", id)
		}
		return json.Marshal(rec)

	case path == "/custody/settlements":
		return json.Marshal(sortedRecords(s.redemptionSettlements))

	case strings.HasPrefix(path, "/custody/settlements/"):
		id := strings.TrimPrefix(path, "/custody/settlements/")
		rec, ok := s.redemptionSettlements[id]
		if !ok {
			return nil, fmt.Errorf("custody redemption settlement not found: %s", id)
		}
		return json.Marshal(rec)

	case path == "/custody/demurrage":
		return json.Marshal(sortedRecords(s.demurrageAssessments))

	case strings.HasPrefix(path, "/custody/demurrage/"):
		id := strings.TrimPrefix(path, "/custody/demurrage/")
		rec, ok := s.demurrageAssessments[id]
		if !ok {
			return nil, fmt.Errorf("custody demurrage assessment not found: %s", id)
		}
		return json.Marshal(rec)

	case strings.HasPrefix(path, "/authority_actions/"):
		// /authority_actions/{asset_id}/{account_commitment}
		// Per-participant authority-action audit interface (Claims 18, 39).
		// Returns only AuthorityActionRecords bound to the given account_commitment
		// and asset_id. Scoped to the authenticated participant's own account:
		// no invocation sequence constructs a cross-participant mapping.
		// Empty response = structural absence-of-adverse-action attestation.
		rest := strings.TrimPrefix(path, "/authority_actions/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("authority_actions requires /authority_actions/{asset_id}/{account_commitment}")
		}
		assetID, accountCommitment := parts[0], parts[1]
		var records []*types.AuthorityActionRecord
		for _, rec := range s.authorityActions {
			if rec.AccountCommitment == accountCommitment && (rec.AssetID == assetID || rec.AssetID == "") {
				records = append(records, rec)
			}
		}
		if records == nil {
			records = []*types.AuthorityActionRecord{}
		}
		return json.Marshal(records)

	default:
		return nil, fmt.Errorf("unknown query path: %s", path)
	}
}

// Commit persists state to LevelDB and computes the app hash.
func (s *State) Commit() ([]byte, error) {
	if !s.dirty {
		return s.appHash, nil
	}

	batch := s.db.NewBatch()
	defer batch.Close()

	for id, a := range s.assets {
		data, err := json.Marshal(a)
		if err != nil {
			return nil, err
		}
		if err := batch.Set([]byte("asset:"+id), data); err != nil {
			return nil, err
		}
	}

	for key, acct := range s.accounts {
		data, err := json.Marshal(acct)
		if err != nil {
			return nil, err
		}
		if err := batch.Set([]byte("account:"+key), data); err != nil {
			return nil, err
		}
	}

	for id, sup := range s.supply {
		data, err := json.Marshal(sup)
		if err != nil {
			return nil, err
		}
		if err := batch.Set([]byte("supply:"+id), data); err != nil {
			return nil, err
		}
	}

	for id, rec := range s.transferRecords {
		data, err := json.Marshal(rec)
		if err != nil {
			return nil, err
		}
		if err := batch.Set([]byte("transfer:"+id), data); err != nil {
			return nil, err
		}
	}

	for nullifier, p := range s.participants {
		data, err := json.Marshal(p)
		if err != nil {
			return nil, err
		}
		if err := batch.Set([]byte("participant:"+nullifier), data); err != nil {
			return nil, err
		}
	}

	for id, rec := range s.contracts {
		data, err := json.Marshal(rec)
		if err != nil {
			return nil, err
		}
		if err := batch.Set([]byte("contract:"+id), data); err != nil {
			return nil, err
		}
	}

	for id, rec := range s.contractExecutions {
		data, err := json.Marshal(rec)
		if err != nil {
			return nil, err
		}
		if err := batch.Set([]byte("contract_execution:"+id), data); err != nil {
			return nil, err
		}
	}

	for id, rec := range s.consortiumPolicies {
		data, err := json.Marshal(rec)
		if err != nil {
			return nil, err
		}
		if err := batch.Set([]byte("custody_policy:"+id), data); err != nil {
			return nil, err
		}
	}

	for id, rec := range s.warehouseOperators {
		data, err := json.Marshal(rec)
		if err != nil {
			return nil, err
		}
		if err := batch.Set([]byte("custody_operator:"+id), data); err != nil {
			return nil, err
		}
	}

	for id, rec := range s.acceptedSkuClasses {
		data, err := json.Marshal(rec)
		if err != nil {
			return nil, err
		}
		if err := batch.Set([]byte("custody_sku:"+id), data); err != nil {
			return nil, err
		}
	}

	for id, rec := range s.intakeLots {
		data, err := json.Marshal(rec)
		if err != nil {
			return nil, err
		}
		if err := batch.Set([]byte("custody_lot:"+id), data); err != nil {
			return nil, err
		}
	}

	for id, rec := range s.redemptionRequests {
		data, err := json.Marshal(rec)
		if err != nil {
			return nil, err
		}
		if err := batch.Set([]byte("custody_redemption:"+id), data); err != nil {
			return nil, err
		}
	}

	for id, rec := range s.redemptionSettlements {
		data, err := json.Marshal(rec)
		if err != nil {
			return nil, err
		}
		if err := batch.Set([]byte("custody_settlement:"+id), data); err != nil {
			return nil, err
		}
	}

	for id, rec := range s.demurrageAssessments {
		data, err := json.Marshal(rec)
		if err != nil {
			return nil, err
		}
		if err := batch.Set([]byte("custody_demurrage:"+id), data); err != nil {
			return nil, err
		}
	}

	for token, rec := range s.enrollmentRecords {
		data, err := json.Marshal(rec)
		if err != nil {
			return nil, err
		}
		if err := batch.Set([]byte("enrollment:"+token), data); err != nil {
			return nil, err
		}
	}

	for id, rec := range s.authorityActions {
		data, err := json.Marshal(rec)
		if err != nil {
			return nil, err
		}
		if err := batch.Set([]byte("authority_action:"+id), data); err != nil {
			return nil, err
		}
	}

	for pk, v := range s.validators {
		data, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		if err := batch.Set([]byte("validator:"+pk), data); err != nil {
			return nil, err
		}
	}

	s.appHash = s.computeAppHash()
	s.height++

	if err := batch.Set([]byte("height"), []byte(fmt.Sprintf("%d", s.height))); err != nil {
		return nil, err
	}
	if err := batch.Set([]byte("app_hash"), s.appHash); err != nil {
		return nil, err
	}
	if err := batch.Set([]byte("custody_policy_current"), []byte(s.currentCustodyPolicyID)); err != nil {
		return nil, err
	}
	if err := batch.WriteSync(); err != nil {
		return nil, fmt.Errorf("failed to write batch: %w", err)
	}

	s.dirty = false
	s.logger.Info("State committed",
		"height", s.height,
		"assets", len(s.assets),
		"accounts", len(s.accounts),
		"transfers", len(s.transferRecords),
		"participants", len(s.participants),
		"contracts", len(s.contracts),
		"contract_executions", len(s.contractExecutions),
		"custody_policies", len(s.consortiumPolicies),
		"custody_lots", len(s.intakeLots),
		"custody_redemptions", len(s.redemptionRequests),
	)
	return s.appHash, nil
}

func (s *State) computeAppHash() []byte {
	h := sha256.New()
	for _, k := range sortedKeys(s.assets) {
		data, _ := json.Marshal(s.assets[k])
		h.Write(data)
	}
	for _, k := range sortedKeys(s.supply) {
		data, _ := json.Marshal(s.supply[k])
		h.Write(data)
	}
	for _, k := range sortedKeys(s.accounts) {
		data, _ := json.Marshal(s.accounts[k])
		h.Write(data)
	}
	for _, k := range sortedKeys(s.transferRecords) {
		data, _ := json.Marshal(s.transferRecords[k])
		h.Write(data)
	}
	for _, k := range sortedKeys(s.participants) {
		data, _ := json.Marshal(s.participants[k])
		h.Write(data)
	}
	for _, k := range sortedKeys(s.contracts) {
		data, _ := json.Marshal(s.contracts[k])
		h.Write(data)
	}
	for _, k := range sortedKeys(s.contractExecutions) {
		data, _ := json.Marshal(s.contractExecutions[k])
		h.Write(data)
	}
	for _, k := range sortedKeys(s.consortiumPolicies) {
		data, _ := json.Marshal(s.consortiumPolicies[k])
		h.Write(data)
	}
	for _, k := range sortedKeys(s.warehouseOperators) {
		data, _ := json.Marshal(s.warehouseOperators[k])
		h.Write(data)
	}
	for _, k := range sortedKeys(s.acceptedSkuClasses) {
		data, _ := json.Marshal(s.acceptedSkuClasses[k])
		h.Write(data)
	}
	for _, k := range sortedKeys(s.intakeLots) {
		data, _ := json.Marshal(s.intakeLots[k])
		h.Write(data)
	}
	for _, k := range sortedKeys(s.redemptionRequests) {
		data, _ := json.Marshal(s.redemptionRequests[k])
		h.Write(data)
	}
	for _, k := range sortedKeys(s.redemptionSettlements) {
		data, _ := json.Marshal(s.redemptionSettlements[k])
		h.Write(data)
	}
	for _, k := range sortedKeys(s.demurrageAssessments) {
		data, _ := json.Marshal(s.demurrageAssessments[k])
		h.Write(data)
	}
	for _, k := range sortedKeys(s.enrollmentRecords) {
		data, _ := json.Marshal(s.enrollmentRecords[k])
		h.Write(data)
	}
	for _, k := range sortedKeys(s.authorityActions) {
		data, _ := json.Marshal(s.authorityActions[k])
		h.Write(data)
	}
	h.Write([]byte(s.currentCustodyPolicyID))
	return h.Sum(nil)
}

func (s *State) loadState() error {
	heightBytes, _ := s.db.Get([]byte("height"))
	if heightBytes != nil {
		fmt.Sscanf(string(heightBytes), "%d", &s.height)
	}
	appHashBytes, _ := s.db.Get([]byte("app_hash"))
	if appHashBytes != nil {
		s.appHash = appHashBytes
	}
	currentPolicyBytes, _ := s.db.Get([]byte("custody_policy_current"))
	if currentPolicyBytes != nil {
		s.currentCustodyPolicyID = string(currentPolicyBytes)
	}

	loaders := []struct {
		prefix string
		fn     func([]byte) error
	}{
		{"asset:", func(val []byte) error {
			var a types.AssetRecord
			if err := json.Unmarshal(val, &a); err != nil {
				return err
			}
			s.assets[a.AssetID] = &a
			return nil
		}},
		{"account:", func(val []byte) error {
			var a types.AccountRecord
			if err := json.Unmarshal(val, &a); err != nil {
				return err
			}
			s.accounts[a.AssetID+":"+a.AccountCommitment] = &a
			return nil
		}},
		{"supply:", func(val []byte) error {
			var sup types.SupplyRecord
			if err := json.Unmarshal(val, &sup); err != nil {
				return err
			}
			s.supply[sup.AssetID] = &sup
			return nil
		}},
		{"transfer:", func(val []byte) error {
			var r types.TransferRecord
			if err := json.Unmarshal(val, &r); err != nil {
				return err
			}
			s.transferRecords[r.TransferID] = &r
			return nil
		}},
		{"participant:", func(val []byte) error {
			var p types.ParticipantRecord
			if err := json.Unmarshal(val, &p); err != nil {
				return err
			}
			s.participants[p.IdentityHash] = &p
			return nil
		}},
		{"contract:", func(val []byte) error {
			var c types.ContractRecord
			if err := json.Unmarshal(val, &c); err != nil {
				return err
			}
			s.contracts[c.ContractID] = &c
			return nil
		}},
		{"contract_execution:", func(val []byte) error {
			var r types.ContractExecutionRecord
			if err := json.Unmarshal(val, &r); err != nil {
				return err
			}
			s.contractExecutions[r.TransferID] = &r
			return nil
		}},
		{"custody_policy:", func(val []byte) error {
			var r types.ConsortiumPolicyRecord
			if err := json.Unmarshal(val, &r); err != nil {
				return err
			}
			s.consortiumPolicies[r.PolicyID] = &r
			return nil
		}},
		{"custody_operator:", func(val []byte) error {
			var r types.WarehouseOperatorRecord
			if err := json.Unmarshal(val, &r); err != nil {
				return err
			}
			s.warehouseOperators[r.OperatorID] = &r
			return nil
		}},
		{"custody_sku:", func(val []byte) error {
			var r types.AcceptedSkuClassRecord
			if err := json.Unmarshal(val, &r); err != nil {
				return err
			}
			s.acceptedSkuClasses[r.SkuClassID] = &r
			return nil
		}},
		{"custody_lot:", func(val []byte) error {
			var r types.IntakeLotRecord
			if err := json.Unmarshal(val, &r); err != nil {
				return err
			}
			s.intakeLots[r.LotID] = &r
			return nil
		}},
		{"custody_redemption:", func(val []byte) error {
			var r types.RedemptionRequestRecord
			if err := json.Unmarshal(val, &r); err != nil {
				return err
			}
			s.redemptionRequests[r.RequestID] = &r
			return nil
		}},
		{"custody_settlement:", func(val []byte) error {
			var r types.RedemptionSettlementRecord
			if err := json.Unmarshal(val, &r); err != nil {
				return err
			}
			s.redemptionSettlements[r.SettlementID] = &r
			return nil
		}},
		{"custody_demurrage:", func(val []byte) error {
			var r types.DemurrageAssessmentRecord
			if err := json.Unmarshal(val, &r); err != nil {
				return err
			}
			s.demurrageAssessments[r.AssessmentID] = &r
			return nil
		}},
		{"enrollment:", func(val []byte) error {
			var r types.EnrollmentRecord
			if err := json.Unmarshal(val, &r); err != nil {
				return err
			}
			s.enrollmentRecords[r.Token] = &r
			return nil
		}},
		{"authority_action:", func(val []byte) error {
			var r types.AuthorityActionRecord
			if err := json.Unmarshal(val, &r); err != nil {
				return err
			}
			s.authorityActions[r.ActionID] = &r
			return nil
		}},
		{"validator:", func(val []byte) error {
			var v ValidatorRecord
			if err := json.Unmarshal(val, &v); err != nil {
				return err
			}
			s.validators[v.PubKeyBase64] = &v
			return nil
		}},
	}

	for _, l := range loaders {
		if err := s.loadPrefix(l.prefix, l.fn); err != nil {
			return fmt.Errorf("loading %s: %w", l.prefix, err)
		}
	}

	s.logger.Info("State loaded",
		"height", s.height,
		"assets", len(s.assets),
		"accounts", len(s.accounts),
		"transfers", len(s.transferRecords),
		"participants", len(s.participants),
		"contracts", len(s.contracts),
		"contract_executions", len(s.contractExecutions),
		"custody_policies", len(s.consortiumPolicies),
		"custody_lots", len(s.intakeLots),
		"custody_redemptions", len(s.redemptionRequests),
	)
	return nil
}

func (s *State) loadPrefix(prefix string, fn func([]byte) error) error {
	start := []byte(prefix)
	end := prefixEnd(start)
	it, err := s.db.Iterator(start, end)
	if err != nil {
		return err
	}
	defer it.Close()
	for ; it.Valid(); it.Next() {
		if err := fn(it.Value()); err != nil {
			return fmt.Errorf("key %s: %w", it.Key(), err)
		}
	}
	return it.Error()
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedRecords[T any](m map[string]*T) []*T {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	records := make([]*T, 0, len(keys))
	for _, k := range keys {
		records = append(records, m[k])
	}
	return records
}

func prefixEnd(prefix []byte) []byte {
	end := make([]byte, len(prefix))
	copy(end, prefix)
	for i := len(end) - 1; i >= 0; i-- {
		end[i]++
		if end[i] != 0 {
			return end[:i+1]
		}
	}
	return nil
}
