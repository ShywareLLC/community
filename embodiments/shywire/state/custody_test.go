package state

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	dbm "github.com/cometbft/cometbft-db"
	"github.com/cometbft/cometbft/libs/log"
	"golang.org/x/crypto/sha3"

	"github.com/ShywareLLC/community/shywire/tx"
)

func newTestState(t *testing.T) *State {
	t.Helper()
	s, err := NewState(dbm.NewMemDB(), log.NewNopLogger())
	if err != nil {
		t.Fatalf("new state: %v", err)
	}
	return s
}

func newTestStateWithOptions(t *testing.T, opts Options) *State {
	t.Helper()
	s, err := NewStateWithOptions(dbm.NewMemDB(), log.NewNopLogger(), opts)
	if err != nil {
		t.Fatalf("new state with options: %v", err)
	}
	return s
}

func mustTx(t *testing.T, typ uint8, payload any) *tx.Tx {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal tx payload: %v", err)
	}
	return &tx.Tx{
		Type:      typ,
		Signature: []byte{1},
		Data:      data,
	}
}

func runTx(t *testing.T, s *State, typ uint8, payload any) {
	t.Helper()
	transaction := mustTx(t, typ, payload)
	if err := s.ValidateTx(transaction); err != nil {
		t.Fatalf("validate tx %d: %v", typ, err)
	}
	if _, err := s.ExecuteTx(transaction); err != nil {
		t.Fatalf("execute tx %d: %v", typ, err)
	}
}

func mustWalletProofBase64(t *testing.T, accountCommitment string) []byte {
	t.Helper()
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("new private key: %v", err)
	}
	derivedCommitment := accountCommitmentFromPrivKey(privKey)
	if derivedCommitment != accountCommitment {
		t.Fatalf("wallet proof helper commitment mismatch: got %s want %s", derivedCommitment, accountCommitment)
	}
	sig, err := ecdsa.SignCompact(privKey, registerAccountWalletMessage(accountCommitment), false)
	if err != nil {
		t.Fatalf("sign wallet proof: %v", err)
	}
	return sig
}

func accountCommitmentFromPrivKey(privKey *btcec.PrivateKey) string {
	pubKey := privKey.PubKey().SerializeUncompressed()
	digest := sha3.NewLegacyKeccak256()
	digest.Write(pubKey[1:])
	evmAddress := "0x" + hex.EncodeToString(digest.Sum(nil)[12:])
	sum := sha256.Sum256([]byte(evmAddress))
	return hex.EncodeToString(sum[:])
}

func makeRegisterAccountData(t *testing.T, enrollmentPriv ed25519.PrivateKey) tx.RegisterAccountData {
	t.Helper()
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("new private key: %v", err)
	}
	accountCommitment := accountCommitmentFromPrivKey(privKey)
	walletProof, err := ecdsa.SignCompact(privKey, registerAccountWalletMessage(accountCommitment), false)
	if err != nil {
		t.Fatalf("sign wallet proof: %v", err)
	}
	data := tx.RegisterAccountData{
		AccountCommitment: accountCommitment,
		WalletProof:       walletProof,
	}
	if len(enrollmentPriv) > 0 {
		data.EnrollmentToken = "enroll-" + accountCommitment[:12]
		data.EnrollmentProof = ed25519.Sign(enrollmentPriv, registerAccountEnrollmentMessage(accountCommitment, data.EnrollmentToken))
	}
	return data
}

func TestCustodyIntakeLotRequiresWhitelistedSKU(t *testing.T) {
	s := newTestState(t)
	account := makeRegisterAccountData(t, nil)

	runTx(t, s, tx.TxTypeRegisterAsset, tx.RegisterAssetData{
		AssetID:  "silo",
		Name:     "Silo",
		Decimals: 2,
	})
	runTx(t, s, tx.TxTypeRegisterAccount, account)
	runTx(t, s, tx.TxTypeRegisterWarehouseOperator, tx.RegisterWarehouseOperatorData{
		OperatorID:  "operator-east",
		Name:        "East Warehouse",
		WarehouseID: "wh-east-1",
		Status:      "active",
	})
	runTx(t, s, tx.TxTypeRegisterAcceptedSkuClass, tx.RegisterAcceptedSkuClassData{
		SkuClassID:          "durum_wheat_grade_a",
		Name:                "Durum Wheat",
		GradeBand:           "Grade A",
		UnitOfMeasure:       "kg",
		NormalizedFactorBps: 10000,
		Status:              "active",
	})
	runTx(t, s, tx.TxTypeRegisterConsortiumPolicy, tx.RegisterConsortiumPolicyData{
		PolicyID:              "policy-001",
		AssetID:               "silo",
		Name:                  "Founding Policy",
		ActiveOperatorIDs:     []string{"operator-east"},
		AcceptedSkuClassIDs:   []string{"durum_wheat_grade_a"},
		UnitOfMeasure:         "kg",
		QuantityNormalization: "grade_weight_nav",
		RedemptionMode:        "physical_goods_only",
		RedemptionRouting:     "holder_chooses_warehouse",
		EvidenceRequirements:  []string{"camera_session_ref"},
	})

	transaction := mustTx(t, tx.TxTypeRecordCustodyIntakeLot, tx.RecordCustodyIntakeLotData{
		LotID:             "lot-001",
		PolicyID:          "policy-001",
		AssetID:           "silo",
		OperatorID:        "operator-east",
		WarehouseID:       "wh-east-1",
		AccountCommitment: account.AccountCommitment,
		SkuClassID:        "rolled_steel_prime",
		Quantity:          1000,
		MintedAmount:      900,
		VideoSessionRef:   "camera-session-001",
		EvidenceRefs:      []string{"operator-receipt-001"},
	})

	if err := s.ValidateTx(transaction); err == nil {
		t.Fatalf("expected intake lot validation to fail for non-whitelisted sku")
	}
}

func TestCustodyRedemptionAndDemurrageUpdateSupply(t *testing.T) {
	s := newTestState(t)
	account := makeRegisterAccountData(t, nil)

	runTx(t, s, tx.TxTypeRegisterAsset, tx.RegisterAssetData{
		AssetID:  "silo",
		Name:     "Silo",
		Decimals: 2,
	})
	runTx(t, s, tx.TxTypeRegisterAccount, account)
	runTx(t, s, tx.TxTypeRegisterWarehouseOperator, tx.RegisterWarehouseOperatorData{
		OperatorID:  "operator-east",
		Name:        "East Warehouse",
		WarehouseID: "wh-east-1",
		Status:      "active",
	})
	runTx(t, s, tx.TxTypeRegisterAcceptedSkuClass, tx.RegisterAcceptedSkuClassData{
		SkuClassID:          "durum_wheat_grade_a",
		Name:                "Durum Wheat",
		GradeBand:           "Grade A",
		UnitOfMeasure:       "kg",
		NormalizedFactorBps: 10000,
		Status:              "active",
	})
	runTx(t, s, tx.TxTypeRegisterConsortiumPolicy, tx.RegisterConsortiumPolicyData{
		PolicyID:              "policy-001",
		AssetID:               "silo",
		Name:                  "Founding Policy",
		ActiveOperatorIDs:     []string{"operator-east"},
		AcceptedSkuClassIDs:   []string{"durum_wheat_grade_a"},
		UnitOfMeasure:         "kg",
		QuantityNormalization: "grade_weight_nav",
		DemurrageRateBps:      125,
		RedemptionMode:        "physical_goods_only",
		RedemptionRouting:     "holder_chooses_warehouse",
		EvidenceRequirements:  []string{"camera_session_ref"},
	})
	runTx(t, s, tx.TxTypeRecordCustodyIntakeLot, tx.RecordCustodyIntakeLotData{
		LotID:             "lot-001",
		PolicyID:          "policy-001",
		AssetID:           "silo",
		OperatorID:        "operator-east",
		WarehouseID:       "wh-east-1",
		AccountCommitment: account.AccountCommitment,
		SkuClassID:        "durum_wheat_grade_a",
		Quantity:          500,
		MintedAmount:      500,
		VideoSessionRef:   "camera-session-001",
		EvidenceRefs:      []string{"operator-receipt-001"},
	})
	runTx(t, s, tx.TxTypeRecordCustodyIntakeLot, tx.RecordCustodyIntakeLotData{
		LotID:             "lot-002",
		PolicyID:          "policy-001",
		AssetID:           "silo",
		OperatorID:        "operator-east",
		WarehouseID:       "wh-east-1",
		AccountCommitment: account.AccountCommitment,
		SkuClassID:        "durum_wheat_grade_a",
		Quantity:          500,
		MintedAmount:      500,
		VideoSessionRef:   "camera-session-002",
		EvidenceRefs:      []string{"operator-receipt-002"},
	})
	runTx(t, s, tx.TxTypeMint, tx.MintData{
		AssetID:           "silo",
		AccountCommitment: account.AccountCommitment,
		Amount:            1000,
	})

	if got := s.supply["silo"].TotalSupply; got != 1000 {
		t.Fatalf("expected initial supply 1000, got %d", got)
	}

	runTx(t, s, tx.TxTypeRequestCustodyRedemption, tx.RequestCustodyRedemptionData{
		RequestID:         "redemption-001",
		AssetID:           "silo",
		AccountCommitment: account.AccountCommitment,
		WarehouseID:       "wh-east-1",
		SkuClassID:        "durum_wheat_grade_a",
		SiloAmount:        700,
		RequestedQuantity: 700,
	})
	runTx(t, s, tx.TxTypeSettleCustodyRedemption, tx.SettleCustodyRedemptionData{
		SettlementID:    "settlement-001",
		RequestID:       "redemption-001",
		OperatorID:      "operator-east",
		WarehouseID:     "wh-east-1",
		FulfillmentRef:  "bill-of-lading-001",
		BurnAmount:      700,
		SettledQuantity: 700,
		SettledAt:       1738368000,
	})

	if got := s.supply["silo"].TotalSupply; got != 300 {
		t.Fatalf("expected supply 300 after redemption burn, got %d", got)
	}
	if got := s.intakeLots["lot-001"].RemainingQuantity; got != 0 {
		t.Fatalf("expected lot-001 to be fully allocated, got %d", got)
	}
	if got := s.intakeLots["lot-002"].RemainingQuantity; got != 300 {
		t.Fatalf("expected remaining pooled quantity 300 in lot-002, got %d", got)
	}
	if got := len(s.redemptionSettlements["settlement-001"].AllocatedLots); got != 2 {
		t.Fatalf("expected settlement to allocate across 2 lots, got %d", got)
	}

	runTx(t, s, tx.TxTypeApplyCustodyDemurrage, tx.ApplyCustodyDemurrageData{
		AssessmentID:      "demurrage-001",
		AssetID:           "silo",
		AccountCommitment: account.AccountCommitment,
		PolicyID:          "policy-001",
		Amount:            50,
		PeriodStart:       1735689600,
		PeriodEnd:         1738368000,
		Reason:            "monthly_storage_policy_burn",
		AppliedAt:         1738368000,
	})

	if got := s.supply["silo"].TotalSupply; got != 250 {
		t.Fatalf("expected supply 250 after demurrage burn, got %d", got)
	}
}

func TestCustodyPartialSettlementConsumesOnlySettledInventory(t *testing.T) {
	s := newTestState(t)
	account := makeRegisterAccountData(t, nil)

	runTx(t, s, tx.TxTypeRegisterAsset, tx.RegisterAssetData{
		AssetID:  "silo",
		Name:     "Silo",
		Decimals: 2,
	})
	runTx(t, s, tx.TxTypeRegisterAccount, account)
	runTx(t, s, tx.TxTypeRegisterWarehouseOperator, tx.RegisterWarehouseOperatorData{
		OperatorID:  "operator-east",
		Name:        "East Warehouse",
		WarehouseID: "wh-east-1",
		Status:      "active",
	})
	runTx(t, s, tx.TxTypeRegisterAcceptedSkuClass, tx.RegisterAcceptedSkuClassData{
		SkuClassID:          "durum_wheat_grade_a",
		Name:                "Durum Wheat",
		GradeBand:           "Grade A",
		UnitOfMeasure:       "kg",
		NormalizedFactorBps: 10000,
		Status:              "active",
	})
	runTx(t, s, tx.TxTypeRegisterConsortiumPolicy, tx.RegisterConsortiumPolicyData{
		PolicyID:              "policy-001",
		AssetID:               "silo",
		Name:                  "Founding Policy",
		ActiveOperatorIDs:     []string{"operator-east"},
		AcceptedSkuClassIDs:   []string{"durum_wheat_grade_a"},
		UnitOfMeasure:         "kg",
		QuantityNormalization: "grade_weight_nav",
		RedemptionMode:        "physical_goods_only",
		RedemptionRouting:     "holder_chooses_warehouse",
		EvidenceRequirements:  []string{"camera_session_ref"},
	})
	runTx(t, s, tx.TxTypeRecordCustodyIntakeLot, tx.RecordCustodyIntakeLotData{
		LotID:             "lot-001",
		PolicyID:          "policy-001",
		AssetID:           "silo",
		OperatorID:        "operator-east",
		WarehouseID:       "wh-east-1",
		AccountCommitment: account.AccountCommitment,
		SkuClassID:        "durum_wheat_grade_a",
		Quantity:          500,
		MintedAmount:      500,
		VideoSessionRef:   "camera-session-001",
		EvidenceRefs:      []string{"operator-receipt-001"},
	})
	runTx(t, s, tx.TxTypeRecordCustodyIntakeLot, tx.RecordCustodyIntakeLotData{
		LotID:             "lot-002",
		PolicyID:          "policy-001",
		AssetID:           "silo",
		OperatorID:        "operator-east",
		WarehouseID:       "wh-east-1",
		AccountCommitment: account.AccountCommitment,
		SkuClassID:        "durum_wheat_grade_a",
		Quantity:          500,
		MintedAmount:      500,
		VideoSessionRef:   "camera-session-002",
		EvidenceRefs:      []string{"operator-receipt-002"},
	})
	runTx(t, s, tx.TxTypeMint, tx.MintData{
		AssetID:           "silo",
		AccountCommitment: account.AccountCommitment,
		Amount:            1000,
	})

	runTx(t, s, tx.TxTypeRequestCustodyRedemption, tx.RequestCustodyRedemptionData{
		RequestID:         "redemption-001",
		AssetID:           "silo",
		AccountCommitment: account.AccountCommitment,
		WarehouseID:       "wh-east-1",
		SkuClassID:        "durum_wheat_grade_a",
		SiloAmount:        700,
		RequestedQuantity: 700,
	})
	runTx(t, s, tx.TxTypeSettleCustodyRedemption, tx.SettleCustodyRedemptionData{
		SettlementID:    "settlement-001",
		RequestID:       "redemption-001",
		OperatorID:      "operator-east",
		WarehouseID:     "wh-east-1",
		FulfillmentRef:  "bill-of-lading-001",
		BurnAmount:      500,
		SettledQuantity: 500,
		SettledAt:       1738368000,
	})

	if got := s.intakeLots["lot-001"].RemainingQuantity; got != 0 {
		t.Fatalf("expected lot-001 remaining quantity 0, got %d", got)
	}
	if got := s.intakeLots["lot-002"].RemainingQuantity; got != 500 {
		t.Fatalf("expected lot-002 remaining quantity 500 after partial settlement, got %d", got)
	}
	if got := s.availableCustodyInventory("silo", "wh-east-1", "durum_wheat_grade_a"); got != 500 {
		t.Fatalf("expected pooled availability 500 after partial settlement, got %d", got)
	}
}
