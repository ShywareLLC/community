package state

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/ShywareLLC/community/shywire/tx"
	"github.com/ShywareLLC/community/shywire/types"
)

func TestTransferQueryRedactsAmount(t *testing.T) {
	s := newTestState(t)
	sender := makeRegisterAccountData(t, nil)
	recipient := makeRegisterAccountData(t, nil)

	runTx(t, s, tx.TxTypeRegisterAsset, tx.RegisterAssetData{
		AssetID:  "usdce",
		Name:     "Wrapped USDC",
		Decimals: 6,
	})
	runTx(t, s, tx.TxTypeRegisterAccount, sender)
	runTx(t, s, tx.TxTypeRegisterAccount, recipient)
	runTx(t, s, tx.TxTypeMint, tx.MintData{
		AssetID:           "usdce",
		AccountCommitment: sender.AccountCommitment,
		Amount:            1000,
	})
	runTx(t, s, tx.TxTypeMint, tx.MintData{
		AssetID:           "usdce",
		AccountCommitment: recipient.AccountCommitment,
		Amount:            0,
	})

	transferTx := mustTx(t, tx.TxTypeTransfer, tx.TransferData{
		AssetID:             "usdce",
		SenderCommitment:    sender.AccountCommitment,
		RecipientCommitment: recipient.AccountCommitment,
		Amount:              250,
		Nullifier:           "nf-001",
		TransferNonce:       "nonce-001",
		SenderProof:         []byte{1},
	})
	if err := s.ValidateTx(transferTx); err != nil {
		t.Fatalf("validate transfer: %v", err)
	}
	if _, err := s.ExecuteTx(transferTx); err != nil {
		t.Fatalf("execute transfer: %v", err)
	}

	transferID := hashNonce("nonce-001")
	raw, err := s.Query("/transfer/"+transferID, nil, 0, false)
	if err != nil {
		t.Fatalf("query transfer: %v", err)
	}

	if string(raw) == "" {
		t.Fatal("expected transfer query payload")
	}
	if containsAmountField := jsonContainsField(raw, "amount"); containsAmountField {
		t.Fatalf("expected public transfer query to redact amount, got %s", string(raw))
	}

	var publicRec types.PublicTransferRecord
	if err := json.Unmarshal(raw, &publicRec); err != nil {
		t.Fatalf("unmarshal public transfer record: %v", err)
	}
	if publicRec.TransferID != transferID {
		t.Fatalf("expected transfer_id %s, got %s", transferID, publicRec.TransferID)
	}
	if publicRec.AssetID != "usdce" {
		t.Fatalf("expected asset_id usdce, got %s", publicRec.AssetID)
	}
}

func TestTransferRejectsDuplicateNullifier(t *testing.T) {
	s := newTestState(t)
	sender := makeRegisterAccountData(t, nil)
	recipient := makeRegisterAccountData(t, nil)

	runTx(t, s, tx.TxTypeRegisterAsset, tx.RegisterAssetData{
		AssetID:  "usdce",
		Name:     "Wrapped USDC",
		Decimals: 6,
	})
	runTx(t, s, tx.TxTypeRegisterAccount, sender)
	runTx(t, s, tx.TxTypeRegisterAccount, recipient)
	runTx(t, s, tx.TxTypeMint, tx.MintData{
		AssetID:           "usdce",
		AccountCommitment: sender.AccountCommitment,
		Amount:            1000,
	})
	runTx(t, s, tx.TxTypeMint, tx.MintData{
		AssetID:           "usdce",
		AccountCommitment: recipient.AccountCommitment,
		Amount:            0,
	})

	runTx(t, s, tx.TxTypeTransfer, tx.TransferData{
		AssetID:             "usdce",
		SenderCommitment:    sender.AccountCommitment,
		RecipientCommitment: recipient.AccountCommitment,
		Amount:              250,
		Nullifier:           "nf-dup",
		TransferNonce:       "nonce-001",
		SenderProof:         []byte{1},
	})

	err := s.ValidateTx(mustTx(t, tx.TxTypeTransfer, tx.TransferData{
		AssetID:             "usdce",
		SenderCommitment:    sender.AccountCommitment,
		RecipientCommitment: recipient.AccountCommitment,
		Amount:              100,
		Nullifier:           "nf-dup",
		TransferNonce:       "nonce-002",
		SenderProof:         []byte{1},
	}))
	if err == nil {
		t.Fatal("expected duplicate nullifier transfer to be rejected")
	}
	if _, ok := err.(*types.ErrorDuplicateTransfer); !ok {
		t.Fatalf("expected ErrorDuplicateTransfer, got %T (%v)", err, err)
	}
}

func TestFinancingRemittancePreservesTwoListAndSupplyInvariants(t *testing.T) {
	s := newTestState(t)
	borrower := makeRegisterAccountData(t, nil)
	servicer := makeRegisterAccountData(t, nil)

	runTx(t, s, tx.TxTypeRegisterAsset, tx.RegisterAssetData{
		AssetID:  "usdce",
		Name:     "Wrapped USDC",
		Decimals: 6,
	})
	runTx(t, s, tx.TxTypeRegisterAccount, borrower)
	runTx(t, s, tx.TxTypeRegisterAccount, servicer)
	runTx(t, s, tx.TxTypeMint, tx.MintData{
		AssetID:           "usdce",
		AccountCommitment: borrower.AccountCommitment,
		Amount:            1000,
	})
	runTx(t, s, tx.TxTypeMint, tx.MintData{
		AssetID:           "usdce",
		AccountCommitment: servicer.AccountCommitment,
		Amount:            0,
	})
	runTx(t, s, tx.TxTypeRegisterFinancingContract, tx.RegisterFinancingContractData{
		ContractID:               "contract-001",
		AssetID:                  "usdce",
		BorrowerCommitment:       borrower.AccountCommitment,
		ServicerCommitment:       servicer.AccountCommitment,
		ContractHash:             "contract-hash-001",
		FinanceType:              "rbf",
		ReturnBasis:              "gross_revenue_share",
		EligibleIncomeCategories: []string{"card_sales"},
		InterestBps:              1200,
		CapAmount:                500,
		RemittanceSourceMode:     "matched_income_only",
		FundingMode:              "single_servicer",
		Timestamp:                1738368000,
	})

	beforeSupply := s.supply["usdce"].TotalSupply
	beforeTransfers := len(s.transferRecords)
	beforeParticipants := len(s.participants)

	runTx(t, s, tx.TxTypeRemitFinancingContract, tx.RemitFinancingContractData{
		ContractID:         "contract-001",
		AssetID:            "usdce",
		PayerCommitment:    borrower.AccountCommitment,
		ServicerCommitment: servicer.AccountCommitment,
		IncomeCategory:     "card_sales",
		SourceRef:          "stripe-batch-001",
		MatchedAmount:      200,
		Amount:             200,
		Nullifier:          "nf-remit-001",
		TransferNonce:      "nonce-remit-001",
		Timestamp:          1738368001,
	})

	if got := s.supply["usdce"].TotalSupply; got != beforeSupply {
		t.Fatalf("expected remittance to preserve total supply %d, got %d", beforeSupply, got)
	}
	if got := len(s.transferRecords); got != beforeTransfers+1 {
		t.Fatalf("expected one additional transfer record, got %d from %d", got, beforeTransfers)
	}
	if got := len(s.participants); got != beforeParticipants+1 {
		t.Fatalf("expected one additional participant record, got %d from %d", got, beforeParticipants)
	}
	if len(s.transferRecords) != len(s.participants) {
		t.Fatalf("expected L1/L2 parity after remittance, got %d transfers and %d participants", len(s.transferRecords), len(s.participants))
	}
	if got := s.accounts["usdce:"+borrower.AccountCommitment].Balance; got != 800 {
		t.Fatalf("expected borrower balance 800, got %d", got)
	}
	if got := s.accounts["usdce:"+servicer.AccountCommitment].Balance; got != 200 {
		t.Fatalf("expected servicer balance 200, got %d", got)
	}
}

func TestRegisterAccountRejectsFakeAccountFromNowhere(t *testing.T) {
	s := newTestState(t)

	tx := mustTx(t, tx.TxTypeRegisterAccount, tx.RegisterAccountData{
		AccountCommitment: "deadbeef",
		WalletProof:       []byte{1, 2, 3},
	})
	if err := s.ValidateTx(tx); err == nil {
		t.Fatal("expected fake account registration to be rejected")
	}
}

func TestRegisterAccountRequiresEnrollmentWhenConfigured(t *testing.T) {
	enrollPub, enrollPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate enrollment key: %v", err)
	}
	s := newTestStateWithOptions(t, Options{EnrollmentAuthorityPubKey: enrollPub})

	account := makeRegisterAccountData(t, nil)
	if err := s.ValidateTx(mustTx(t, tx.TxTypeRegisterAccount, account)); err == nil {
		t.Fatal("expected enrollment-gated registration without enrollment proof to fail")
	}

	account = makeRegisterAccountData(t, enrollPriv)
	runTx(t, s, tx.TxTypeRegisterAccount, account)

	if err := s.ValidateTx(mustTx(t, tx.TxTypeRegisterAccount, account)); err == nil {
		t.Fatal("expected single-use enrollment token reuse to fail")
	}
}

func jsonContainsField(raw []byte, field string) bool {
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return false
	}
	_, ok := decoded[field]
	return ok
}
