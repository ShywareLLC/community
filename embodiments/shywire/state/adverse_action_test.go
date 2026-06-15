package state

import (
	"crypto/ed25519"
	"testing"

	"github.com/ShywareLLC/community/shywire/tx"
	"github.com/ShywareLLC/community/shywire/types"
)

// newAdverseActionState creates a test state with both authority keys configured.
func newAdverseActionState(t *testing.T) (*State, ed25519.PublicKey, ed25519.PrivateKey, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	elPub, elPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate eligibility key: %v", err)
	}
	recPub, recPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate reconciliation key: %v", err)
	}
	s := newTestStateWithOptions(t, Options{
		EligibilityAuthorityPubKey:    elPub,
		ReconciliationAuthorityPubKey: recPub,
	})
	return s, elPub, elPriv, recPub, recPriv
}

// buildAdverseAction constructs and signs an AdverseActionData with both keys.
func buildAdverseAction(t *testing.T, accountCommitment, assetID, actionType, nonce, reason string,
	elPriv ed25519.PrivateKey, recPriv ed25519.PrivateKey) tx.AdverseActionData {
	t.Helper()
	actionID := hashNonce(nonce)
	d := tx.AdverseActionData{
		ActionID:          actionID,
		ActionNonce:       nonce,
		AccountCommitment: accountCommitment,
		AssetID:           assetID,
		ActionType:        actionType,
		Reason:            reason,
		Timestamp:         1000000,
	}
	msg := adverseActionCanonicalMessage(d)
	d.EligibilityAuth = ed25519.Sign(elPriv, msg)
	d.ReconciliationAuth = ed25519.Sign(recPriv, msg)
	return d
}

// setupAccountWithBalance registers an asset and account and mints balance.
func setupAccountWithBalance(t *testing.T, s *State, assetID string, amount int64) tx.RegisterAccountData {
	t.Helper()
	runTx(t, s, tx.TxTypeRegisterAsset, tx.RegisterAssetData{
		AssetID:  assetID,
		Name:     assetID,
		Decimals: 6,
	})
	acct := makeRegisterAccountData(t, nil)
	runTx(t, s, tx.TxTypeRegisterAccount, acct)
	if amount > 0 {
		runTx(t, s, tx.TxTypeMint, tx.MintData{
			AssetID:           assetID,
			AccountCommitment: acct.AccountCommitment,
			Amount:            amount,
		})
	}
	return acct
}

// TestAdverseActionRequiresBothAuthorities verifies that the action is rejected
// when neither authority key is configured on the deployment.
func TestAdverseActionRequiresBothAuthorities(t *testing.T) {
	s := newTestState(t) // no authority keys
	acct := setupAccountWithBalance(t, s, "usdce", 1000)

	_, elPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_, recPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	d := buildAdverseAction(t, acct.AccountCommitment, "", "disable", "nonce-1", "test", elPriv, recPriv)
	if err := s.ValidateTx(mustTx(t, tx.TxTypeAdverseAction, d)); err == nil {
		t.Fatal("expected adverse action to fail when authority keys are not configured")
	}
}

// TestAdverseActionRejectsInvalidSignature verifies that a tampered eligibility
// signature is rejected before any state is modified.
func TestAdverseActionRejectsInvalidSignature(t *testing.T) {
	s, _, _, _, recPriv := newAdverseActionState(t)
	acct := setupAccountWithBalance(t, s, "usdce", 1000)

	_, badPriv, _ := ed25519.GenerateKey(nil)
	d := buildAdverseAction(t, acct.AccountCommitment, "", "disable", "nonce-1", "test", badPriv, recPriv)
	if err := s.ValidateTx(mustTx(t, tx.TxTypeAdverseAction, d)); err == nil {
		t.Fatal("expected tampered eligibility signature to be rejected")
	}
}

// TestAdverseActionDisableBlocksSender verifies that a disabled account cannot
// send transfers, but the historical transfer records are preserved.
func TestAdverseActionDisableBlocksSender(t *testing.T) {
	s, _, elPriv, _, recPriv := newAdverseActionState(t)
	sender := setupAccountWithBalance(t, s, "usdce", 1000)

	// Register a recipient (needs a zero-balance account too).
	recipient := makeRegisterAccountData(t, nil)
	runTx(t, s, tx.TxTypeRegisterAccount, recipient)
	runTx(t, s, tx.TxTypeMint, tx.MintData{
		AssetID:           "usdce",
		AccountCommitment: recipient.AccountCommitment,
		Amount:            0,
	})

	// Disable the sender.
	d := buildAdverseAction(t, sender.AccountCommitment, "", "disable", "nonce-disable-1", "AML hold", elPriv, recPriv)
	runTx(t, s, tx.TxTypeAdverseAction, d)

	// Transfer from disabled sender must be rejected.
	err := s.ValidateTx(mustTx(t, tx.TxTypeTransfer, tx.TransferData{
		AssetID:             "usdce",
		SenderCommitment:    sender.AccountCommitment,
		RecipientCommitment: recipient.AccountCommitment,
		Amount:              100,
		Nullifier:           "nf-post-disable",
		TransferNonce:       "nonce-post-disable",
		SenderProof:         []byte{1},
	}))
	if err == nil {
		t.Fatal("expected transfer from disabled account to be rejected")
	}
	if _, ok := err.(*types.ErrorAccountDisabled); !ok {
		t.Fatalf("expected ErrorAccountDisabled, got %T (%v)", err, err)
	}

	// Authority-action log must contain one record (append-only).
	if got := len(s.authorityActions); got != 1 {
		t.Fatalf("expected 1 authority action record, got %d", got)
	}
}

// TestAdverseActionFreezeBlocksSendButNotReceive verifies the AML-hold semantics:
// frozen accounts cannot send but can still receive transfers.
func TestAdverseActionFreezeBlocksSendButNotReceive(t *testing.T) {
	s, _, elPriv, _, recPriv := newAdverseActionState(t)

	frozen := setupAccountWithBalance(t, s, "usdce", 500)
	other := makeRegisterAccountData(t, nil)
	runTx(t, s, tx.TxTypeRegisterAccount, other)
	runTx(t, s, tx.TxTypeMint, tx.MintData{
		AssetID:           "usdce",
		AccountCommitment: other.AccountCommitment,
		Amount:            1000,
	})

	// Freeze the account.
	d := buildAdverseAction(t, frozen.AccountCommitment, "", "freeze", "nonce-freeze-1", "OFAC screening", elPriv, recPriv)
	runTx(t, s, tx.TxTypeAdverseAction, d)

	// Frozen account cannot send.
	err := s.ValidateTx(mustTx(t, tx.TxTypeTransfer, tx.TransferData{
		AssetID:             "usdce",
		SenderCommitment:    frozen.AccountCommitment,
		RecipientCommitment: other.AccountCommitment,
		Amount:              100,
		Nullifier:           "nf-frozen-send",
		TransferNonce:       "nonce-frozen-send",
		SenderProof:         []byte{1},
	}))
	if err == nil {
		t.Fatal("expected send from frozen account to be rejected")
	}
	if _, ok := err.(*types.ErrorAccountFrozen); !ok {
		t.Fatalf("expected ErrorAccountFrozen, got %T (%v)", err, err)
	}

	// Frozen account CAN receive (freeze blocks sends, not receives).
	receiveErr := s.ValidateTx(mustTx(t, tx.TxTypeTransfer, tx.TransferData{
		AssetID:             "usdce",
		SenderCommitment:    other.AccountCommitment,
		RecipientCommitment: frozen.AccountCommitment,
		Amount:              100,
		Nullifier:           "nf-to-frozen",
		TransferNonce:       "nonce-to-frozen",
		SenderProof:         []byte{1},
	}))
	if receiveErr != nil {
		t.Fatalf("expected frozen account to be able to receive transfers, got: %v", receiveErr)
	}
}

// TestAdverseActionRestoreReenablesAccount verifies that a "restore" action clears
// the disabled flag and the account can transfer again, while the authority-action
// log grows to two records (append-only — the disable record is not removed).
func TestAdverseActionRestoreReenablesAccount(t *testing.T) {
	s, _, elPriv, _, recPriv := newAdverseActionState(t)
	sender := setupAccountWithBalance(t, s, "usdce", 1000)

	recipient := makeRegisterAccountData(t, nil)
	runTx(t, s, tx.TxTypeRegisterAccount, recipient)
	runTx(t, s, tx.TxTypeMint, tx.MintData{
		AssetID:           "usdce",
		AccountCommitment: recipient.AccountCommitment,
		Amount:            0,
	})

	// Disable then restore.
	runTx(t, s, tx.TxTypeAdverseAction,
		buildAdverseAction(t, sender.AccountCommitment, "", "disable", "nonce-dis-1", "AML hold", elPriv, recPriv))
	runTx(t, s, tx.TxTypeAdverseAction,
		buildAdverseAction(t, sender.AccountCommitment, "", "restore", "nonce-res-1", "cleared", elPriv, recPriv))

	// Authority-action log must have both records — the disable is NOT erased.
	if got := len(s.authorityActions); got != 2 {
		t.Fatalf("expected 2 authority action records after disable+restore, got %d", got)
	}

	// Transfer must succeed after restore.
	runTx(t, s, tx.TxTypeTransfer, tx.TransferData{
		AssetID:             "usdce",
		SenderCommitment:    sender.AccountCommitment,
		RecipientCommitment: recipient.AccountCommitment,
		Amount:              100,
		Nullifier:           "nf-post-restore",
		TransferNonce:       "nonce-post-restore",
		SenderProof:         []byte{1},
	})
}

// TestAdverseActionReplayRejected verifies that reusing an action_id is rejected.
func TestAdverseActionReplayRejected(t *testing.T) {
	s, _, elPriv, _, recPriv := newAdverseActionState(t)
	acct := setupAccountWithBalance(t, s, "usdce", 1000)

	d := buildAdverseAction(t, acct.AccountCommitment, "", "disable", "nonce-replay", "test", elPriv, recPriv)
	runTx(t, s, tx.TxTypeAdverseAction, d)

	// Replay the same action_id — must be rejected.
	if err := s.ValidateTx(mustTx(t, tx.TxTypeAdverseAction, d)); err == nil {
		t.Fatal("expected replayed action_id to be rejected")
	}
}

// TestAdverseActionLogIsAppendOnly verifies that the authority-action log record
// from a disable action survives a subsequent restore action — it is never deleted.
func TestAdverseActionLogIsAppendOnly(t *testing.T) {
	s, _, elPriv, _, recPriv := newAdverseActionState(t)
	acct := setupAccountWithBalance(t, s, "usdce", 500)

	disableNonce := "nonce-ao-disable"
	disableActionID := hashNonce(disableNonce)

	runTx(t, s, tx.TxTypeAdverseAction,
		buildAdverseAction(t, acct.AccountCommitment, "", "disable", disableNonce, "test disable", elPriv, recPriv))
	runTx(t, s, tx.TxTypeAdverseAction,
		buildAdverseAction(t, acct.AccountCommitment, "", "restore", "nonce-ao-restore", "test restore", elPriv, recPriv))

	// The original disable record must still exist.
	if _, ok := s.authorityActions[disableActionID]; !ok {
		t.Fatal("expected disable authority-action record to survive after restore (append-only invariant violated)")
	}
	if got := len(s.authorityActions); got != 2 {
		t.Fatalf("expected exactly 2 authority-action records, got %d", got)
	}
}
