package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/ShywareLLC/community/protocol/tx"
)

// NoopVerifier is a dev/demo stub that accepts any ballot without IDV
// attestation. identity_hash = sha256(voter_pub_key || poll_id).
// Only valid when shyconfig identity.provider = "none".
type NoopVerifier struct{}

func (v *NoopVerifier) VerifyAndIdentify(data *tx.BallotCastData) (string, error) {
	h := sha256.Sum256([]byte(data.VoterPubKey + ":" + data.PollID))
	return hex.EncodeToString(h[:]), nil
}
func (v *NoopVerifier) VerifyAndIdentifyUpdate(data *tx.BallotUpdateData) (string, error) {
	h := sha256.Sum256([]byte(data.VoterPubKey + ":" + data.PollID))
	return hex.EncodeToString(h[:]), nil
}
func (v *NoopVerifier) VerifyAndIdentifyConfirm(data *tx.ConfirmReceiptData) (string, error) {
	h := sha256.Sum256([]byte(data.VoterPubKey + ":" + data.PollID))
	return hex.EncodeToString(h[:]), nil
}

// WalletVerifier implements wallet-based identity for DAO governance embodiments
// (shyshares-v1).
//
// identity_hash = sha256(lowercase(wallet_address) + ":" + poll_id)
//
// The voter declares their wallet address in BallotCastData.WalletAddress.
// The voter device signature (sk_v over ballotNonce:pollID) is verified by the
// state machine before VerifyAndIdentify is called — this binds the ballot to
// the submitting device.
//
// TODO(wallet-ecdsa): add secp256k1 personal_sign ownership proof so the voter
// proves control of wallet_address at submission time. Wire format:
//   - BallotCastData.WalletSig = personal_sign(walletKey, sha256("wallet_vote:" || pollID || ":" || ballotNonce))
//   - WalletVerifier recovers the signer address via btcec ecrecover and asserts
//     it equals WalletAddress.
// Until that is wired, WalletVerifier trusts the declared address — appropriate
// only when the state machine is additionally gated by governance contract
// membership checks at the API layer.
type WalletVerifier struct{}

func (v *WalletVerifier) VerifyAndIdentify(data *tx.BallotCastData) (string, error) {
	if data.WalletAddress == "" {
		return "", errors.New("wallet_address is required for wallet identity")
	}
	hash, err := walletIdentityHash(data.WalletAddress, data.PollID)
	if err != nil {
		return "", err
	}
	return hash, nil
}

func (v *WalletVerifier) VerifyAndIdentifyUpdate(data *tx.BallotUpdateData) (string, error) {
	if data.WalletAddress == "" {
		return "", errors.New("wallet_address is required for wallet identity update")
	}
	hash, err := walletIdentityHash(data.WalletAddress, data.PollID)
	if err != nil {
		return "", err
	}
	return hash, nil
}

func (v *WalletVerifier) VerifyAndIdentifyConfirm(data *tx.ConfirmReceiptData) (string, error) {
	if data.WalletAddress == "" {
		return "", errors.New("wallet_address is required for wallet identity confirm receipt")
	}
	hash, err := walletIdentityHash(data.WalletAddress, data.PollID)
	if err != nil {
		return "", err
	}
	return hash, nil
}

// walletIdentityHash = sha256(lowercase(walletAddress) + ":" + pollID).
func walletIdentityHash(walletAddress, pollID string) (string, error) {
	addr := strings.ToLower(strings.TrimSpace(walletAddress))
	if !isValidEVMAddress(addr) {
		return "", fmt.Errorf("wallet_address must be a 40-hex-char EVM address (with or without 0x prefix)")
	}
	if pollID == "" {
		return "", errors.New("poll_id must not be empty")
	}
	h := sha256.Sum256([]byte(addr + ":" + pollID))
	return hex.EncodeToString(h[:]), nil
}

// AccountCommitment returns the anonymous account token for a wallet address.
// commitment = sha256(lowercase(walletAddress))
//
// This is the public-facing identity token used as the List 2 participant
// identifier when an account commitment (not per-poll hash) is needed.
func AccountCommitment(walletAddress string) string {
	payload := strings.ToLower(strings.TrimSpace(walletAddress))
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func isValidEVMAddress(s string) bool {
	s = strings.TrimPrefix(s, "0x")
	if len(s) != 40 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
