package shyshares

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// AccountCommitment returns the anonymous account token for a wallet address.
// commitment = SHA-256(lowercase(walletAddress))
//
// This is the public-facing identity token used as the List 2 participant
// identifier. The raw wallet address is never stored alongside a ballot.
func AccountCommitment(walletAddress string) string {
	payload := strings.ToLower(strings.TrimSpace(walletAddress))
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// WalletIdentity computes the identity hash for a DAO governance ballot.
//
// identityHash = SHA-256(lowercase(walletAddress) || ":" || pollID)
//
// This replaces the Didit biometric IDV used in blockchain/ and seda-haqq/
// deployments. The two-list structural invariant is unchanged — the identity
// hash is the List 2 participant key; the anonymous vote direction is List 1.
//
// Lowercase normalisation prevents case-sensitivity attacks on EVM addresses
// (case-insensitive modulo EIP-55 checksum). The ":" separator prevents
// length-extension collisions between address and poll ID components.
func WalletIdentity(walletAddress, pollID string) (string, error) {
	walletAddress = strings.ToLower(strings.TrimSpace(walletAddress))
	if !isValidEVMAddress(walletAddress) {
		return "", errors.New("shyshares: walletAddress must be a 40-hex-char EVM address (with or without 0x prefix)")
	}
	if pollID == "" {
		return "", errors.New("shyshares: pollID must not be empty")
	}
	h := sha256.Sum256([]byte(walletAddress + ":" + pollID))
	return hex.EncodeToString(h[:]), nil
}

func isValidEVMAddress(s string) bool {
	s = strings.TrimPrefix(s, "0x")
	if len(s) != 40 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// EligibilityCheck holds governance membership requirements for a proposal.
// At least one field should be set; the zero value allows any member.
// The ABCI state machine evaluates these conditions at ballot submission time.
type EligibilityCheck struct {
	// MinTokenBalance is the minimum token balance required to vote.
	// Zero means no balance check.
	MinTokenBalance uint64

	// DelegationRequired, if true, requires the voter to hold an active
	// governance delegation from a qualifying address.
	DelegationRequired bool

	// Allowlist restricts voting to wallets in the list when non-empty.
	// Entries must be lowercase hex EVM addresses (without 0x prefix).
	Allowlist []string
}

// Check returns nil if walletAddress satisfies the eligibility condition.
// onChainBalance and hasDelegation must be resolved by the caller via
// an RPC call to the governance contract.
func (e EligibilityCheck) Check(walletAddress string, onChainBalance uint64, hasDelegation bool) error {
	walletAddress = strings.ToLower(strings.TrimPrefix(walletAddress, "0x"))

	if e.MinTokenBalance > 0 && onChainBalance < e.MinTokenBalance {
		return fmt.Errorf("shyshares eligibility: wallet balance %d < required %d", onChainBalance, e.MinTokenBalance)
	}

	if e.DelegationRequired && !hasDelegation {
		return errors.New("shyshares eligibility: wallet has no active governance delegation")
	}

	if len(e.Allowlist) > 0 {
		for _, allowed := range e.Allowlist {
			if strings.ToLower(strings.TrimPrefix(allowed, "0x")) == walletAddress {
				return nil
			}
		}
		return errors.New("shyshares eligibility: wallet not in allowlist")
	}

	return nil
}
