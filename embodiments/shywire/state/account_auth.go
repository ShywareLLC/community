package state

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"golang.org/x/crypto/sha3"

	"github.com/ShywareLLC/community/shywire/tx"
	"github.com/ShywareLLC/community/shywire/types"
)

func registerAccountWalletMessage(accountCommitment string) []byte {
	sum := sha256.Sum256([]byte("shyware-register-account:" + accountCommitment))
	return sum[:]
}

func registerAccountEnrollmentMessage(accountCommitment, token string) []byte {
	sum := sha256.Sum256([]byte("shyware-enroll-account:" + accountCommitment + ":" + token))
	return sum[:]
}

func verifyRegisterAccountWalletProof(data tx.RegisterAccountData) error {
	pubKey, err := recoverRegisterAccountPubKey(data.WalletProof, data.AccountCommitment)
	if err != nil {
		return err
	}

	address := evmAddressFromPubKey(pubKey.SerializeUncompressed())
	candidates := []string{
		hashAccountCommitment(address),
		hashAccountCommitment(strings.TrimPrefix(address, "0x")),
	}
	for _, candidate := range candidates {
		if candidate == data.AccountCommitment {
			return nil
		}
	}
	return fmt.Errorf("wallet proof does not match account commitment")
}

func recoverRegisterAccountPubKey(walletProof []byte, accountCommitment string) (*btcec.PublicKey, error) {
	msg := registerAccountWalletMessage(accountCommitment)
	if pubKey, _, err := ecdsa.RecoverCompact(walletProof, msg); err == nil {
		return pubKey, nil
	}

	compactSig, err := ethereumSigToCompact(walletProof)
	if err != nil {
		return nil, fmt.Errorf("recover wallet proof: %w", err)
	}

	if pubKey, _, err := ecdsa.RecoverCompact(compactSig, msg); err == nil {
		return pubKey, nil
	}

	personalHash := ethereumPersonalSignHash(msg)
	pubKey, _, err := ecdsa.RecoverCompact(compactSig, personalHash)
	if err != nil {
		return nil, fmt.Errorf("recover wallet proof: %w", err)
	}
	return pubKey, nil
}

func verifyRegisterAccountEnrollment(data tx.RegisterAccountData, authorityPubKey ed25519.PublicKey, used map[string]*types.EnrollmentRecord) error {
	if len(authorityPubKey) == 0 {
		return nil
	}
	if data.EnrollmentToken == "" || len(data.EnrollmentProof) == 0 {
		return fmt.Errorf("enrollment authorization required for account registration")
	}
	if _, exists := used[data.EnrollmentToken]; exists {
		return fmt.Errorf("enrollment token already used")
	}
	msg := registerAccountEnrollmentMessage(data.AccountCommitment, data.EnrollmentToken)
	if !ed25519.Verify(authorityPubKey, msg, data.EnrollmentProof) {
		return fmt.Errorf("invalid enrollment authorization")
	}
	return nil
}

func evmAddressFromPubKey(uncompressed []byte) string {
	digest := sha3.NewLegacyKeccak256()
	digest.Write(uncompressed[1:])
	sum := digest.Sum(nil)
	return "0x" + hex.EncodeToString(sum[len(sum)-20:])
}

func hashAccountCommitment(walletAddress string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(walletAddress))))
	return hex.EncodeToString(sum[:])
}

func ethereumSigToCompact(sig []byte) ([]byte, error) {
	if len(sig) != 65 {
		return nil, fmt.Errorf("unsupported wallet proof length %d", len(sig))
	}
	recID := sig[64]
	switch recID {
	case 27, 28:
		recID -= 27
	case 0, 1:
	default:
		return nil, fmt.Errorf("unsupported wallet recovery id %d", recID)
	}

	compact := make([]byte, 65)
	compact[0] = 27 + recID
	copy(compact[1:33], sig[:32])
	copy(compact[33:], sig[32:64])
	return compact, nil
}

func ethereumPersonalSignHash(message []byte) []byte {
	prefix := []byte("\x19Ethereum Signed Message:\n" + strconv.Itoa(len(message)))
	digest := sha3.NewLegacyKeccak256()
	digest.Write(prefix)
	digest.Write(message)
	return digest.Sum(nil)
}
