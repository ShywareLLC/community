// Package verify provides standalone tally verification functions.
//
// This package is intentionally lightweight — stdlib + x509 only, no KMS client,
// no cometbft — so the verification tooling can be audited and run independently
// by anyone, including third parties in adversarial environments.
//
// The canonical verification procedure:
//
//  1. Fetch the tally (GET /polls/{id}/tally) — includes Signature and PublicKey (DER).
//  2. Fetch voter count (GET /polls/{id}/voters) — verify count-match invariant.
//  3. Call BuildSigningPayload with the tally fields to reconstruct the signed digest.
//  4. Call VerifyECDSA(tally.PublicKey, tally.Signature, payload) → must return true.
package verify

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"math/big"
	"sort"
)

// BuildSigningPayload reconstructs the canonical 32-byte SHA-256 digest that
// was signed when the poll was closed. This is the single source of truth for
// the payload format — both the signer (protocol/state/tallies.go) and all
// verifier tools must call this function so they cannot silently diverge.
//
// Payload: SHA-256(VoteMerkleRoot ‖ VoterMerkleRoot ‖ enc64(TotalVotes) ‖ sorted-counts)
// where enc64(n) = big-endian uint64 encoding of n.
func BuildSigningPayload(voteMerkleRoot, voterMerkleRoot []byte, totalVotes int64, counts map[string]int64) []byte {
	h := sha256.New()
	h.Write(voteMerkleRoot)
	h.Write(voterMerkleRoot)

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(totalVotes))
	h.Write(buf[:])

	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		binary.BigEndian.PutUint64(buf[:], uint64(counts[k]))
		h.Write([]byte(k))
		h.Write(buf[:])
	}

	return h.Sum(nil)
}

// VerifyECDSA verifies a DER-encoded ECDSA signature against a payload using a
// DER-encoded SubjectPublicKeyInfo public key. No KMS connection is required —
// the public key is read directly from the tally record.
//
// pubKeyDER: tally.PublicKey — SubjectPublicKeyInfo DER bytes (from KMS GetPublicKey).
// sigDER:    tally.Signature — DER-encoded ECDSA signature (SEQUENCE { INTEGER r, INTEGER s }).
// payload:   the 32-byte digest from BuildSigningPayload.
func VerifyECDSA(pubKeyDER, sigDER, payload []byte) (bool, error) {
	pub, err := x509.ParsePKIXPublicKey(pubKeyDER)
	if err != nil {
		return false, fmt.Errorf("verify: failed to parse SubjectPublicKeyInfo DER: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("verify: public key is not ECDSA (got %T)", pub)
	}

	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sigDER, &sig); err != nil {
		return false, fmt.Errorf("verify: failed to parse DER signature: %w", err)
	}

	// kms.Signer.Sign computes SHA-256(payload) and sends it to KMS with
	// MessageTypeDigest. So the value KMS actually signed is SHA-256(payload),
	// not payload directly. We must apply the same single hash here before
	// calling ecdsa.Verify.
	digest := sha256.Sum256(payload)
	return ecdsa.Verify(ecPub, digest[:], sig.R, sig.S), nil
}
