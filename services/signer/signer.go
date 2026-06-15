// Package signer defines the Signer interface used by the protocol state machine
// for tally attestation. Both AWS KMS (ECDSA) and local Ed25519 implementations
// satisfy this interface, so the shared state package is agnostic to which
// signing backend a given deployment uses.
package signer

import "context"

// Signer signs tally payloads and exposes the corresponding public key.
//
// The canonical signing payload is:
//
//	SHA-256(VoteMerkleRoot || VoterMerkleRoot || TotalVotes || sorted-counts)
//
// Two implementations:
//   - protocol/kms.Signer     — AWS KMS ECDSA_SHA_256; every sign call is CloudTrail-audited.
//   - seda-haqq/abci/internal/signer.LocalSigner — local Ed25519; key never leaves the VM.
type Signer interface {
	// Sign produces a signature over payload. The payload is already the 32-byte
	// SHA-256 digest of the tally signing material — the implementation must NOT
	// hash it again (KMS uses MessageTypeDigest; Ed25519 signs the digest directly).
	Sign(ctx context.Context, payload []byte) ([]byte, error)

	// PublicKeyDER returns the DER-encoded SubjectPublicKeyInfo for the signing key.
	// For ECDSA keys this is an EC SubjectPublicKeyInfo (P-256).
	// For Ed25519 keys this is an id-EdDSA SubjectPublicKeyInfo.
	// Verifiers parse this with x509.ParsePKIXPublicKey.
	PublicKeyDER() []byte
}
