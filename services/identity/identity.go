// Package identity defines two verifier interfaces and their built-in
// implementations.
//
// IdentityVerifier — individual IDV attestation for ballot casting (BallotCast,
// BallotUpdate, ConfirmReceipt txs). Implementations: DiditVerifier, ZKVerifier,
// IdentusVerifier, WalletVerifier.
//
// KYBVerifier — entity (house) beneficial-ownership attestation for off-chain
// onboarding. Used by operator tooling to verify a warehouse/vault owner before
// their Ed25519 signing key is admitted to house_keys in shyconfig.
// Implementation: PersonaVerifier.
//
// The IDV provider is a deployment-time configuration choice orthogonal to the
// voting type set (shyvoting-v1, shyshares-v1, etc.).  Any IdentityVerifier
// implementation can be wired into any embodiment — the two-list structural
// invariant is unaffected by which verifier is used.
//
// The voter device signature (sk_v over ballotNonce:pollID) is verified by the
// state machine before VerifyAndIdentify is called.  IdentityVerifier handles
// only the IDV-provider-specific attestation and identity-hash derivation.
package identity

import "github.com/ShywareLLC/community/protocol/tx"

// IdentityVerifier verifies an IDV attestation in a ballot transaction and
// derives the identity_hash written to List 2 of the two-list invariant.
type IdentityVerifier interface {
	// VerifyAndIdentify verifies the IDV attestation in a BallotCast tx and
	// returns the identity_hash to write to List 2, or an error.
	VerifyAndIdentify(data *tx.BallotCastData) (identityHash string, err error)

	// VerifyAndIdentifyUpdate verifies the IDV attestation in a BallotUpdate tx
	// and returns the identity_hash for the List 2 lookup, or an error.
	VerifyAndIdentifyUpdate(data *tx.BallotUpdateData) (identityHash string, err error)

	// VerifyAndIdentifyConfirm verifies the IDV attestation in a ConfirmReceipt
	// tx (post-close Sybil audit) and returns the identity_hash for registry
	// lookup.  The attestation message uses a "confirm:" prefix to prevent
	// replay of cast-time attestations.
	VerifyAndIdentifyConfirm(data *tx.ConfirmReceiptData) (identityHash string, err error)
}
