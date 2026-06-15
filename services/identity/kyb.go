package identity

// KYBVerifier verifies a KYB (Know Your Business) inquiry result for a house
// entity before its Ed25519 signing key is added to house_keys in shyconfig.
//
// KYB verification is an off-chain onboarding step — the operator verifies a
// warehouse/vault owner via a KYB provider (Persona) before the house key is
// admitted to the consortium. The ABCI state machine only checks that PollCreate
// txs are signed by a key already in house_keys; the KYBVerifier is used by
// operator tooling during that admission process.
//
// The house actor is a person, partnership, or verified entity with beneficial-
// ownership attestation. A single house may operate multiple warehouse locations.
type KYBVerifier interface {
	// VerifyEntity verifies a completed KYB inquiry for a house entity and
	// binds the entity to an Ed25519 signing key.
	//
	// Returns an EntityRecord if the inquiry is approved, or an error if the
	// signature is invalid, the inquiry is not approved, or the payload is
	// malformed.
	VerifyEntity(req *EntityVerificationRequest) (*EntityRecord, error)
}

// EntityVerificationRequest carries the KYB inquiry result and the Ed25519
// public key the operator wants to bind to the verified entity.
type EntityVerificationRequest struct {
	// InquiryID is the KYB provider inquiry ID for the completed verification.
	InquiryID string

	// EntityPubKeyHex is the hex-encoded Ed25519 public key to bind to the
	// verified entity. This key will be added to house_keys in shyconfig.
	EntityPubKeyHex string

	// WebhookSig is the provider-signed webhook event signature (format is
	// provider-specific — see PersonaVerifier for Persona's format).
	WebhookSig string

	// WebhookPayload is the raw webhook event body as received from the provider.
	WebhookPayload []byte
}

// EntityRecord is returned by VerifyEntity on successful KYB approval.
type EntityRecord struct {
	// EntityID is the provider's stable reference ID for the verified entity
	// (Persona: the account reference ID).
	EntityID string

	// EntityName is the legal name of the entity as verified by KYB.
	EntityName string

	// VerificationStatus is the final inquiry status ("approved").
	// VerifyEntity only returns a record for approved inquiries.
	VerificationStatus string

	// PubKeyHex is the hex-encoded Ed25519 public key bound to this entity —
	// the value passed in EntityVerificationRequest.EntityPubKeyHex.
	PubKeyHex string
}
