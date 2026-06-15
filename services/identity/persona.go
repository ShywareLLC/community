package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// PersonaVerifier implements KYBVerifier using Persona's webhook event
// signature scheme.
//
// Persona is the recommended KYB provider for house entity verification:
// - 100+ country entity verification, UBO chain traversal
// - Unified KYB + KYC under one platform
// - FedRAMP, SOC2 Type II, ISO 27001 certifications
//
// Persona sends a webhook event when a KYB inquiry reaches a terminal state.
// The event is signed with HMAC-SHA256 over the raw payload using the webhook
// secret. The signature header format is:
//
//	Persona-Signature: t=<unix_timestamp>,v1=<hex_hmac>
//
// PersonaVerifier verifies the signature, checks that the inquiry status is
// "approved", and binds the entity to the caller-supplied Ed25519 public key.
//
// Tolerance: webhook events with a timestamp older than WebhookTolerance are
// rejected to prevent replay attacks. Default: 5 minutes.
type PersonaVerifier struct {
	// WebhookSecret is the Persona webhook signing secret for this endpoint
	// (from the Persona dashboard → Webhooks → Signing Secret).
	WebhookSecret string

	// WebhookTolerance is the maximum age of an accepted webhook event.
	// Defaults to 5 minutes if zero.
	WebhookTolerance time.Duration
}

// personaWebhookEvent is a minimal parse of the Persona webhook payload.
// We only need the inquiry ID, status, and the account reference ID
// (the stable entity identifier in Persona).
type personaWebhookEvent struct {
	Data struct {
		Type       string `json:"type"`
		ID         string `json:"id"`
		Attributes struct {
			Status    string `json:"status"`
			ReferenceID string `json:"reference-id"`
		} `json:"attributes"`
		Relationships struct {
			Account struct {
				Data struct {
					ID string `json:"id"`
				} `json:"data"`
			} `json:"account"`
		} `json:"relationships"`
	} `json:"data"`
}

// VerifyEntity verifies a Persona KYB webhook event and returns an EntityRecord
// binding the approved entity to the provided Ed25519 public key.
//
// req.WebhookSig must be the raw value of the Persona-Signature header.
// req.WebhookPayload must be the raw (unmodified) request body.
// req.InquiryID must match the inquiry ID in the webhook event.
// req.EntityPubKeyHex must be the hex-encoded Ed25519 key to bind.
func (v *PersonaVerifier) VerifyEntity(req *EntityVerificationRequest) (*EntityRecord, error) {
	if err := v.verifyWebhookSig(req.WebhookSig, req.WebhookPayload); err != nil {
		return nil, fmt.Errorf("persona webhook signature: %w", err)
	}

	var event personaWebhookEvent
	if err := json.Unmarshal(req.WebhookPayload, &event); err != nil {
		return nil, fmt.Errorf("persona webhook payload: %w", err)
	}

	inquiryID := event.Data.ID
	if inquiryID == "" {
		return nil, fmt.Errorf("persona webhook payload: missing data.id")
	}
	if req.InquiryID != "" && inquiryID != req.InquiryID {
		return nil, fmt.Errorf("persona webhook payload: inquiry ID mismatch: got %s, want %s", inquiryID, req.InquiryID)
	}

	status := event.Data.Attributes.Status
	if status != "approved" {
		return nil, fmt.Errorf("persona inquiry %s is not approved (status: %s)", inquiryID, status)
	}

	entityName := event.Data.Attributes.ReferenceID
	entityID := event.Data.Relationships.Account.Data.ID

	return &EntityRecord{
		EntityID:           entityID,
		EntityName:         entityName,
		VerificationStatus: status,
		PubKeyHex:          req.EntityPubKeyHex,
	}, nil
}

// verifyWebhookSig verifies a Persona webhook signature header.
//
// Header format: "t=<unix_timestamp>,v1=<hex_hmac_sha256>"
// Signed payload: "<timestamp>.<raw_body>"
func (v *PersonaVerifier) verifyWebhookSig(sigHeader string, payload []byte) error {
	tolerance := v.WebhookTolerance
	if tolerance == 0 {
		tolerance = 5 * time.Minute
	}

	parts := strings.Split(sigHeader, ",")
	var timestamp string
	var v1Sig string
	for _, part := range parts {
		if strings.HasPrefix(part, "t=") {
			timestamp = strings.TrimPrefix(part, "t=")
		} else if strings.HasPrefix(part, "v1=") {
			v1Sig = strings.TrimPrefix(part, "v1=")
		}
	}
	if timestamp == "" {
		return fmt.Errorf("missing timestamp (t=) in Persona-Signature header")
	}
	if v1Sig == "" {
		return fmt.Errorf("missing v1 signature in Persona-Signature header")
	}

	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp in Persona-Signature header: %w", err)
	}
	age := time.Since(time.Unix(ts, 0))
	if age > tolerance || age < -tolerance {
		return fmt.Errorf("webhook timestamp out of tolerance: age=%s", age)
	}

	mac := hmac.New(sha256.New, []byte(v.WebhookSecret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))

	// Constant-time comparison to prevent timing attacks.
	if !hmac.Equal([]byte(v1Sig), []byte(expected)) {
		return fmt.Errorf("Persona-Signature v1 mismatch")
	}
	return nil
}
