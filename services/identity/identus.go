package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/ShywareLLC/community/protocol/tx"
)

// IdentusVerifier implements the offline VC embodiment (Identus DID-based attestation).
//
// identity_hash = sha256(subject_did || voter_pub_key || poll_id)
//
// The Identus issuer signs sha256(subject_did || voter_pub_key || poll_id), attesting
// the DID subject controls this voter keypair for this poll. voter_pub_key is
// ephemeral — a coercer who knows the voter's DID cannot compute the on-chain
// identity_hash without it.
//
// Verification is offline against the registered issuer public key — no callback
// to the Identus service required at ballot submission time.
type IdentusVerifier struct {
	IssuerPubKey ed25519.PublicKey // Identus credential issuer Ed25519 key
}

func (v *IdentusVerifier) VerifyAndIdentify(data *tx.BallotCastData) (string, error) {
	if data.IdentusSubjectDID == "" {
		return "", fmt.Errorf("identus_subject_did is required")
	}
	if len(data.IdentusCredentialSig) == 0 {
		return "", fmt.Errorf("identus_credential_sig is required")
	}
	msg := identusCredentialMessage(data.IdentusSubjectDID, data.VoterPubKey, data.PollID)
	if !ed25519.Verify(v.IssuerPubKey, msg, data.IdentusCredentialSig) {
		return "", fmt.Errorf("Identus credential signature invalid for poll %s", data.PollID)
	}
	return hex.EncodeToString(msg), nil
}

func (v *IdentusVerifier) VerifyAndIdentifyUpdate(data *tx.BallotUpdateData) (string, error) {
	if data.IdentusSubjectDID == "" {
		return "", fmt.Errorf("identus_subject_did is required for ballot update")
	}
	if len(data.IdentusCredentialSig) == 0 {
		return "", fmt.Errorf("identus_credential_sig is required for ballot update")
	}
	msg := identusCredentialMessage(data.IdentusSubjectDID, data.VoterPubKey, data.PollID)
	if !ed25519.Verify(v.IssuerPubKey, msg, data.IdentusCredentialSig) {
		return "", fmt.Errorf("Identus credential signature invalid for ballot update on poll %s", data.PollID)
	}
	return hex.EncodeToString(msg), nil
}

func (v *IdentusVerifier) VerifyAndIdentifyConfirm(data *tx.ConfirmReceiptData) (string, error) {
	if data.IdentusSubjectDID == "" {
		return "", fmt.Errorf("identus_subject_did is required for confirm receipt")
	}
	if len(data.IdentusCredentialSig) == 0 {
		return "", fmt.Errorf("identus_credential_sig is required for confirm receipt")
	}
	// "confirm:" prefix prevents replay of cast-time credentials.
	msg := identusConfirmMessage(data.IdentusSubjectDID, data.VoterPubKey, data.PollID)
	if !ed25519.Verify(v.IssuerPubKey, msg, data.IdentusCredentialSig) {
		return "", fmt.Errorf("Identus credential signature invalid for confirm receipt on poll %s", data.PollID)
	}
	// identity_hash = sha256(subject_did || voter_pub_key || poll_id) — same as cast.
	castMsg := identusCredentialMessage(data.IdentusSubjectDID, data.VoterPubKey, data.PollID)
	return hex.EncodeToString(castMsg), nil
}

// identusCredentialMessage = sha256(subjectDID || voterPubKey || pollID).
func identusCredentialMessage(subjectDID, voterPubKey, pollID string) []byte {
	h := sha256.New()
	h.Write([]byte(subjectDID))
	h.Write([]byte(voterPubKey))
	h.Write([]byte(pollID))
	return h.Sum(nil)
}

// identusConfirmMessage = sha256("confirm:" || subjectDID || voterPubKey || pollID).
// The "confirm:" prefix prevents replay of cast-time Identus credentials.
func identusConfirmMessage(subjectDID, voterPubKey, pollID string) []byte {
	h := sha256.New()
	h.Write([]byte("confirm:"))
	h.Write([]byte(subjectDID))
	h.Write([]byte(voterPubKey))
	h.Write([]byte(pollID))
	return h.Sum(nil)
}
