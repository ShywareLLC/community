package identity

import (
	"crypto/ed25519"
	"fmt"

	"github.com/ShywareLLC/community/protocol/tx"
)

// IdentusVerifier implements an offline issuer-key variant of the current IDV
// attestation contract.
//
// identity_hash = sha256(voter_pub_key || poll_id)
// The issuer signs the same current idv_attestation_sig message as Didit. This
// keeps provider choice out of the transaction payload and avoids writing a
// subject-DID field into the submission path.
type IdentusVerifier struct {
	IssuerPubKey ed25519.PublicKey // offline credential issuer Ed25519 key
}

func (v *IdentusVerifier) VerifyAndIdentify(data *tx.BallotCastData) (string, error) {
	if len(data.IdvAttestationSig) == 0 {
		return "", fmt.Errorf("idv_attestation_sig is required")
	}
	msg := diditDeviceAttestMessage(data.VoterPubKey, data.PollID)
	if !ed25519.Verify(v.IssuerPubKey, msg, data.IdvAttestationSig) {
		return "", fmt.Errorf("issuer attestation signature invalid for poll %s", data.PollID)
	}
	return diditIdentityHash(data.VoterPubKey, data.PollID), nil
}

func (v *IdentusVerifier) VerifyAndIdentifyUpdate(data *tx.BallotUpdateData) (string, error) {
	if len(data.IdvAttestationSig) == 0 {
		return "", fmt.Errorf("idv_attestation_sig is required for ballot update")
	}
	msg := diditDeviceAttestMessage(data.VoterPubKey, data.PollID)
	if !ed25519.Verify(v.IssuerPubKey, msg, data.IdvAttestationSig) {
		return "", fmt.Errorf("issuer attestation signature invalid for ballot update on poll %s", data.PollID)
	}
	return diditIdentityHash(data.VoterPubKey, data.PollID), nil
}

func (v *IdentusVerifier) VerifyAndIdentifyConfirm(data *tx.ConfirmReceiptData) (string, error) {
	if len(data.IdvAttestationSig) == 0 {
		return "", fmt.Errorf("idv_attestation_sig is required for confirm receipt")
	}
	msg := diditConfirmAttestMessage(data.VoterPubKey, data.PollID)
	if !ed25519.Verify(v.IssuerPubKey, msg, data.IdvAttestationSig) {
		return "", fmt.Errorf("issuer attestation signature invalid for confirm receipt on poll %s", data.PollID)
	}
	return diditIdentityHash(data.VoterPubKey, data.PollID), nil
}
