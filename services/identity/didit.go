package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/ShywareLLC/community/protocol/tx"
	"github.com/ShywareLLC/community/protocol/zkp"
)

// DiditVerifier implements the preferred non-ZK IDV attestation embodiment.
//
// identity_hash = sha256(voter_pub_key || poll_id)
// Didit signs sha256(voter_pub_key || poll_id) to attest the keypair belongs
// to a biometrically verified real person for this poll.
type DiditVerifier struct {
	PubKey ed25519.PublicKey // Didit Ed25519 signing key
}

func (v *DiditVerifier) VerifyAndIdentify(data *tx.BallotCastData) (string, error) {
	if len(data.IdvAttestationSig) == 0 {
		return "", fmt.Errorf("idv_attestation_sig is required")
	}
	msg := diditDeviceAttestMessage(data.VoterPubKey, data.PollID)
	if !ed25519.Verify(v.PubKey, msg, data.IdvAttestationSig) {
		return "", fmt.Errorf("Didit device attestation signature invalid for poll %s", data.PollID)
	}
	return diditIdentityHash(data.VoterPubKey, data.PollID), nil
}

func (v *DiditVerifier) VerifyAndIdentifyUpdate(data *tx.BallotUpdateData) (string, error) {
	if len(data.IdvAttestationSig) == 0 {
		return "", fmt.Errorf("idv_attestation_sig is required for ballot update")
	}
	msg := diditDeviceAttestMessage(data.VoterPubKey, data.PollID)
	if !ed25519.Verify(v.PubKey, msg, data.IdvAttestationSig) {
		return "", fmt.Errorf("Didit device attestation signature invalid for ballot update on poll %s", data.PollID)
	}
	return diditIdentityHash(data.VoterPubKey, data.PollID), nil
}

func (v *DiditVerifier) VerifyAndIdentifyConfirm(data *tx.ConfirmReceiptData) (string, error) {
	if len(data.IdvAttestationSig) == 0 {
		return "", fmt.Errorf("idv_attestation_sig is required for confirm receipt")
	}
	// "confirm:" prefix prevents replay of cast-time attestations.
	msg := diditConfirmAttestMessage(data.VoterPubKey, data.PollID)
	if !ed25519.Verify(v.PubKey, msg, data.IdvAttestationSig) {
		return "", fmt.Errorf("Didit device attestation signature invalid for confirm receipt on poll %s", data.PollID)
	}
	return diditIdentityHash(data.VoterPubKey, data.PollID), nil
}

// ZKVerifier implements the high-assurance embodiment (Groth16 ZK nullifier +
// Didit commitment signature).
//
// identity_hash = ZKNullifier = MiMC(person_secret, poll_id)
// Groth16 proof binds the nullifier and commitment to the same device-held secret.
// Didit signs sha256(zk_commitment || poll_id) — it cannot forge a ballot because
// it never holds sk_v.
type ZKVerifier struct {
	DiditPubKey ed25519.PublicKey
	ZK          *zkp.Verifier
}

func (v *ZKVerifier) VerifyAndIdentify(data *tx.BallotCastData) (string, error) {
	if data.ZKNullifier == "" || len(data.ZKNullifierProof) == 0 ||
		data.ZKCommitment == "" || len(data.DiditCommitmentSig) == 0 {
		return "", fmt.Errorf("zk_nullifier, zk_nullifier_proof, zk_commitment, didit_commitment_sig are all required")
	}
	commitMsg := diditCommitmentSigMessage(data.ZKCommitment, data.PollID)
	if !ed25519.Verify(v.DiditPubKey, commitMsg, data.DiditCommitmentSig) {
		return "", fmt.Errorf("Didit commitment signature invalid for poll %s", data.PollID)
	}
	if err := v.ZK.Verify(data.ZKNullifierProof, data.ZKNullifier, data.ZKCommitment, data.PollID); err != nil {
		return "", fmt.Errorf("ZK nullifier proof rejected: %w", err)
	}
	return data.ZKNullifier, nil
}

func (v *ZKVerifier) VerifyAndIdentifyUpdate(data *tx.BallotUpdateData) (string, error) {
	if data.ZKNullifier == "" || len(data.ZKNullifierProof) == 0 ||
		data.ZKCommitment == "" || len(data.DiditCommitmentSig) == 0 {
		return "", fmt.Errorf("all ZK fields required for ballot update")
	}
	commitMsg := diditCommitmentSigMessage(data.ZKCommitment, data.PollID)
	if !ed25519.Verify(v.DiditPubKey, commitMsg, data.DiditCommitmentSig) {
		return "", fmt.Errorf("Didit commitment signature invalid for ballot update on poll %s", data.PollID)
	}
	if err := v.ZK.Verify(data.ZKNullifierProof, data.ZKNullifier, data.ZKCommitment, data.PollID); err != nil {
		return "", fmt.Errorf("ZK nullifier proof rejected for update: %w", err)
	}
	return data.ZKNullifier, nil
}

func (v *ZKVerifier) VerifyAndIdentifyConfirm(data *tx.ConfirmReceiptData) (string, error) {
	if data.ZKNullifier == "" || len(data.ZKNullifierProof) == 0 ||
		data.ZKCommitment == "" || len(data.DiditCommitmentSig) == 0 {
		return "", fmt.Errorf("all ZK fields required for confirm receipt")
	}
	// "confirm:" prefix prevents replay of cast-time commitment signatures.
	commitMsg := diditConfirmCommitmentSigMessage(data.ZKCommitment, data.PollID)
	if !ed25519.Verify(v.DiditPubKey, commitMsg, data.DiditCommitmentSig) {
		return "", fmt.Errorf("Didit commitment signature invalid for confirm receipt on poll %s", data.PollID)
	}
	if err := v.ZK.Verify(data.ZKNullifierProof, data.ZKNullifier, data.ZKCommitment, data.PollID); err != nil {
		return "", fmt.Errorf("ZK nullifier proof rejected for confirm receipt: %w", err)
	}
	return data.ZKNullifier, nil
}

// diditDeviceAttestMessage is the message Didit signs to attest a voter's device
// keypair at cast time: sha256(voter_pub_key || poll_id).
func diditDeviceAttestMessage(voterPubKey, pollID string) []byte {
	h := sha256.New()
	h.Write([]byte(voterPubKey))
	h.Write([]byte(pollID))
	return h.Sum(nil)
}

// diditConfirmAttestMessage is the message Didit signs for a confirm-receipt tx:
// sha256("confirm:" || voter_pub_key || poll_id).
// The "confirm:" prefix prevents replay of cast-time attestations.
func diditConfirmAttestMessage(voterPubKey, pollID string) []byte {
	h := sha256.New()
	h.Write([]byte("confirm:"))
	h.Write([]byte(voterPubKey))
	h.Write([]byte(pollID))
	return h.Sum(nil)
}

// diditCommitmentSigMessage is the message Didit signs in the ZK embodiment at
// cast time: sha256(zk_commitment || poll_id).
func diditCommitmentSigMessage(zkCommitment, pollID string) []byte {
	h := sha256.New()
	h.Write([]byte(zkCommitment))
	h.Write([]byte(pollID))
	return h.Sum(nil)
}

// diditConfirmCommitmentSigMessage is the message Didit signs in the ZK embodiment
// for a confirm-receipt tx: sha256("confirm:" || zk_commitment || poll_id).
func diditConfirmCommitmentSigMessage(zkCommitment, pollID string) []byte {
	h := sha256.New()
	h.Write([]byte("confirm:"))
	h.Write([]byte(zkCommitment))
	h.Write([]byte(pollID))
	return h.Sum(nil)
}

// diditIdentityHash = sha256(voter_pub_key || poll_id) hex-encoded.
func diditIdentityHash(voterPubKey, pollID string) string {
	h := sha256.New()
	h.Write([]byte(voterPubKey))
	h.Write([]byte(pollID))
	return hex.EncodeToString(h.Sum(nil))
}
