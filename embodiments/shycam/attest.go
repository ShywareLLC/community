package shycam

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// NewLivenessProof produces a signed LivenessProof from a single video frame hash.
// The frameHash is computed by the camera device or co-located HSM — the full frame
// bytes never need to leave the device. Call HashFrame first if you have the raw bytes.
func NewLivenessProof(
	warehouseID, operatorID, streamRef string,
	frameHash []byte,
	privateKey ed25519.PrivateKey,
) (*LivenessProof, error) {
	if warehouseID == "" || operatorID == "" || streamRef == "" {
		return nil, fmt.Errorf("warehouseID, operatorID, streamRef are required")
	}
	if len(frameHash) == 0 {
		return nil, fmt.Errorf("frameHash required")
	}

	p := &LivenessProof{
		WarehouseID: warehouseID,
		OperatorID:  operatorID,
		FrameHash:   hex.EncodeToString(frameHash),
		StreamRef:   streamRef,
		Timestamp:   time.Now().Unix(),
	}

	sig, err := signProof(p, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign liveness proof: %w", err)
	}
	p.Signature = sig

	return p, nil
}

// HashFrame hashes a single raw video frame.
// Call this on the camera device before calling NewLivenessProof.
// Devices that compute the hash internally (HSM-attached cameras) skip this.
func HashFrame(frameBytes []byte) []byte {
	h := sha256.Sum256(frameBytes)
	return h[:]
}

// HashIntakeRecording hashes a complete intake event recording.
// The result is the value that goes into IntakeLotRecord.VideoSessionRef on-chain.
// This is the only place in shycam where a full video file is hashed —
// intake recordings are discrete files, not streams.
func HashIntakeRecording(recordingBytes []byte) string {
	h := sha256.Sum256(recordingBytes)
	return hex.EncodeToString(h[:])
}

// signProof serialises the proof without its Signature field and signs it.
func signProof(p *LivenessProof, key ed25519.PrivateKey) ([]byte, error) {
	msg, err := canonicalProof(p)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(key, msg), nil
}

func canonicalProof(p *LivenessProof) ([]byte, error) {
	copy := *p
	copy.Signature = nil
	return json.Marshal(copy)
}
