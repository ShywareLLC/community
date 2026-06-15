package submission

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// BeaconWindowSize is the number of recent block hashes retained in the beacon
// window. Submission nonces must reference a beacon within this window.
const BeaconWindowSize = 20

// ValidateNonce checks that a submission nonce satisfies basic format and
// sanity requirements: exactly 64 hex characters (32 bytes), non-zero, and
// non-constant. These are structural input guards against degenerate inputs;
// they do not and need not establish any distributional property of the nonce,
// because the nonce by definition is a fresh value unrelated to identity
// credentials and does not appear in canonical state.
func ValidateNonce(nonce string) error {
	if len(nonce) != 64 {
		return fmt.Errorf(
			"submission nonce must be exactly 64 hex chars (32 bytes), got %d — use crypto/rand or Web Crypto getRandomValues",
			len(nonce),
		)
	}
	b, err := hex.DecodeString(nonce)
	if err != nil {
		return fmt.Errorf("submission nonce must be valid lowercase hex: %w", err)
	}
	allZero := true
	for _, v := range b {
		if v != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("submission nonce is all-zero: RNG failure")
	}
	allSame := true
	for i := 1; i < len(b); i++ {
		if b[i] != b[0] {
			allSame = false
			break
		}
	}
	if allSame {
		return fmt.Errorf("submission nonce is constant-byte (%02x): RNG failure", b[0])
	}
	return nil
}

// ValidateBeacon verifies that the submitted beacon fields are consistent with
// the canonical beacon window: the block hash at the given height matches the
// BFT-committed value stored by the state machine.
//
// The beacon is a canonical block hash committed by BFT consensus before the
// submission session. Because the beacon was committed to canonical state before
// identity information was presented, any party holding the ledger can verify
// that the submission identifier — derived as H(beacon || nonce) — was
// conditioned on a value not yet known when identity was generated. This makes
// the identifier's freshness externally auditable without trust in the
// submitting device.
//
// window maps block height → canonical hex-encoded block hash. Entries outside
// BeaconWindowSize are pruned to prevent replay of stale beacons.
func ValidateBeacon(beaconBlockHash string, beaconBlockHeight int64, window map[int64]string) error {
	if len(beaconBlockHash) != 64 {
		return fmt.Errorf(
			"beacon_block_hash must be exactly 64 hex chars (32 bytes), got %d",
			len(beaconBlockHash),
		)
	}
	if _, err := hex.DecodeString(beaconBlockHash); err != nil {
		return fmt.Errorf("beacon_block_hash must be valid hex: %w", err)
	}
	if beaconBlockHeight <= 0 {
		return fmt.Errorf("beacon_block_height must be positive, got %d", beaconBlockHeight)
	}
	canonical, ok := window[beaconBlockHeight]
	if !ok {
		return fmt.Errorf(
			"beacon_block_height %d not in recent block window (window covers %d blocks) — client must fetch a recent block hash",
			beaconBlockHeight, BeaconWindowSize,
		)
	}
	if canonical != beaconBlockHash {
		return fmt.Errorf(
			"beacon_block_hash mismatch at height %d: canonical %s, submitted %s",
			beaconBlockHeight, canonical, beaconBlockHash,
		)
	}
	return nil
}

// DeriveSubmissionID derives the payload-free submission identifier from a
// beacon block hash and submission nonce.
//
//	submission_id = SHA-256(beacon_block_hash_bytes || nonce_bytes)
//
// The beacon is a BFT-committed block hash that was canonical before the
// submission session began. Any party holding the ledger can verify that the
// identifier was conditioned on a value not yet available when identity
// information was generated, confirming that the identifier could not have
// been predetermined with knowledge of identity inputs.
func DeriveSubmissionID(beaconBlockHash, nonce string) (string, error) {
	beaconBytes, err := hex.DecodeString(beaconBlockHash)
	if err != nil {
		return "", fmt.Errorf("beacon_block_hash: %w", err)
	}
	nonceBytes, err := hex.DecodeString(nonce)
	if err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}
	combined := append(beaconBytes, nonceBytes...) //nolint:gocritic
	h := sha256.Sum256(combined)
	return hex.EncodeToString(h[:]), nil
}
