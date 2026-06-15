// Package shycam provides warehouse transparency for shywire custody deployments.
//
// Two distinct concerns:
//
//  1. Intake recording — the specific event when physical goods arrive, are inspected,
//     and weighed. This is a discrete video file. Its SHA-256 goes into IntakeLotRecord.VideoSessionRef
//     on-chain so the recording is permanently bound to the lot.
//
//  2. Continuous presence — 24/7 live streams registered via WarehouseOperatorRecord.VideoStreamRef.
//     Customers watch directly. The camera's signing device (or a co-located HSM) emits
//     periodic LivenessProofs: a signed hash of a single frame, proving the stream is live
//     and not a loop. No full video is ever held in memory or hashed end-to-end.
package shycam

// LivenessProof is a signed assertion that a warehouse camera was live at Timestamp.
// The signing device (camera HSM or co-located signer) hashes one frame and signs it
// with the operator's Ed25519 key. Customers verify the signature independently.
//
// LivenessProofs are off-chain. They are published to a feed that any customer can query.
// The operator cannot selectively withhold proofs without creating a detectable gap.
type LivenessProof struct {
	WarehouseID string `json:"warehouse_id"` // matches WarehouseOperatorRecord.WarehouseID
	OperatorID  string `json:"operator_id"`  // matches WarehouseOperatorRecord.OperatorID
	FrameHash   string `json:"frame_hash"`   // SHA-256(one video frame) hex — not the full stream
	StreamRef   string `json:"stream_ref"`   // the stream identifier (matches VideoStreamRef on-chain)
	Timestamp   int64  `json:"timestamp"`    // unix seconds
	Signature   []byte `json:"signature"`    // Ed25519 sig over Canonical(this proof)
}

// LivenessFeed is an ordered sequence of LivenessProofs for a single warehouse, newest first.
// Gaps between proofs indicate periods where the operator stopped publishing — auditable by
// any customer from the timestamp sequence alone.
type LivenessFeed struct {
	WarehouseID string           `json:"warehouse_id"`
	Proofs      []*LivenessProof `json:"proofs"`
}

// LivenessVerdict is the result of VerifyLiveness.
type LivenessVerdict struct {
	OK       bool   `json:"ok"`
	SigValid bool   `json:"sig_valid"`
	GapSec   int64  `json:"gap_sec,omitempty"` // seconds since previous proof; 0 if first
	Reason   string `json:"reason,omitempty"`
}

// ReserveSummary is the asset-level proof-of-physical-reserves view.
// Produced by SummariseLots from on-chain lot records and the liveness feed.
type ReserveSummary struct {
	AssetID         string `json:"asset_id"`
	TotalOnChainQty int64  `json:"total_on_chain_qty"`  // sum of RemainingQuantity from active lots
	LivenessCurrent bool   `json:"liveness_current"`    // false if any warehouse feed has gone silent
	MaxFeedGapSec   int64  `json:"max_feed_gap_sec"`    // largest gap across all warehouse feeds
	Underbacked     bool   `json:"underbacked"`         // true if liveness is stale or feed missing
}
