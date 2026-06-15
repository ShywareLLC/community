package shycam

import (
	"crypto/ed25519"
	"fmt"

	"github.com/ShywareLLC/community/shywire/types"
)

// VerifyLiveness checks a LivenessProof signature against the operator's registered public key.
// No video bytes needed — the frame hash is already in the proof.
// Any customer can call this independently using the operator's public key from the
// on-chain WarehouseOperatorRecord.
func VerifyLiveness(p *LivenessProof, operatorPubKey ed25519.PublicKey) LivenessVerdict {
	v := LivenessVerdict{}

	msg, err := canonicalProof(p)
	if err != nil {
		v.Reason = fmt.Sprintf("failed to canonicalise proof: %v", err)
		return v
	}

	v.SigValid = ed25519.Verify(operatorPubKey, msg, p.Signature)
	if !v.SigValid {
		v.Reason = "signature invalid — proof not signed by registered operator key"
		return v
	}

	v.OK = true
	return v
}

// VerifyFeedFreshness checks whether a warehouse's liveness feed is current.
// staleSec is the maximum acceptable gap between proofs in seconds.
// Returns a verdict with GapSec set to the time since the last proof.
func VerifyFeedFreshness(feed *LivenessFeed, nowUnix, staleSec int64, operatorPubKey ed25519.PublicKey) LivenessVerdict {
	if len(feed.Proofs) == 0 {
		return LivenessVerdict{Reason: fmt.Sprintf("no liveness proofs published for warehouse %s", feed.WarehouseID)}
	}

	latest := feed.Proofs[0]
	gap := nowUnix - latest.Timestamp

	v := VerifyLiveness(latest, operatorPubKey)
	v.GapSec = gap

	if v.OK && gap > staleSec {
		v.OK = false
		v.Reason = fmt.Sprintf("liveness feed stale: last proof %ds ago, threshold %ds", gap, staleSec)
	}

	return v
}

// SummariseLots produces the asset-level proof-of-physical-reserves view.
// feeds is keyed by WarehouseID. operatorKeys is keyed by OperatorID.
// staleSec is how old the most recent liveness proof can be before flagging underbacked.
func SummariseLots(
	assetID string,
	lots []*types.IntakeLotRecord,
	feeds map[string]*LivenessFeed,
	operatorKeys map[string]ed25519.PublicKey,
	nowUnix, staleSec int64,
) ReserveSummary {
	summary := ReserveSummary{
		AssetID:      assetID,
		LivenessCurrent: true,
	}

	seen := map[string]bool{} // warehouses already checked for liveness

	for _, lot := range lots {
		if lot.AssetID != assetID || lot.Status == "exhausted" {
			continue
		}
		summary.TotalOnChainQty += lot.RemainingQuantity

		if seen[lot.WarehouseID] {
			continue
		}
		seen[lot.WarehouseID] = true

		feed, ok := feeds[lot.WarehouseID]
		if !ok {
			summary.LivenessCurrent = false
			summary.Underbacked = true
			continue
		}

		pubKey, ok := operatorKeys[lot.OperatorID]
		if !ok {
			summary.LivenessCurrent = false
			summary.Underbacked = true
			continue
		}

		v := VerifyFeedFreshness(feed, nowUnix, staleSec, pubKey)
		if v.GapSec > summary.MaxFeedGapSec {
			summary.MaxFeedGapSec = v.GapSec
		}
		if !v.OK {
			summary.LivenessCurrent = false
			summary.Underbacked = true
		}
	}

	return summary
}
