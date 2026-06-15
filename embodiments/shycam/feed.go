package shycam

import (
	"fmt"
	"sort"
)

// Feed manages an in-memory liveness feed for a single warehouse.
// In production this is backed by an append-only store (CockroachDB, S3, etc.).
// Customers query the feed via the operator's public shycam API endpoint.
// Gaps in the timestamp sequence are detectable without operator cooperation.
type Feed struct {
	feed *LivenessFeed
}

func NewFeed(warehouseID string) *Feed {
	return &Feed{feed: &LivenessFeed{WarehouseID: warehouseID}}
}

// Append adds a liveness proof. Proofs are kept newest-first.
func (f *Feed) Append(p *LivenessProof) error {
	if p.WarehouseID != f.feed.WarehouseID {
		return fmt.Errorf("proof warehouse_id %s does not match feed warehouse_id %s", p.WarehouseID, f.feed.WarehouseID)
	}
	f.feed.Proofs = append(f.feed.Proofs, p)
	sort.Slice(f.feed.Proofs, func(i, j int) bool {
		return f.feed.Proofs[i].Timestamp > f.feed.Proofs[j].Timestamp
	})
	return nil
}

// Latest returns the most recent proof, or nil if the feed is empty.
func (f *Feed) Latest() *LivenessProof {
	if len(f.feed.Proofs) == 0 {
		return nil
	}
	return f.feed.Proofs[0]
}

// Since returns all proofs after the given unix timestamp.
func (f *Feed) Since(unixSec int64) []*LivenessProof {
	var out []*LivenessProof
	for _, p := range f.feed.Proofs {
		if p.Timestamp > unixSec {
			out = append(out, p)
		}
	}
	return out
}

// GapSeconds returns seconds since the last proof, or -1 if the feed is empty.
func (f *Feed) GapSeconds(nowUnix int64) int64 {
	latest := f.Latest()
	if latest == nil {
		return -1
	}
	return nowUnix - latest.Timestamp
}

// LivenessFeed returns the underlying feed for serialisation or RPC.
func (f *Feed) LivenessFeed() *LivenessFeed {
	return f.feed
}
