// Package state implements the canonical two-list ballot apparatus.
//
// # Invariants
//
// The state machine enforces three invariants on every committed block:
//
//  1. len(voteDirections) == len(voterRegistry) == TotalVotes  (count-match)
//  2. ZK nullifier proof verifies before any ballot is accepted  (per-poll dedup)
//  3. Didit Ed25519 commitment signature verifies before any ballot  (IDV binding)
//
// If any invariant is violated, the transaction is rejected and the block is
// not committed with that transaction included.
//
// # Two-list separation
//
// voteDirections (List 1) stores anonymous vote directions, keyed by ballot_id.
// voterRegistry (List 2) stores verified participation records, keyed by
// identity_hash (ZK nullifier). These maps are stored under separate LevelDB
// key prefixes and are never joined on-chain. Anonymity is structural, not policy.
//
// # Lifecycle
//
// Callers use ValidateTx during CheckTx (mempool) and ExecuteTx during
// FinalizeBlock (consensus). Commit persists state to LevelDB and returns the
// new app hash. This matches the CometBFT ABCI 2.0 contract.
package state
