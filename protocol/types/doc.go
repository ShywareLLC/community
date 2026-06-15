// Package types defines the shared data model for the Populist two-list voting protocol.
// Consumers embed these types when building ballots, querying tallies, or verifying receipts.
//
// # Transaction type constants
//
// TxTypePollCreate through TxTypeBatchFlush are the wire-format discriminators used
// in Tx.Type. They are accepted by state.State and broadcast over CometBFT.
//
// # Two-list architecture
//
// VoteRecord (List 1) and VoterRecord (List 2) are intentionally separate types.
// They are stored under different LevelDB key prefixes and are never linked on-chain.
// Anonymity is structural: no join key exists between a voter's identity and their
// vote direction.
package types
