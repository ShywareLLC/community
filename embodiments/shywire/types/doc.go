// Package types defines the data model for the shyware anonymous transfer protocol.
//
// shyware is a privacy layer, not a coin. Operators register assets (AssetRecord)
// and control supply via Mint/Burn. Users transfer assets anonymously via the
// two-list structural invariant:
//
//   - List 1 (TransferRecord): transfer_id → {amount, asset_id} — no identity
//   - List 2 (ParticipantRecord): nullifier → account_commitment — no amount
//
// The invariant |L1| == |L2|, never joined on-chain, is enforced by the state machine.
// Value conservation (Σ inputs == Σ outputs) is enforced per transfer.
//
// Production note: Amount and Balance fields are plaintext in this scaffold.
// The circuit layer (Pedersen commitments + range proofs over BN254) will replace
// these with cryptographic commitments, hiding individual amounts while keeping
// conservation provable. All TODO(circuit) markers indicate these replacement points.
package types
