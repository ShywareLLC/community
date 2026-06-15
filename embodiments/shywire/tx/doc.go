// Package tx defines the wire format for shyware anonymous transfer transactions.
//
// Transaction types:
//   - TxTypeRegisterAsset (1): operator registers a new asset type
//   - TxTypeMint (2): operator mints supply to an account (issuance)
//   - TxTypeBurn (3): operator burns supply from an account (redemption)
//   - TxTypeTransfer (4): anonymous transfer — the core two-list transaction
//   - TxTypeRegisterAccount (5): register account_commitment = H(wallet_address)
//   - TxTypeRegisterValidator (6): add/remove consensus validator
//
// The Transfer transaction enforces the two-list invariant:
// transfer_id = H(TransferNonce) goes to List 1 (amount only, no identity).
// Nullifier = H(wallet_address, transfer_id) goes to List 2 (identity only, no amount).
package tx
