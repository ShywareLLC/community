// Package tx encodes, decodes, and statlessly validates protocol transactions.
//
// # Usage
//
// DecodeTx and EncodeTx are the only serialization functions consumers need.
// Tx.Validate performs stateless checks (type range, required fields, JSON
// well-formedness). Stateful checks — duplicate vote detection, ZK proof
// verification, Didit signature validation — live in state.State.
//
// # Transaction data payloads
//
// Each Tx carries a JSON-encoded data payload whose concrete type is determined
// by Tx.Type:
//
//	TxTypePollCreate       → PollCreateData
//	TxTypeBallotCast       → BallotCastData
//	TxTypePollClose        → PollCloseData
//	TxTypeRegisterValidator → ValidatorRegistrationData
//	TxTypeConfirmReceipt   → ConfirmReceiptData
//
// Use Tx.UnmarshalData to decode the payload into the appropriate struct.
package tx
