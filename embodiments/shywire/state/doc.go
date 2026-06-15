// Package state implements the two-list anonymous transfer protocol state machine.
//
// Two maps enforce the anonymity separation on-chain:
//
//	transferRecords (List 1): transfer_id → TransferRecord  — amount + asset, no identity
//	participants    (List 2): nullifier   → ParticipantRecord — identity only, no amount
//
// The invariant |L1| == |L2|, never joined on-chain, mirrors the voting protocol.
//
// Value conservation: for every Transfer or ExecuteContract tx, sender.Balance -= Amount
// and recipient.Balance += Amount. The state machine verifies this before execution.
//
// Contracts extend the same model:
//
//	contracts:          contract_id  → ContractRecord
//	contractExecutions: execution_id → ContractExecutionRecord
//
// Contract executions still write to the standard transferRecords + participants maps
// so the two-list invariant continues to hold for all contract flows.
//
// Supply invariants (enforced by executeMint / executeBurn):
//
//	TotalSupply = TotalMinted - TotalBurned  (per asset)
//
// Only the operator (validator key) may register assets, mint, or burn.
package state
