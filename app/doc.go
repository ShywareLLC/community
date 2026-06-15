// Package app wraps state.State in a CometBFT ABCI 2.0 application.
//
// # Construction
//
// Deployments instantiate App via New, passing a Config that specifies the ZK
// verifying-key path and Didit Ed25519 public key. Both are mandatory: New
// returns an error if either is absent or cannot be loaded.
//
// # ABCI 2.0
//
// App implements the FinalizeBlock / Commit split introduced in CometBFT 0.38.
// FinalizeBlock processes all transactions in a block and applies any validator
// set updates. Commit signals that the block is final and triggers state.Commit.
//
// # Observability
//
// All handlers emit OpenTelemetry spans via the configured tracer. PII guardrail:
// span attributes never include poll_id, ballot_id, or identity_hash.
package app
