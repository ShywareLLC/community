// Package submission implements the generic two-list invariant base for the shyware protocol.
//
// # Architecture
//
// All shyware regulated domains share a single structural primitive: the two-list
// invariant. Every participant submission atomically writes two disjoint records:
//
//   - List 1 (submissions): direction-free submission identifier + payload. No identity.
//   - List 2 (participants): participant identity commitment. No payload, no submission ID.
//
// No join key between List 1 and List 2 is ever written to canonical state.
// The count-match invariant |L1(P)| = |L2(P)| = N_P is enforced at period close.
//
// # TwoListBase
//
// TwoListBase is an embeddable struct that domain state machines (shychat, shystore,
// and shyvoting if migrated) compose to inherit the invariant enforcement without
// duplicating it. The domain layer supplies:
//
//   - Domain-specific period metadata (mailboxes, buckets, polls).
//   - Identity verification (IDV attestation → identity_hash derivation).
//   - Domain-specific tx dispatch (MailboxCreate/MessageDispatch vs. SecretStore/BucketClose).
//
// TwoListBase supplies:
//
//   - SubmitToLists: atomic List 1 + List 2 write with dedup guard.
//   - UpdateSubmission: replace the List 1 entry; List 2 unchanged.
//   - WithdrawFromLists: bilateral deletion from both lists; count invariant preserved.
//   - ClosePeriod: count-match verification + HSM-signed closure record.
//   - CommitRollingAttestation: intermediate attestation without closing.
//   - DB persistence (Commit, loadState).
//   - Consensus validator management.
//
// # Domain isolation
//
// shyvoting's state machine is intentionally not refactored to embed TwoListBase in
// this pass — it has election-specific field names (voteDirections, voterRegistry) and
// a mature test suite. The migration path is: (1) verify TwoListBase API against shychat
// and shystore; (2) migrate shyvoting to embed TwoListBase in a follow-on.
package submission
