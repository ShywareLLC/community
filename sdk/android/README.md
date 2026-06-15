# Shyware Android SDK

Kotlin/JVM client library for the Shyware two-list anonymous ledger protocol.  
Package: `com.sayists.shyware` · Min SDK: API 26 · Language: Kotlin 2.0

---

## Installation

Add to your module `build.gradle.kts`:

```kotlin
dependencies {
    implementation("com.sayists:shyware-android:<version>")
}
```

Or include as a local source module (monorepo):

```kotlin
includeBuild("../shyware/sdk/android")
```

---

## Clients

Each client is constructed from a `ShyConfig` manifest decoded from your `shyconfig.json`.

| Client | Contract version | Domain |
|---|---|---|
| `VotingClient` | `shyvoting-v1` | Elections / referenda |
| `WireClient` | `shywire-v1` | Private value transfer |
| `SharesClient` | `shyshares-v1` | DAO governance / tokenized equity |
| `CustodyClient` | `shycustody-v1` | Physical commodity custody |
| `ContractsClient` | `shycontracts-v1` | Revenue-based financing |
| `StoreClient` | `shystore-v1` | Sealed anonymous store |
| `StreamClient` | `shystream-v1` | Anonymous stream segments |
| `ChatClient` | `shychat-v1` | End-to-end sealed messaging |
| `BrowserClient` | `shybrowser-v1` | Anonymous browser analytics |
| `BetsClient` | `shybets-v1` | Anonymous prediction markets |
| `LotsClient` | `shylots-v1` | Sealed-bid auction lots |

---

## Quick start — shyvoting

```kotlin
val config = ShyConfig.fromAsset(context, "shyconfig.json")
val client = VotingClient.from(config)

// Cast a ballot (L1 + L2 two-list atomic write)
val ballot = runBlocking {
    client.castBallot(
        pollId = "poll-2026-general",
        choice = "yes",
        input  = IdentityInput.Didit(personId = "user-didit-person-id"),
    )
}
// ballot.ballotId — server-assigned direction-free identifier (List 1)
// ballot.ballotNonce — local nonce for inclusion-proof recovery
```

---

## Key types

### `ShyConfig`

Decoded from `shyconfig.json`. All clients take a `ShyConfig` via `Client.from(config)`.

```kotlin
data class ShyConfig(
    val contractVersion: String,
    val app:    AppConfig,
    val api:    ApiConfig,          // baseUrl, submitBaseUrl, requiresAuth
    val identity: IdentityConfig,   // provider, mode, kycRequired
    val signing:  SigningConfig,     // required, backend
    val anonLayer: AnonLayerConfig, // blackBoxRequired, requiredFlows
    val receipts:  ReceiptsConfig,
    val deployment: DeploymentConfig,
    val wire:      WireConfig?,     // shywire settings
    val custody:   CustodyConfig?,
    val contracts: ContractsConfig?,
    val governance: GovernanceConfig?,
    val execution:  ExecutionConfig?,
    val store:     StoreConfig?,
    val messaging: MessagingConfig?,
    val sealer:    SealerConfig?,
    val stream:    StreamConfig?,
    val lots:      LotsConfig?,
)
```

### `IdentityInput`

How the caller asserts their identity for commitment derivation:

```kotlin
sealed class IdentityInput {
    data class Didit(val personId: String)          : IdentityInput()
    data class DiditJourney(val journeyId: String)  : IdentityInput()
    data class Wallet(val address: String)          : IdentityInput()
    data class Identus(val subjectId: String)       : IdentityInput()
    data class Raw(val value: String)               : IdentityInput()
}
```

### `BallotResult` (VotingClient)

```kotlin
data class BallotResult(
    val ballotId: String,      // server-assigned List-1 direction-free identifier
    val ballotNonce: String,   // local nonce; used for ballot-inclusion proof
    val identityHash: String,  // H(commitment || pollId) — never sent to IDV
    val txJson: String,        // full transaction payload (for audit trail)
)
```

### `WireSubmissionResult` (WireClient)

```kotlin
data class WireSubmissionResult(
    val submissionId: String,  // direction-free transfer identifier (List 1)
    val submissionNonce: String,
    val nullifier: String,
    val txJson: String,
) {
    val transferId: String get() = submissionId  // iOS cross-platform alias
}
```

### `WireCanonicalCount` (WireClient)

Contains the two-list count-match invariant fields:

```kotlin
data class WireCanonicalCount(
    val transferId: String,
    val count: Long,
    val ledger: WireCountLedger?,
) {
    val l1Count: Long    // List-1 record count (direction-free submissions)
    val l2Count: Long    // List-2 record count (identity registrations)
    val countMatch: Boolean  // l1Count == l2Count — structural invariant
}
```

---

## Write-only posture

Resolve the effective posture before deciding whether to retain receipts:

```kotlin
client.setRuntimeSignals(RuntimeSignals(
    playIntegrity       = PlayIntegritySignal(available = true, passed = true),
    deviceAttestation   = DeviceAttestationSignal(trusted = true),
    network             = NetworkSignal(hostile = false),
))
val posture = client.effectivePosture()
if (posture.writeOnly) {
    // suppress all readback — only the direction-free ballot/transfer ID is retained
}
```

---

## Manifest validation

Each `Client.from()` call validates the manifest before returning the client.  
Throws `IllegalArgumentException` with a descriptive message if the contract version,
required flows, signing configuration, or required domain block are missing.

---

## DPIA / GDPR note

This SDK implements structural anonymity by write architecture: the L1 submission
record and L2 identity record share no join key at the protocol layer.  
See `patent/mainhub/dpia/` for the full GDPR Data Protection Impact Assessment,
including per-domain evidence artifacts and the EDPB DPIA template output.
