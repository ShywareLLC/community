package com.sayists.shyware

// JVM stubs for Android-only types excluded from the JVM build.
// Real implementations live in WriteOnlyPosture.kt and ReceiptStore.kt.

data class PlayIntegritySignal(val available: Boolean = false, val passed: Boolean = false)
data class DeviceAttestationSignal(val trusted: Boolean = false)
data class NetworkSignal(val hostile: Boolean = false)

data class RuntimeSignals(
    val playIntegrity: PlayIntegritySignal? = null,
    val deviceAttestation: DeviceAttestationSignal? = null,
    val network: NetworkSignal? = null,
) {
    companion object {
        val untrusted = RuntimeSignals()
    }
}

data class PostureResult(
    val writeOnly: Boolean,
    val recoverable: Boolean,
    val fallbackReasons: Set<String> = emptySet(),
)

data class BallotReceipt(
    val pollId: String = "",
    val ballotId: String = "",
    val ballotNonce: String = "",
    val choice: String = "",
    val identityHash: String = "",
    val submissionId: String = "",
    val timestamp: Long = 0L,
)

class EncryptedReceiptStore {
    fun save(receipt: BallotReceipt) {}
    fun load(pollId: String): BallotReceipt? = null
}

fun resolveEffectivePosture(manifest: ShyConfig, signals: RuntimeSignals): PostureResult {
    val defaultPosture = manifest.deployment?.defaultPosture ?: "recoverable"
    val fallbacks = manifest.deployment?.runtimeFallbacks
    val reasons = mutableSetOf<String>()

    var forceWriteOnly = defaultPosture == "coercion_resistant"
    if (fallbacks != null) {
        if (fallbacks.writeOnlyOnMissingPlayIntegrity && (signals.playIntegrity == null || !signals.playIntegrity.passed)) {
            forceWriteOnly = true; reasons.add("missing_play_integrity")
        }
        if (fallbacks.writeOnlyOnUntrustedDeviceAttestation && (signals.deviceAttestation == null || !signals.deviceAttestation.trusted)) {
            forceWriteOnly = true; reasons.add("untrusted_device_attestation")
        }
        if (fallbacks.writeOnlyOnHostileNetwork && signals.network?.hostile == true) {
            forceWriteOnly = true; reasons.add("hostile_network")
        }
    }
    return PostureResult(writeOnly = forceWriteOnly, recoverable = !forceWriteOnly, fallbackReasons = reasons)
}
