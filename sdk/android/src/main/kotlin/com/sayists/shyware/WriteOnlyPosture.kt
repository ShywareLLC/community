package com.sayists.shyware

import android.content.Context
import kotlinx.serialization.json.Json

// Mirrors resolveEffectivePosture in votingClient.js.
// Absorbs the authority matrix and receipt policy from DeploymentPosture.kt (Seda Haqq).

private val configJson = Json { ignoreUnknownKeys = true }
private const val SHYCONFIG_ASSET = "shyconfig.json"

data class RuntimeSignals(
    val playIntegrity: PlayIntegritySignal = PlayIntegritySignal(),
    val deviceAttestation: DeviceAttestationSignal = DeviceAttestationSignal(),
    val network: NetworkSignal = NetworkSignal(),
    val hsm: HSMSignal = HSMSignal(),
) {
    companion object {
        val trusted get() = RuntimeSignals(deviceAttestation = DeviceAttestationSignal(trusted = true))
        val untrusted get() = RuntimeSignals()
    }
}

data class PlayIntegritySignal(val available: Boolean = false, val passed: Boolean = false)
data class DeviceAttestationSignal(val trusted: Boolean = false)
data class NetworkSignal(val hostile: Boolean = false)
data class HSMSignal(val available: Boolean = true)

data class PostureResult(
    val configuredPosture: String,
    val effectivePosture: String,
    val fallbackActive: Boolean,
    val fallbackReasons: List<String>,
    val runtimeSignals: RuntimeSignals,
) {
    val writeOnly: Boolean get() = effectivePosture == "write_only"
    val recoverable: Boolean get() = effectivePosture == "recoverable"
}

data class EffectiveReceiptPolicy(
    val matchStore: String,
    val userAccess: String,
    val effectiveUserAccess: String,
    val recoverySignals: List<String>,
    val writeOnly: Boolean,
)

data class AuthorityAccess(
    val authority: String,
    val canonicalBlockchainRead: String,
    val canonicalBlockchainWrite: String,
    val privateReconcileRead: String,
    val privateReconcileWrite: String,
)

data class VotingInitialization(
    val contractVersion: String,
    val appId: String,
    val chainId: String?,
    val apiBase: String,
    val submitBase: String,
    val posture: PostureResult,
    val receipts: EffectiveReceiptPolicy?,
    val authorityMatrix: List<AuthorityAccess>,
    val requiredFlows: List<String>,
)

fun loadShyConfig(context: Context): ShyConfig =
    context.assets.open(SHYCONFIG_ASSET).bufferedReader().use { reader ->
        configJson.decodeFromString<ShyConfig>(reader.readText())
    }

fun resolveEffectivePosture(manifest: ShyConfig, signals: RuntimeSignals): PostureResult {
    val fallbacks = manifest.deployment.runtimeFallbacks
    val reasons = mutableListOf<String>()

    if (fallbacks.writeOnlyOnMissingPlayIntegrity &&
        (!signals.playIntegrity.available || !signals.playIntegrity.passed))
        reasons.add("missing_play_integrity")
    if (fallbacks.writeOnlyOnUntrustedDeviceAttestation && !signals.deviceAttestation.trusted)
        reasons.add("untrusted_device_attestation")
    if (fallbacks.writeOnlyOnHostileNetwork && signals.network.hostile)
        reasons.add("hostile_network")
    if (fallbacks.writeOnlyOnHSMUnavailable && !signals.hsm.available)
        reasons.add("hsm_unavailable")

    val configured = manifest.deployment.defaultPosture
    val effective = if (configured == "coercion_resistant" || reasons.isNotEmpty()) "write_only" else "recoverable"

    return PostureResult(
        configuredPosture = configured,
        effectivePosture = effective,
        fallbackActive = reasons.isNotEmpty(),
        fallbackReasons = reasons,
        runtimeSignals = signals,
    )
}

fun resolveEffectiveReceiptPolicy(manifest: ShyConfig, posture: PostureResult): EffectiveReceiptPolicy? {
    val receipts = manifest.receipts ?: return null
    return if (!posture.writeOnly) {
        EffectiveReceiptPolicy(
            matchStore = receipts.matchStore,
            userAccess = receipts.userAccess,
            effectiveUserAccess = receipts.userAccess,
            recoverySignals = emptyList(),
            writeOnly = false,
        )
    } else {
        EffectiveReceiptPolicy(
            matchStore = "none",
            userAccess = "never",
            effectiveUserAccess = "never",
            recoverySignals = emptyList(),
            writeOnly = true,
        )
    }
}

fun buildAuthorityMatrix(posture: PostureResult): List<AuthorityAccess> = listOf(
    AuthorityAccess(
        authority = "voter_hostile_state",
        canonicalBlockchainRead = "anonymous_public_state_only",
        canonicalBlockchainWrite = "ballot_submission_only",
        privateReconcileRead = if (posture.writeOnly) "none" else "policy_gated",
        privateReconcileWrite = "none",
    ),
    AuthorityAccess(
        authority = "voter_safe_recovery_context",
        canonicalBlockchainRead = "anonymous_public_state_only",
        canonicalBlockchainWrite = "none",
        privateReconcileRead = if (posture.writeOnly) "none" else "policy_gated",
        privateReconcileWrite = "none",
    ),
    AuthorityAccess(
        authority = "reconciling_authority",
        canonicalBlockchainRead = "anonymous_public_state_only",
        canonicalBlockchainWrite = "none",
        privateReconcileRead = if (posture.writeOnly) "disabled" else "read_only",
        privateReconcileWrite = "none",
    ),
    AuthorityAccess(
        authority = "adversary_public_chain_only",
        canonicalBlockchainRead = "anonymous_public_state_only",
        canonicalBlockchainWrite = "none",
        privateReconcileRead = "none",
        privateReconcileWrite = "none",
    ),
)

fun initializeFromShyConfig(context: Context, signals: RuntimeSignals = RuntimeSignals.untrusted): VotingInitialization {
    val config = loadShyConfig(context)
    val posture = resolveEffectivePosture(config, signals)
    return VotingInitialization(
        contractVersion = config.contractVersion,
        appId = config.app.id,
        chainId = config.app.chainId,
        apiBase = config.api.baseUrl,
        submitBase = config.api.submitBaseUrl ?: config.api.baseUrl,
        posture = posture,
        receipts = resolveEffectiveReceiptPolicy(config, posture),
        authorityMatrix = buildAuthorityMatrix(posture),
        requiredFlows = config.anonLayer.requiredFlows,
    )
}
