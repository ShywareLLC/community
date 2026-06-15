package com.sayists.shyware

import java.security.MessageDigest

// Mirrors identityClient.js commitment derivation:
// SHA-256(namespace:provider:source[:scope])

sealed class IdentityInput {
    data class Didit(val personId: String) : IdentityInput()
    data class DiditJourney(val journeyId: String) : IdentityInput()
    data class Wallet(val address: String) : IdentityInput()
    data class Identus(val subjectId: String) : IdentityInput()
    data class Raw(val value: String) : IdentityInput()
}

fun createIdentityCommitment(
    manifest: ShyConfig,
    input: IdentityInput,
    namespace: String = "stable_identity",
    scope: String = "",
): String {
    val provider = manifest.identity.provider
    val source = stableIdentitySource(provider, input)
    val parts = mutableListOf(namespace, provider, source)
    if (scope.isNotEmpty()) parts.add(scope)
    return sha256hex(parts.joinToString(":"))
}

fun createIdentityProofHash(
    manifest: ShyConfig,
    input: IdentityInput,
    scope: String = "",
    audience: String = "",
): String? {
    val provider = manifest.identity.provider
    if (provider == "wallet" || provider == "none") return null
    val source = stableIdentitySource(provider, input)
    val workflowId = manifest.identity.workflowId ?: ""
    val issuerDid = manifest.identity.issuerDid ?: ""
    val parts = listOf("proof", provider, source, workflowId, issuerDid, scope, audience, "")
    return sha256hex(parts.joinToString(":"))
}

private fun stableIdentitySource(provider: String, input: IdentityInput): String = when {
    provider == "didit" && input is IdentityInput.Didit         -> input.personId
    provider == "didit" && input is IdentityInput.DiditJourney  -> input.journeyId
    provider == "wallet" && input is IdentityInput.Wallet       -> input.address.lowercase()
    provider == "identus" && input is IdentityInput.Identus     -> input.subjectId
    input is IdentityInput.Raw                                   -> input.value
    else -> throw ShywareException("Identity input type does not match manifest provider '$provider'.")
}

internal fun sha256hex(input: String): String {
    val digest = MessageDigest.getInstance("SHA-256")
    val bytes = digest.digest(input.toByteArray(Charsets.UTF_8))
    return bytes.joinToString("") { "%02x".format(it) }
}
