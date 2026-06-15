package com.sayists.shyware

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.security.SecureRandom

// MARK: - Wire result types

data class WireSubmissionResult(
    val submissionId: String,
    val submissionNonce: String,
    val nullifier: String,
    val txJson: String,
) {
    /** Cross-platform alias — iOS WireClient returns this field as `transferId`. */
    val transferId: String get() = submissionId
}

data class WireReceipt(
    val transferId: String,
    val transferNonce: String,
    val senderCommitment: String,
    val submittedAtMs: Long = System.currentTimeMillis(),
)

@Serializable
data class WireSupply(
    @kotlinx.serialization.SerialName("assetId") val assetId: String = "",
    @kotlinx.serialization.SerialName("totalUSDCe") val totalSupply: Long = 0L,
    @kotlinx.serialization.SerialName("circulatingSupply") val circulatingSupply: Long = totalSupply,
) {
    /** Cross-platform alias matching iOS WireClient.SupplyResult.totalUSDCe. */
    val totalUSDCe: Long get() = totalSupply
}

@Serializable
data class WireCountLedger(
    val l1Count: Long = 0L,
    val l2Count: Long = 0L,
    val countMatch: Boolean = (l1Count == l2Count),
)

@Serializable
data class WireCanonicalCount(
    val transferId: String = "",
    val count: Long = 0L,
    /** Count-match invariant — nested `ledger` block from the service response. */
    val ledger: WireCountLedger? = null,
) {
    /** List-1 record count for this scoping id. Mirrors iOS CountResult.l1Count. */
    val l1Count: Long get() = ledger?.l1Count ?: count
    /** List-2 record count for this scoping id. Mirrors iOS CountResult.l2Count. */
    val l2Count: Long get() = ledger?.l2Count ?: count
    /** True when l1Count == l2Count — the two-list structural invariant. */
    val countMatch: Boolean get() = ledger?.countMatch ?: (l1Count == l2Count)
}

// MARK: - Manifest validation

fun assertWireManifest(config: ShyConfig) {
    require(config.contractVersion == "shywire-v1") {
        "contract_version must be shywire-v1"
    }
    require(config.anonLayer.blackBoxRequired) {
        "anon_layer.black_box_required must be true"
    }
    val required = setOf("wire_issue", "wire_transfer", "wire_redeem")
    for (flow in required) {
        require(flow in config.anonLayer.requiredFlows) { "Missing required flow: $flow" }
    }
    require(config.signing.required && config.signing.backend != "none") {
        "Signing must be required and enabled"
    }
    requireNotNull(config.wire) { "shyconfig must declare wire settings for shywire apps." }
}

// MARK: - Client

class WireClient internal constructor(
    val manifest: ShyConfig,
    private val operatorMode: Boolean = false,
) {
    private val http = OkHttpClient()
    private val json = Json { ignoreUnknownKeys = true }
    private val jsonMediaType = "application/json".toMediaType()
    private val rng = SecureRandom()

    companion object {
        fun from(manifest: ShyConfig, operatorMode: Boolean = false): WireClient {
            assertWireManifest(manifest)
            return WireClient(manifest, operatorMode)
        }

        /** Build without wire manifest assertion. Used by BetsClient and LotsClient. */
        internal fun fromRaw(manifest: ShyConfig, operatorMode: Boolean = false): WireClient =
            WireClient(manifest, operatorMode)
    }

    // MARK: - Identity

    fun createIdentityCommitment(input: IdentityInput): String =
        com.sayists.shyware.createIdentityCommitment(manifest, input, namespace = "account")

    // MARK: - Read

    suspend fun getSupply(): WireSupply = withContext(Dispatchers.IO) {
        get("/supply/${manifest.wire?.assetId ?: ""}")
    }

    suspend fun getSupply(assetId: String): WireSupply = withContext(Dispatchers.IO) {
        get("/supply/$assetId")
    }

    suspend fun getCanonicalCount(transferId: String): WireCanonicalCount = withContext(Dispatchers.IO) {
        get("/wire/canonical/count/$transferId")
    }

    suspend fun getCanonicalFeed(): Map<String, Any> = withContext(Dispatchers.IO) {
        get("/wire/reconcile/feed")
    }

    suspend fun getReconcileHistory(): Map<String, Any> = withContext(Dispatchers.IO) {
        get("/wire/reconcile/history")
    }

    // MARK: - Account

    suspend fun registerAccount(walletAddress: String): Map<String, Any> = withContext(Dispatchers.IO) {
        val commitment = createIdentityCommitment(IdentityInput.Wallet(walletAddress))
        val walletProof = buildWalletProof(commitment, walletAddress)
        val body = JSONObject().apply {
            put("account_commitment", commitment)
            put("wallet_proof", walletProof)
        }.toString().toRequestBody(jsonMediaType)
        post("/accounts", body)
    }

    // MARK: - Transfer

    suspend fun wireSubmission(
        scopingId: String,
        senderCommitment: String,
        recipientCommitment: String,
        amount: Long,
    ): WireSubmissionResult = withContext(Dispatchers.IO) {
        val submissionNonce = randomHex(32)
        val nullifier = sha256hex("$senderCommitment:$scopingId:$submissionNonce")
        val submissionId = sha256hex(submissionNonce)
        val timestamp = System.currentTimeMillis() / 1000

        val data = JSONObject().apply {
            put("asset_id", scopingId)
            put("sender_commitment", senderCommitment)
            put("recipient_commitment", recipientCommitment)
            put("amount", amount)
            put("nullifier", nullifier)
            put("submission_nonce", submissionNonce)
            put("sender_proof", "AQ==")
            put("timestamp", timestamp)
        }
        val txJson = JSONObject().apply {
            put("type", 4)
            put("signature", "AQ==")
            put("data", data)
        }.toString()

        val bodyObj = JSONObject().put("tx", txJson).toString().toRequestBody(jsonMediaType)
        post("/transfers", bodyObj)

        WireSubmissionResult(
            submissionId = submissionId,
            submissionNonce = submissionNonce,
            nullifier = nullifier,
            txJson = txJson,
        )
    }

    // MARK: - Period close + rescind

    suspend fun periodClose(scopingId: String, l1MerkleRoot: String, l2MerkleRoot: String): Map<String, Any> =
        withContext(Dispatchers.IO) {
            requireOperatorMode("periodClose")
            val body = JSONObject().apply {
                put("scopingId", scopingId)
                put("l1MerkleRoot", l1MerkleRoot)
                put("l2MerkleRoot", l2MerkleRoot)
            }.toString().toRequestBody(jsonMediaType)
            post("/wire/period-close", body)
        }

    suspend fun rescind(transferId: String, eligibilityToken: String): Map<String, Any> =
        withContext(Dispatchers.IO) {
            requireOperatorMode("rescind")
            val body = JSONObject().apply {
                put("transfer_id", transferId)
                put("eligibility_token", eligibilityToken)
            }.toString().toRequestBody(jsonMediaType)
            post("/wire/rescind", body)
        }

    // MARK: - Helpers

    private fun requireOperatorMode(action: String) {
        require(operatorMode) { "$action requires operator authority." }
    }

    private fun randomHex(byteCount: Int): String {
        val bytes = ByteArray(byteCount)
        rng.nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private fun buildWalletProof(commitment: String, address: String): String {
        val msg = "shyware_account_registration:$commitment:$address"
        return java.util.Base64.getEncoder().encodeToString(msg.toByteArray())
    }

    private inline fun <reified T> get(path: String): T {
        val base = manifest.api.baseUrl.trimEnd('/')
        val req = Request.Builder().url("$base$path").get().build()
        http.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) throw ShywareException("HTTP ${resp.code}")
            return json.decodeFromString(resp.body!!.string())
        }
    }

    private fun post(path: String, body: okhttp3.RequestBody): Map<String, Any> {
        val base = (manifest.api.submitBaseUrl ?: manifest.api.baseUrl).trimEnd('/')
        val req = Request.Builder().url("$base$path").post(body).build()
        http.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) throw ShywareException("HTTP ${resp.code}")
            return emptyMap()
        }
    }
}
