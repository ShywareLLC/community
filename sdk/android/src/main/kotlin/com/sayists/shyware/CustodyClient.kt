package com.sayists.shyware

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.security.SecureRandom

// MARK: - Custody result types

@Serializable
data class CustodyLot(
    @SerialName("lot_id") val lotId: String,
    @SerialName("asset_id") val assetId: String,
    @SerialName("policy_id") val policyId: String,
    @SerialName("operator_id") val operatorId: String,
    @SerialName("warehouse_id") val warehouseId: String,
    @SerialName("sku_class_id") val skuClassId: String,
    val quantity: Double,
    @SerialName("minted_amount") val mintedAmount: Long,
)

@Serializable
data class CustodyPolicy(
    @SerialName("policy_id") val policyId: String,
    @SerialName("asset_id") val assetId: String,
    val name: String,
    @SerialName("redemption_mode") val redemptionMode: String,
)

@Serializable
data class SiloBalance(
    @SerialName("asset_id") val assetId: String,
    @SerialName("account_commitment") val accountCommitment: String,
    val balance: Long,
)

// MARK: - Manifest validation

fun assertCustodyManifest(config: ShyConfig) {
    require(config.contractVersion == "shycustody-v1") {
        "contract_version must be shycustody-v1"
    }
    require(config.anonLayer.blackBoxRequired) {
        "anon_layer.black_box_required must be true"
    }
    require(config.signing.required && config.signing.backend != "none") {
        "Signing must be required and enabled"
    }
    requireNotNull(config.custody) { "shyconfig must declare custody settings for shycustody apps." }
    val transferLayer = config.custody?.transferLayer
    require(transferLayer == null || transferLayer == "shywire") {
        "shyconfig custody.transfer_layer must be \"shywire\" when declared."
    }
    val required = setOf(
        "policy_read", "lot_record", "silo_transfer",
        "redemption_request", "redemption_settlement", "demurrage_apply"
    )
    for (flow in required) {
        require(flow in config.anonLayer.requiredFlows) { "Missing required flow: $flow" }
    }
}

// MARK: - Client

class CustodyClient internal constructor(
    val manifest: ShyConfig,
    private val operatorMode: Boolean = false,
) {
    private val http = OkHttpClient()
    private val json = Json { ignoreUnknownKeys = true }
    private val jsonMediaType = "application/json".toMediaType()
    private val rng = SecureRandom()

    companion object {
        fun from(manifest: ShyConfig, operatorMode: Boolean = false): CustodyClient {
            assertCustodyManifest(manifest)
            return CustodyClient(manifest, operatorMode)
        }

        /** Build without manifest assertion. Used by LotsClient. */
        internal fun fromRaw(manifest: ShyConfig, operatorMode: Boolean = false): CustodyClient =
            CustodyClient(manifest, operatorMode)
    }

    // MARK: - Read

    suspend fun getLotPolicy(policyId: String): CustodyPolicy = withContext(Dispatchers.IO) {
        get("/custody/policies/$policyId")
    }

    suspend fun getSiloBalance(assetId: String, accountCommitment: String): SiloBalance =
        withContext(Dispatchers.IO) {
            get("/custody/silos/$assetId/balance?account_commitment=$accountCommitment")
        }

    // MARK: - Write (operator)

    suspend fun recordIntakeLot(
        lotId: String,
        policyId: String,
        assetId: String,
        operatorId: String,
        warehouseId: String,
        accountCommitment: String,
        skuClassId: String,
        quantity: Double,
        mintedAmount: Long,
        videoSessionRef: String,
        evidenceRefs: List<String>,
    ): Map<String, Any> = withContext(Dispatchers.IO) {
        requireOperatorMode("recordIntakeLot")
        val timestamp = System.currentTimeMillis() / 1000
        val data = JSONObject().apply {
            put("lot_id", lotId)
            put("policy_id", policyId)
            put("asset_id", assetId)
            put("operator_id", operatorId)
            put("warehouse_id", warehouseId)
            put("account_commitment", accountCommitment)
            put("sku_class_id", skuClassId)
            put("quantity", quantity)
            put("minted_amount", mintedAmount)
            put("video_session_ref", videoSessionRef)
            put("evidence_refs", org.json.JSONArray(evidenceRefs))
            put("timestamp", timestamp)
        }
        val txJson = buildTxJson(13, data)
        postTx("/custody/lots", txJson)
    }

    suspend fun mintSilo(
        assetId: String,
        accountCommitment: String,
        amount: Long,
    ): Map<String, Any> = withContext(Dispatchers.IO) {
        requireOperatorMode("mintSilo")
        val data = JSONObject().apply {
            put("asset_id", assetId)
            put("account_commitment", accountCommitment)
            put("amount", amount)
            put("timestamp", System.currentTimeMillis() / 1000)
        }
        val txJson = buildTxJson(2, data)
        postTx("/custody/silos/mint", txJson)
    }

    suspend fun transferSilo(
        assetId: String,
        senderCommitment: String,
        recipientCommitment: String,
        amount: Long,
    ): Map<String, Any> = withContext(Dispatchers.IO) {
        val transferNonce = randomHex(32)
        val nullifier = sha256hex("$senderCommitment:$assetId:$transferNonce")
        val data = JSONObject().apply {
            put("asset_id", assetId)
            put("sender_commitment", senderCommitment)
            put("recipient_commitment", recipientCommitment)
            put("amount", amount)
            put("nullifier", nullifier)
            put("transfer_nonce", transferNonce)
            put("sender_proof", "AQ==")
            put("timestamp", System.currentTimeMillis() / 1000)
        }
        val txJson = buildTxJson(4, data)
        postTx("/custody/silos/transfer", txJson)
    }

    suspend fun requestLotRedemption(
        assetId: String,
        accountCommitment: String,
        warehouseId: String,
        skuClassId: String,
        siloAmount: Long,
        requestedQuantity: Double,
    ): Map<String, Any> = withContext(Dispatchers.IO) {
        val requestId = sha256hex("${randomHex(8)}:${System.currentTimeMillis()}")
        val data = JSONObject().apply {
            put("request_id", requestId)
            put("asset_id", assetId)
            put("account_commitment", accountCommitment)
            put("warehouse_id", warehouseId)
            put("sku_class_id", skuClassId)
            put("silo_amount", siloAmount)
            put("requested_quantity", requestedQuantity)
            put("destination_ref", "")
            put("timestamp", System.currentTimeMillis() / 1000)
        }
        val txJson = buildTxJson(14, data)
        postTx("/custody/redemptions", txJson)
    }

    suspend fun periodClose(scopingId: String, l1MerkleRoot: String, l2MerkleRoot: String): Map<String, Any> =
        withContext(Dispatchers.IO) {
            requireOperatorMode("periodClose")
            val body = JSONObject().apply {
                put("scopingId", scopingId)
                put("l1MerkleRoot", l1MerkleRoot)
                put("l2MerkleRoot", l2MerkleRoot)
            }.toString().toRequestBody(jsonMediaType)
            post("/custody/period-close", body)
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

    private fun buildTxJson(type: Int, data: JSONObject): String =
        JSONObject().apply {
            put("type", type)
            put("signature", "AQ==")
            put("data", data)
        }.toString()

    private fun postTx(path: String, txJson: String): Map<String, Any> {
        val body = JSONObject().put("tx", txJson).toString().toRequestBody(jsonMediaType)
        return post(path, body)
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
