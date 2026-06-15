package com.sayists.shyware

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.security.SecureRandom

// MARK: - Manifest validation

fun assertLotsManifest(config: ShyConfig) {
    require(config.anonLayer.blackBoxRequired) {
        "anon_layer.black_box_required must be true"
    }
    require(config.signing.required && config.signing.backend != "none") {
        "Signing must be required and enabled"
    }
}

// MARK: - Client

/**
 * LotsClient pairs CustodyClient + WireClient for lot auction flows.
 * The custody rail handles physical-lot tracking; the wire rail handles
 * bid bonds, award transfers, and settlement asset movements.
 */
class LotsClient private constructor(
    val manifest: ShyConfig,
    private val custodyClient: CustodyClient,
    private val wireClient: WireClient,
) {
    private val http = OkHttpClient()
    private val json = Json { ignoreUnknownKeys = true }
    private val jsonMediaType = "application/json".toMediaType()
    private val rng = SecureRandom()

    companion object {
        fun from(manifest: ShyConfig, operatorMode: Boolean = false): LotsClient {
            assertLotsManifest(manifest)
            val custody = CustodyClient.fromRaw(manifest, operatorMode)
            val wire = WireClient.fromRaw(manifest, operatorMode)
            return LotsClient(manifest, custody, wire)
        }
    }

    fun getCustodyClient(): CustodyClient = custodyClient
    fun getWireClient(): WireClient = wireClient

    // MARK: - Account + Funding

    suspend fun registerBidderAccount(walletAddress: String): Map<String, Any> =
        withContext(Dispatchers.IO) {
            val body = JSONObject().apply {
                put("wallet_address", walletAddress)
            }.toString().toRequestBody(jsonMediaType)
            post("/lots/accounts", body)
        }

    suspend fun createFundingIntent(
        amount: Long,
        destinationNetwork: String,
        destinationAddress: String,
    ): Map<String, Any> = withContext(Dispatchers.IO) {
        val body = JSONObject().apply {
            put("amount", amount)
            put("destination_network", destinationNetwork)
            put("destination_address", destinationAddress)
        }.toString().toRequestBody(jsonMediaType)
        post("/lots/funding", body)
    }

    // MARK: - Bid bonds + award transfers

    suspend fun transferBidBond(
        senderCommitment: String,
        recipientCommitment: String,
        amount: Long,
    ): Map<String, Any> = withContext(Dispatchers.IO) {
        val nonce = randomHex(32)
        val nullifier = sha256hex("$senderCommitment:bid_bond:$nonce")
        val data = JSONObject().apply {
            put("sender_commitment", senderCommitment)
            put("recipient_commitment", recipientCommitment)
            put("amount", amount)
            put("nullifier", nullifier)
            put("nonce", nonce)
            put("timestamp", System.currentTimeMillis() / 1000)
        }
        val txJson = JSONObject().apply {
            put("type", 4)
            put("signature", "AQ==")
            put("data", data)
        }.toString()
        val body = JSONObject().put("tx", txJson).toString().toRequestBody(jsonMediaType)
        post("/lots/bonds/transfer", body)
    }

    suspend fun settleAwardTransfer(
        senderCommitment: String,
        recipientCommitment: String,
        amount: Long,
    ): Map<String, Any> = withContext(Dispatchers.IO) {
        val nonce = randomHex(32)
        val nullifier = sha256hex("$senderCommitment:award:$nonce")
        val data = JSONObject().apply {
            put("sender_commitment", senderCommitment)
            put("recipient_commitment", recipientCommitment)
            put("amount", amount)
            put("nullifier", nullifier)
            put("nonce", nonce)
            put("timestamp", System.currentTimeMillis() / 1000)
        }
        val txJson = JSONObject().apply {
            put("type", 4)
            put("signature", "AQ==")
            put("data", data)
        }.toString()
        val body = JSONObject().put("tx", txJson).toString().toRequestBody(jsonMediaType)
        post("/lots/awards/transfer", body)
    }

    // MARK: - Redemption (delegates to custody)

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
        val txJson = JSONObject().apply {
            put("type", 14)
            put("signature", "AQ==")
            put("data", data)
        }.toString()
        val body = JSONObject().put("tx", txJson).toString().toRequestBody(jsonMediaType)
        post("/lots/redemptions", body)
    }

    // MARK: - Helpers

    private fun randomHex(byteCount: Int): String {
        val bytes = ByteArray(byteCount)
        rng.nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
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
