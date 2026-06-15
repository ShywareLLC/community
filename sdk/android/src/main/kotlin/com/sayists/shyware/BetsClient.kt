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
import org.json.JSONArray
import org.json.JSONObject
import java.security.SecureRandom

// MARK: - Bets result types

@Serializable
data class BetsEvent(
    @SerialName("event_id") val eventId: String,
    val title: String,
    val outcomes: List<String>,
    val status: String,
    @SerialName("closes_at") val closesAt: Long,
)

@Serializable
data class BetsOrder(
    @SerialName("order_id") val orderId: String,
    @SerialName("event_id") val eventId: String,
    val side: String,
    val outcome: String,
    val stake: Long,
    val odds: Double,
    val status: String,
)

@Serializable
data class BetsSettlement(
    @SerialName("event_id") val eventId: String,
    @SerialName("winning_outcome") val winningOutcome: String,
    val status: String,
)

// MARK: - Manifest validation

fun assertBetsManifest(config: ShyConfig) {
    // shybets-v1 extends shywire — inherits wire validation
    require(config.anonLayer.blackBoxRequired) {
        "anon_layer.black_box_required must be true"
    }
    require(config.signing.required && config.signing.backend != "none") {
        "Signing must be required and enabled"
    }
}

// MARK: - Client

/**
 * BetsClient extends WireClient for prediction market / betting flows.
 * The wire transfer rail is used for stake transfers and payouts.
 */
class BetsClient private constructor(
    val manifest: ShyConfig,
    private val wireClient: WireClient,
    private val operatorMode: Boolean = false,
) {
    private val http = OkHttpClient()
    private val json = Json { ignoreUnknownKeys = true }
    private val jsonMediaType = "application/json".toMediaType()
    private val rng = SecureRandom()

    companion object {
        fun from(manifest: ShyConfig, operatorMode: Boolean = false): BetsClient {
            assertBetsManifest(manifest)
            val wire = WireClient.fromRaw(manifest, operatorMode)
            return BetsClient(manifest, wire, operatorMode)
        }
    }

    // MARK: - Account + Funding

    suspend fun registerSettlementAccount(walletAddress: String): Map<String, Any> =
        withContext(Dispatchers.IO) {
            val body = JSONObject().apply {
                put("wallet_address", walletAddress)
            }.toString().toRequestBody(jsonMediaType)
            post("/bets/accounts", body)
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
        post("/bets/funding", body)
    }

    // MARK: - Events

    suspend fun createEvent(
        marketId: String,
        title: String,
        outcomes: List<String>,
        closesAt: Long,
    ): BetsEvent = withContext(Dispatchers.IO) {
        val body = JSONObject().apply {
            put("market_id", marketId)
            put("title", title)
            put("outcomes", JSONArray(outcomes))
            put("closes_at", closesAt)
        }.toString().toRequestBody(jsonMediaType)
        postTyped("/bets/events", body)
    }

    suspend fun listEvents(status: String? = null, marketId: String? = null): List<BetsEvent> =
        withContext(Dispatchers.IO) {
            val params = buildList {
                if (status != null) add("status=$status")
                if (marketId != null) add("market_id=$marketId")
            }.joinToString("&")
            val path = if (params.isEmpty()) "/bets/events" else "/bets/events?$params"
            get<Map<String, Any>>(path)
            emptyList()
        }

    suspend fun getEvent(eventId: String): BetsEvent = withContext(Dispatchers.IO) {
        get("/bets/events/$eventId")
    }

    suspend fun settleEvent(eventId: String, winningOutcome: String): BetsSettlement =
        withContext(Dispatchers.IO) {
            requireOperatorMode("settleEvent")
            val body = JSONObject().apply {
                put("winning_outcome", winningOutcome)
            }.toString().toRequestBody(jsonMediaType)
            postTyped("/bets/events/$eventId/settle", body)
        }

    // MARK: - Orders

    suspend fun placeOrder(
        eventId: String,
        side: String,
        outcome: String,
        stake: Long,
        odds: Double,
        accountCommitment: String,
    ): BetsOrder = withContext(Dispatchers.IO) {
        val body = JSONObject().apply {
            put("event_id", eventId)
            put("side", side)
            put("outcome", outcome)
            put("stake", stake)
            put("odds", odds)
            put("account_commitment", accountCommitment)
        }.toString().toRequestBody(jsonMediaType)
        postTyped("/bets/orders", body)
    }

    suspend fun listOrders(eventId: String? = null): List<BetsOrder> = withContext(Dispatchers.IO) {
        val path = if (eventId != null) "/bets/orders?event_id=$eventId" else "/bets/orders"
        get<Map<String, Any>>(path)
        emptyList()
    }

    suspend fun listOrderBook(eventId: String): Map<String, Any> = withContext(Dispatchers.IO) {
        get("/bets/events/$eventId/orderbook")
    }

    suspend fun getSettlement(eventId: String): BetsSettlement = withContext(Dispatchers.IO) {
        get("/bets/events/$eventId/settlement")
    }

    // MARK: - Stake transfer (via wire rail)

    suspend fun transferStake(
        scopingId: String,
        senderCommitment: String,
        recipientCommitment: String,
        amount: Long,
    ) = withContext(Dispatchers.IO) {
        val submissionNonce = randomHex(32)
        val nullifier = sha256hex("$senderCommitment:$scopingId:$submissionNonce")
        val data = JSONObject().apply {
            put("asset_id", scopingId)
            put("sender_commitment", senderCommitment)
            put("recipient_commitment", recipientCommitment)
            put("amount", amount)
            put("nullifier", nullifier)
            put("submission_nonce", submissionNonce)
            put("sender_proof", "AQ==")
            put("timestamp", System.currentTimeMillis() / 1000)
        }
        val txJson = JSONObject().apply {
            put("type", 4)
            put("signature", "AQ==")
            put("data", data)
        }.toString()
        val body = JSONObject().put("tx", txJson).toString().toRequestBody(jsonMediaType)
        post("/bets/stake/transfer", body)
    }

    // MARK: - Payout

    suspend fun createPayoutIntent(
        amount: Long,
        accountCommitment: String,
        payoutRail: String,
        payoutDestination: String,
    ): Map<String, Any> = withContext(Dispatchers.IO) {
        val body = JSONObject().apply {
            put("amount", amount)
            put("account_commitment", accountCommitment)
            put("payout_rail", payoutRail)
            put("payout_destination", payoutDestination)
        }.toString().toRequestBody(jsonMediaType)
        post("/bets/payouts", body)
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

    private inline fun <reified T> postTyped(path: String, body: okhttp3.RequestBody): T {
        val base = (manifest.api.submitBaseUrl ?: manifest.api.baseUrl).trimEnd('/')
        val req = Request.Builder().url("$base$path").post(body).build()
        http.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) throw ShywareException("HTTP ${resp.code}")
            return json.decodeFromString(resp.body!!.string())
        }
    }
}
