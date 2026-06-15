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

// MARK: - Result types

data class BallotResult(
    val ballotId: String,
    val ballotNonce: String,
    val identityHash: String,
    val txJson: String,
)

data class ReceiptVerification(
    val verified: Boolean,
    val ballotId: String,
    val matchedChoice: String?,
)

@Serializable
data class PollsResponse(val polls: List<Poll>)

@Serializable
data class VotesResponse(val votes: List<VoteRecord>)

// MARK: - Manifest validation

fun assertVotingManifest(config: ShyConfig) {
    require(config.contractVersion == "shyvoting-v1") {
        "contract_version must be shyvoting-v1"
    }
    require(config.anonLayer.blackBoxRequired) {
        "anon_layer.black_box_required must be true"
    }
    val required = setOf("poll_read", "ballot_build", "ballot_submit", "receipt_verify")
    for (flow in required) {
        require(flow in config.anonLayer.requiredFlows) { "Missing required flow: $flow" }
    }
    require(config.identity.provider != "none") { "A real identity provider is required" }
    require(config.signing.required && config.signing.backend != "none") {
        "Signing must be required and enabled"
    }
}

// MARK: - Client

class VotingClient private constructor(
    private val manifest: ShyConfig,
    private val receiptStore: EncryptedReceiptStore?,
    private val bearerToken: String? = null,
    private val devUid: String? = null,
) {
    private var signals: RuntimeSignals = RuntimeSignals.untrusted
    private val http = OkHttpClient.Builder()
        .addInterceptor { chain ->
            val req = chain.request().newBuilder().apply {
                when {
                    bearerToken != null -> header("Authorization", "Bearer $bearerToken")
                    devUid != null      -> header("x-dev-uid", devUid)
                }
            }.build()
            chain.proceed(req)
        }.build()
    private val json = Json { ignoreUnknownKeys = true }
    private val jsonMediaType = "application/json".toMediaType()

    companion object {
        fun from(
            manifest: ShyConfig,
            store: EncryptedReceiptStore? = null,
            bearerToken: String? = null,
            devUid: String? = null,
        ): VotingClient {
            assertVotingManifest(manifest)
            return VotingClient(manifest, store, bearerToken, devUid)
        }
    }

    // MARK: - Posture

    fun setRuntimeSignals(s: RuntimeSignals) { signals = s }
    fun effectivePosture(): PostureResult = resolveEffectivePosture(manifest, signals)

    // MARK: - Read

    suspend fun getAllPolls(): List<Poll> = withContext(Dispatchers.IO) {
        get<PollsResponse>("/api/vote/polls").polls
    }

    suspend fun getPoll(id: String): Poll = withContext(Dispatchers.IO) {
        get("/api/vote/polls/$id")
    }

    suspend fun getTally(id: String): Tally = withContext(Dispatchers.IO) {
        val base = manifest.api.baseUrl.trimEnd('/')
        val req = Request.Builder().url("$base/api/vote/polls/$id/count").get().build()
        http.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) throw ShywareException("HTTP ${resp.code}")
            val obj = JSONObject(resp.body!!.string())
            val ledger = obj.optJSONObject("ledger") ?: obj
            val countsObj = obj.optJSONObject("counts")
            val counts = mutableMapOf<String, Long>()
            if (countsObj != null) {
                val keys = countsObj.keys()
                while (keys.hasNext()) {
                    val key = keys.next()
                    counts[key] = countsObj.optLong(key)
                }
            }
            val totalVotes = obj.optLong("total_votes", ledger.optLong("l1Count", counts.values.sum()))
            Tally(
                pollId = obj.optString("poll_id", obj.optString("pollId", id)),
                counts = counts,
                totalVotes = totalVotes,
                confirmedCount = obj.optLong("confirmed_count", totalVotes),
                voteMerkleRoot = obj.optString("vote_merkle_root", ledger.optString("l1MerkleRoot", "")),
                voterMerkleRoot = obj.optString("voter_merkle_root", ledger.optString("l2MerkleRoot", "")),
                signature = obj.optString("signature", ""),
                publicKey = obj.optString("public_key", obj.optString("publicKey", "")),
            )
        }
    }

    suspend fun getVotes(id: String): List<VoteRecord> = withContext(Dispatchers.IO) {
        val base = manifest.api.baseUrl.trimEnd('/')
        val req = Request.Builder().url("$base/api/vote/reconcile/ballot?pollId=$id").get().build()
        http.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) throw ShywareException("HTTP ${resp.code}")
            val text = resp.body!!.string()
            val obj = JSONObject(text)
            val votes = obj.optJSONArray("votes")
            if (votes != null) return@withContext json.decodeFromString<VotesResponse>(text).votes
            val ballotId = obj.optString("ballotId", obj.optString("ballot_id", ""))
            if (ballotId.isBlank()) emptyList() else listOf(VoteRecord(ballotId, emptyList()))
        }
    }

    // MARK: - Build

    fun buildBallot(pollId: String, choice: String, input: IdentityInput): BallotResult {
        val nonce = randomHex(32)
        val ballotId = sha256hex(nonce)
        val commitment = createIdentityCommitment(manifest, input)
        val identityHash = sha256hex(commitment + pollId)

        val data = JSONObject().apply {
            put("poll_id", pollId)
            put("identity_hash", identityHash)
            put("choice", choice)
            put("ballot_nonce", nonce)
            put("timestamp", System.currentTimeMillis() / 1000)
        }
        val txJson = JSONObject().apply {
            put("type", 2)
            put("signature", "AQ==")
            put("data", data)
        }.toString()

        return BallotResult(
            ballotId = ballotId,
            ballotNonce = nonce,
            identityHash = identityHash,
            txJson = txJson,
        )
    }

    // MARK: - Submit

    suspend fun submitBallot(pollId: String, choice: String): String = withContext(Dispatchers.IO) {
        val body = JSONObject()
            .put("pollId", pollId)
            .put("direction", choice)
            .toString().toRequestBody(jsonMediaType)
        val base = (manifest.api.submitBaseUrl ?: manifest.api.baseUrl).trimEnd('/')
        val req = Request.Builder().url("$base/api/vote/cast").post(body).build()
        http.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) throw ShywareException("HTTP ${resp.code}")
            // Return server-assigned ballotId so callers use the canonical ID
            val respJson = JSONObject(resp.body?.string() ?: "{}")
            respJson.optString("ballotId", "")
        }
    }

    suspend fun flushQueuedBallots(pollId: String): Unit = withContext(Dispatchers.IO) {
        val body = JSONObject().toString().toRequestBody(jsonMediaType)
        val base = (manifest.api.submitBaseUrl ?: manifest.api.baseUrl).trimEnd('/')
        val req = Request.Builder().url("$base/polls/$pollId/flush").post(body).build()
        http.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) throw ShywareException("HTTP ${resp.code}")
        }
    }

    suspend fun castBallot(pollId: String, choice: String, input: IdentityInput): BallotResult {
        val local = buildBallot(pollId, choice, input)
        val serverBallotId = submitBallot(pollId, choice)
        val result = if (serverBallotId.isNotBlank()) local.copy(ballotId = serverBallotId) else local
        if (!effectivePosture().writeOnly) {
            receiptStore?.save(
                BallotReceipt(
                    pollId = pollId,
                    ballotId = result.ballotId,
                    ballotNonce = result.ballotNonce,
                    choice = choice,
                    identityHash = result.identityHash,
                )
            )
        }
        return result
    }

    // MARK: - Verify

    fun verifyReceipt(nonce: String, expectedChoice: String, votes: List<VoteRecord>): ReceiptVerification {
        val ballotId = sha256hex(nonce)
        val match = votes.firstOrNull { it.ballotId == ballotId && expectedChoice in it.choices }
        return ReceiptVerification(
            verified = match != null,
            ballotId = ballotId,
            matchedChoice = match?.choices?.firstOrNull(),
        )
    }

    fun loadReceipt(pollId: String): BallotReceipt? = receiptStore?.load(pollId)

    // MARK: - HTTP

    private inline fun <reified T> get(path: String): T {
        val base = manifest.api.baseUrl.trimEnd('/')
        val req = Request.Builder().url("$base$path").get().build()
        http.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) throw ShywareException("HTTP ${resp.code}")
            return json.decodeFromString(resp.body!!.string())
        }
    }
}

// MARK: - Utilities

private val random = SecureRandom()

private fun randomHex(byteCount: Int): String {
    val bytes = ByteArray(byteCount)
    random.nextBytes(bytes)
    return bytes.joinToString("") { "%02x".format(it) }
}

class ShywareException(message: String) : Exception(message)
