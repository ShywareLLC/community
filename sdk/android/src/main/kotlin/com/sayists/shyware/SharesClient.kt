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

// MARK: - Shares result types

@Serializable
data class SharesProposal(
    @SerialName("proposal_id") val proposalId: String,
    val question: String,
    val options: List<String>,
    val status: String,
)

@Serializable
data class SharesTally(
    @SerialName("proposal_id") val proposalId: String,
    val counts: Map<String, Long>,
    @SerialName("total_votes") val totalVotes: Long,
)

@Serializable
data class SharesAction(
    @SerialName("action_id") val actionId: String,
    val adapter: String,
    val status: String,
)

@Serializable
data class MembershipSnapshot(
    @SerialName("account_commitment") val accountCommitment: String,
    val weight: Long,
)

// MARK: - Manifest validation

fun assertSharesManifest(config: ShyConfig) {
    require(config.contractVersion == "shyshares-v1") {
        "contract_version must be shyshares-v1"
    }
    require(config.anonLayer.blackBoxRequired) {
        "anon_layer.black_box_required must be true"
    }
    require(config.signing.required && config.signing.backend != "none") {
        "Signing must be required and enabled"
    }
    requireNotNull(config.governance) { "shyconfig must declare governance settings." }
    requireNotNull(config.execution) { "shyconfig must declare execution settings." }
    val transferLayer = config.governance?.transferLayer
    require(transferLayer == null || transferLayer == "shywire") {
        "shyconfig governance.transfer_layer must be \"shywire\" when declared."
    }
    val required = setOf(
        "organization_read", "membership_snapshot_read", "proposal_create",
        "weighted_ballot_submit", "tally_read", "action_queue_read", "action_dispatch"
    )
    for (flow in required) {
        require(flow in config.anonLayer.requiredFlows) { "Missing required flow: $flow" }
    }
}

// MARK: - Client

class SharesClient private constructor(
    val manifest: ShyConfig,
) {
    private val http = OkHttpClient()
    private val json = Json { ignoreUnknownKeys = true }
    private val jsonMediaType = "application/json".toMediaType()

    companion object {
        fun from(manifest: ShyConfig): SharesClient {
            assertSharesManifest(manifest)
            return SharesClient(manifest)
        }
    }

    // MARK: - Read

    suspend fun getProposalTally(proposalId: String): SharesTally = withContext(Dispatchers.IO) {
        get("/tallies/$proposalId")
    }

    suspend fun getActionQueue(): List<SharesAction> = withContext(Dispatchers.IO) {
        get<Map<String, Any>>("/actions")
        emptyList() // server returns list under "actions" key
    }

    suspend fun getMembershipSnapshot(): List<MembershipSnapshot> = withContext(Dispatchers.IO) {
        get<Map<String, Any>>("/memberships")
        emptyList()
    }

    // MARK: - Write

    suspend fun createProposal(
        proposalClass: String,
        question: String,
        options: List<String>,
        startTime: Long,
        endTime: Long,
    ): Map<String, Any> = withContext(Dispatchers.IO) {
        val body = JSONObject().apply {
            put("proposal_class", proposalClass)
            put("question", question)
            put("options", JSONArray(options))
            put("start_time", startTime)
            put("end_time", endTime)
            put("submitted_at", System.currentTimeMillis() / 1000)
        }.toString().toRequestBody(jsonMediaType)
        post("/proposals", body)
    }

    suspend fun submitWeightedBallot(
        proposalId: String,
        choice: String,
        accountCommitment: String,
    ): Map<String, Any> = withContext(Dispatchers.IO) {
        val body = JSONObject().apply {
            put("proposal_id", proposalId)
            put("choice", choice)
            put("account_commitment", accountCommitment)
            put("submitted_at", System.currentTimeMillis() / 1000)
        }.toString().toRequestBody(jsonMediaType)
        post("/ballots", body)
    }

    suspend fun dispatchAction(
        actionId: String,
        adapter: String,
        adapterPayload: Map<String, Any>,
    ): Map<String, Any> = withContext(Dispatchers.IO) {
        val bodyObj = JSONObject().apply {
            put("adapter", adapter)
            for ((k, v) in adapterPayload) put(k, v)
        }.toString().toRequestBody(jsonMediaType)
        post("/actions/$actionId/dispatch", bodyObj)
    }

    // MARK: - Helpers

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
