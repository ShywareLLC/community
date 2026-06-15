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

// MARK: - Contracts result types

@Serializable
data class ContractParty(
    val role: String,
    val commitment: String,
    @SerialName("allocation_bps") val allocationBps: Int = 0,
    val seniority: Int = 0,
)

@Serializable
data class ContractRecord(
    @SerialName("contract_id") val contractId: String,
    @SerialName("asset_id") val assetId: String? = null,
    @SerialName("contract_type") val contractType: String,
    val status: String,
)

@Serializable
data class ContractState(
    @SerialName("contract_id") val contractId: String,
    val status: String,
    @SerialName("execution_count") val executionCount: Long = 0,
)

data class ContractRegistrationResult(
    val contractId: String,
    val contractHash: String,
    val txJson: String,
)

data class ContractExecutionResult(
    val executionId: String,
    val nullifier: String,
    val txJson: String,
)

// MARK: - Manifest validation

fun assertContractsManifest(config: ShyConfig) {
    require(config.contractVersion == "shycontracts-v1") {
        "contract_version must be shycontracts-v1"
    }
    require(config.anonLayer.blackBoxRequired) {
        "anon_layer.black_box_required must be true"
    }
    val required = setOf("contract_register", "contract_activate", "contract_execute")
    for (flow in required) {
        require(flow in config.anonLayer.requiredFlows) { "Missing required flow: $flow" }
    }
    require(config.signing.required && config.signing.backend != "none") {
        "Signing must be required and enabled"
    }
    val block = config.contracts ?: config.financing
    requireNotNull(block) { "shyconfig must declare a contracts (or financing) block." }
    val transferLayer = block.transferLayer
    require(transferLayer == null || transferLayer == "shywire") {
        "shyconfig contracts.transfer_layer must be \"shywire\" when declared."
    }
}

// MARK: - Client

class ContractsClient private constructor(
    val manifest: ShyConfig,
) {
    private val http = OkHttpClient()
    private val json = Json { ignoreUnknownKeys = true }
    private val jsonMediaType = "application/json".toMediaType()
    private val rng = SecureRandom()

    companion object {
        fun from(manifest: ShyConfig): ContractsClient {
            assertContractsManifest(manifest)
            return ContractsClient(manifest)
        }
    }

    // MARK: - Read

    suspend fun getContract(contractId: String): ContractRecord = withContext(Dispatchers.IO) {
        get("/contracts/$contractId")
    }

    suspend fun getContractState(contractId: String): ContractState = withContext(Dispatchers.IO) {
        get("/contracts/$contractId/state")
    }

    // MARK: - Write

    suspend fun registerContract(
        assetId: String?,
        parties: List<ContractParty>,
        contractType: String = "general",
        termsRef: String? = null,
    ): ContractRegistrationResult = withContext(Dispatchers.IO) {
        val timestamp = System.currentTimeMillis() / 1000
        val normalizedParties = parties.mapIndexed { i, p ->
            JSONObject().apply {
                put("role", p.role.ifEmpty { "party_$i" })
                put("commitment", p.commitment)
                put("allocation_bps", p.allocationBps)
                put("seniority", p.seniority.takeIf { it >= 0 } ?: i)
            }
        }
        val contractHashInput = buildString {
            append(contractType)
            if (termsRef != null) append(":$termsRef")
        }
        val contractHash = sha256hex(contractHashInput)
        val contractId = sha256hex("$contractHash:$timestamp:${randomHex(16)}")

        val data = JSONObject().apply {
            put("contract_id", contractId)
            put("asset_id", assetId)
            put("contract_type", contractType)
            put("contract_hash", contractHash)
            put("parties", JSONArray(normalizedParties))
            if (termsRef != null) put("terms_ref", termsRef)
            put("expiry_timestamp", 0)
            put("timestamp", timestamp)
        }
        val txJson = buildTxJson(7, data)
        postTx("/contracts", txJson)

        ContractRegistrationResult(
            contractId = contractId,
            contractHash = contractHash,
            txJson = txJson,
        )
    }

    suspend fun activateContract(contractId: String): Map<String, Any> = withContext(Dispatchers.IO) {
        val data = JSONObject().apply {
            put("contract_id", contractId)
            put("evidence_hash", sha256hex("operator_attestation"))
            put("evidence_type", "operator_attestation")
            put("activated_at", System.currentTimeMillis() / 1000)
        }
        val txJson = buildTxJson(9, data)
        postTx("/contracts/activate", txJson)
    }

    suspend fun executeContract(
        contractId: String,
        partyCommitment: String,
        counterpartyCommitment: String?,
        sourceRef: String,
        amount: Long? = null,
    ): ContractExecutionResult = withContext(Dispatchers.IO) {
        val transferNonce = randomHex(32)
        val nullifier = sha256hex("$partyCommitment:$contractId:$sourceRef")
        val executionId = sha256hex(transferNonce)

        val data = JSONObject().apply {
            put("contract_id", contractId)
            put("asset_id", JSONObject.NULL)
            put("party_commitment", partyCommitment)
            put("counterparty_commitment", counterpartyCommitment ?: JSONObject.NULL)
            put("execution_type", "execution")
            put("source_ref", sourceRef)
            if (amount != null) put("amount", amount)
            put("nullifier", nullifier)
            put("transfer_nonce", transferNonce)
            put("timestamp", System.currentTimeMillis() / 1000)
        }
        val txJson = buildTxJson(8, data)
        postTx("/contracts/executions", txJson)

        ContractExecutionResult(
            executionId = executionId,
            nullifier = nullifier,
            txJson = txJson,
        )
    }

    suspend fun periodClose(scopingId: String, l1MerkleRoot: String, l2MerkleRoot: String): Map<String, Any> =
        withContext(Dispatchers.IO) {
            val body = JSONObject().apply {
                put("scopingId", scopingId)
                put("l1MerkleRoot", l1MerkleRoot)
                put("l2MerkleRoot", l2MerkleRoot)
            }.toString().toRequestBody(jsonMediaType)
            post("/contracts/period-close", body)
        }

    // MARK: - Helpers

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
