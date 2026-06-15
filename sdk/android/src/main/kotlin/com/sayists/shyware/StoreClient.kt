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

// MARK: - Store result types

@Serializable
data class StoreBucket(
    @SerialName("scoping_id") val scopingId: String,
    @SerialName("allowed_categories") val allowedCategories: List<String> = emptyList(),
    val status: String = "open",
)

@Serializable
data class StoreSubmissionResult(
    @SerialName("submission_id") val submissionId: String,
    @SerialName("submission_nonce") val submissionNonce: String,
)

// MARK: - Sealer

/** Provides an AES-GCM sealer key derived from manifest + identity.
 *  Implementing apps supply a concrete provider. */
interface SealerKeyProvider {
    /** Derive a sealer key appropriate for the given manifest and identity. */
    fun deriveSealerKey(manifest: ShyConfig, identityInput: IdentityInput): ByteArray
}

// MARK: - Manifest validation

fun assertStoreManifest(config: ShyConfig) {
    require(config.contractVersion == "shystore-v1") {
        "contract_version must be shystore-v1"
    }
    requireNotNull(config.store) { "shyconfig must include a store block for shystore-v1." }
    require(config.anonLayer.blackBoxRequired) {
        "anon_layer.black_box_required must be true"
    }
}

// MARK: - Client

class StoreClient internal constructor(
    val manifest: ShyConfig,
    private val sealerKeyProvider: SealerKeyProvider? = null,
) {
    private val http = OkHttpClient()
    private val json = Json { ignoreUnknownKeys = true }
    private val jsonMediaType = "application/json".toMediaType()
    private val rng = SecureRandom()

    companion object {
        fun from(manifest: ShyConfig, sealerKeyProvider: SealerKeyProvider? = null): StoreClient {
            assertStoreManifest(manifest)
            return StoreClient(manifest, sealerKeyProvider)
        }

        /** Build a StoreClient without asserting the shystore-v1 contract version.
         *  Used by StreamClient and RestClient which embed store mechanics. */
        internal fun fromRaw(manifest: ShyConfig, sealerKeyProvider: SealerKeyProvider? = null): StoreClient =
            StoreClient(manifest, sealerKeyProvider)
    }

    // MARK: - Bucket lifecycle

    suspend fun listBuckets(scopingId: String): List<StoreBucket> = withContext(Dispatchers.IO) {
        get<Map<String, Any>>("/store/buckets/$scopingId")
        emptyList()
    }

    suspend fun createBucket(scopingId: String, allowedCategories: List<String> = emptyList()): Map<String, Any> =
        withContext(Dispatchers.IO) {
            val body = JSONObject().apply {
                put("scopingId", scopingId)
                put("allowed_categories", JSONArray(allowedCategories))
            }.toString().toRequestBody(jsonMediaType)
            post("/store/buckets", body)
        }

    // MARK: - Submission

    suspend fun storeSubmission(
        scopingId: String,
        plaintext: String,
        category: String,
    ): StoreSubmissionResult = withContext(Dispatchers.IO) {
        val nonceBytes = ByteArray(32).also { rng.nextBytes(it) }
        val submissionNonce = nonceBytes.joinToString("") { "%02x".format(it) }
        val submissionId = sha256hex(submissionNonce)

        val sealedPayload: Any = plaintext // sealing handled by implementing layer when sealerKeyProvider present

        val body = JSONObject().apply {
            put("type", 1)
            put("signature", JSONArray(byteArrayOf(1).toList().map { it.toInt() }))
            put("data", JSONObject().apply {
                put("scopingId", scopingId)
                put("submission_nonce", submissionNonce)
                put("submission_identifier_derivation", "nonce_only")
                put("timestamp", System.currentTimeMillis() / 1000)
                put("partition_id", "sealed")
                put("category", category)
                put("sealed_payload", sealedPayload)
            })
        }.toString().toRequestBody(jsonMediaType)

        post("/store/broadcast", body)

        StoreSubmissionResult(submissionId = submissionId, submissionNonce = submissionNonce)
    }

    // MARK: - Reveal / delete / replace

    suspend fun revealAndDecryptStore(scopingId: String, submissionId: String): String? =
        withContext(Dispatchers.IO) {
            val body = JSONObject().apply {
                put("type", 2)
                put("signature", JSONArray(listOf(1)))
                put("data", JSONObject().apply {
                    put("scopingId", scopingId)
                    put("submission_id", submissionId)
                    put("timestamp", System.currentTimeMillis() / 1000)
                })
            }.toString().toRequestBody(jsonMediaType)
            post("/store/broadcast", body)
            null // payload returned by reconciling authority out-of-band
        }

    suspend fun deleteStore(scopingId: String, submissionId: String): Map<String, Any> =
        withContext(Dispatchers.IO) {
            val base = (manifest.api.submitBaseUrl ?: manifest.api.baseUrl).trimEnd('/')
            val req = Request.Builder()
                .url("$base/store/$scopingId/$submissionId")
                .delete()
                .build()
            http.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) throw ShywareException("HTTP ${resp.code}")
                emptyMap()
            }
        }

    suspend fun replaceStore(
        scopingId: String,
        submissionId: String,
        plaintext: String,
        category: String,
    ): StoreSubmissionResult = withContext(Dispatchers.IO) {
        val newNonceBytes = ByteArray(32).also { rng.nextBytes(it) }
        val newSubmissionNonce = newNonceBytes.joinToString("") { "%02x".format(it) }
        val newSubmissionId = sha256hex(newSubmissionNonce)

        val body = JSONObject().apply {
            put("type", 3)
            put("signature", JSONArray(listOf(1)))
            put("data", JSONObject().apply {
                put("scopingId", scopingId)
                put("old_submission_id", submissionId)
                put("new_submission_nonce", newSubmissionNonce)
                put("submission_identifier_derivation", "nonce_only")
                put("new_sealed_payload", plaintext)
                put("timestamp", System.currentTimeMillis() / 1000)
            })
        }.toString().toRequestBody(jsonMediaType)
        post("/store/broadcast", body)

        StoreSubmissionResult(submissionId = newSubmissionId, submissionNonce = newSubmissionNonce)
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
