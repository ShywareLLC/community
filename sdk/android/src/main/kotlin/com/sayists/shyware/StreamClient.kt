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
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

// MARK: - Stream result types

@Serializable
data class StreamBucket(
    @SerialName("bucket_id") val bucketId: String,
    @SerialName("scoping_id") val scopingId: String,
    @SerialName("allowed_categories") val allowedCategories: List<String> = emptyList(),
)

@Serializable
data class StreamSegmentResult(
    @SerialName("segment_id") val segmentId: String,
    val sequence: Long,
)

/**
 * A live-segment queue that accumulates segments and flushes them in batches.
 * Create via [StreamClient.createLiveQueue].
 */
class LiveSegmentQueue(
    private val bucketId: String,
    private val streamId: String,
    private val minBatchSize: Int,
    private val flushIntervalMs: Long,
    private val flushFn: suspend (List<ByteArray>, LongRange) -> Unit,
    private val scope: CoroutineScope,
) {
    private val pending = mutableListOf<ByteArray>()
    private val sequenceBase = AtomicLong(0L)
    private var flushJob: Job? = null

    fun start() {
        flushJob = scope.launch(Dispatchers.IO) {
            while (true) {
                delay(flushIntervalMs)
                drainAndFlush()
            }
        }
    }

    fun stop() {
        flushJob?.cancel()
    }

    /** Enqueue a segment. Flushes immediately when minBatchSize is reached. */
    suspend fun enqueue(segment: ByteArray) {
        synchronized(pending) { pending.add(segment) }
        if (pending.size >= minBatchSize) drainAndFlush()
    }

    private suspend fun drainAndFlush() {
        val batch: List<ByteArray>
        val base: Long
        synchronized(pending) {
            if (pending.isEmpty()) return
            batch = pending.toList()
            pending.clear()
            base = sequenceBase.getAndAdd(batch.size.toLong())
        }
        flushFn(batch, base until base + batch.size)
    }
}

// MARK: - Manifest validation

fun assertStreamManifest(config: ShyConfig) {
    require(config.anonLayer.blackBoxRequired) {
        "anon_layer.black_box_required must be true"
    }
    requireNotNull(config.stream) { "shyconfig must include a stream block." }
}

// MARK: - Client

/**
 * StreamClient extends the store protocol for live segment streams.
 * It internally composes with StoreClient for the two-list write mechanics.
 */
class StreamClient private constructor(
    val manifest: ShyConfig,
    val storeClient: StoreClient,
) {
    private val http = OkHttpClient()
    private val json = Json { ignoreUnknownKeys = true }
    private val jsonMediaType = "application/json".toMediaType()
    private val rng = SecureRandom()

    companion object {
        /**
         * Create a StreamClient from a manifest.
         * The manifest does not need to be shystore-v1 — stream uses the store
         * two-list mechanics without requiring the top-level store contract version.
         */
        fun from(manifest: ShyConfig, sealerKeyProvider: SealerKeyProvider? = null): StreamClient {
            assertStreamManifest(manifest)
            val store = StoreClient.fromRaw(manifest, sealerKeyProvider)
            return StreamClient(manifest, store)
        }
    }

    // MARK: - Bucket

    suspend fun createBucket(scopingId: String, allowedCategories: List<String> = emptyList()): StreamBucket =
        withContext(Dispatchers.IO) {
            val body = JSONObject().apply {
                put("scopingId", scopingId)
                put("allowed_categories", JSONArray(allowedCategories))
            }.toString().toRequestBody(jsonMediaType)
            post("/stream/buckets", body)
        }

    // MARK: - Segments

    suspend fun sealLiveSegment(
        bucketId: String,
        streamId: String,
        sequence: Long,
        segment: ByteArray,
    ): StreamSegmentResult = withContext(Dispatchers.IO) {
        val segmentNonce = ByteArray(32).also { rng.nextBytes(it) }
        val nonceHex = segmentNonce.joinToString("") { "%02x".format(it) }
        val segmentId = sha256hex(nonceHex)
        val encoded = java.util.Base64.getEncoder().encodeToString(segment)

        val body = JSONObject().apply {
            put("bucket_id", bucketId)
            put("stream_id", streamId)
            put("sequence", sequence)
            put("segment_nonce", nonceHex)
            put("segment_id", segmentId)
            put("sealed_segment", encoded)
            put("timestamp", System.currentTimeMillis() / 1000)
        }.toString().toRequestBody(jsonMediaType)

        post<Unit>("/stream/segments", body)
        StreamSegmentResult(segmentId = segmentId, sequence = sequence)
    }

    // MARK: - Live queue

    fun createLiveQueue(
        bucketId: String,
        streamId: String,
        minBatchSize: Int,
        flushIntervalMs: Long,
        scope: CoroutineScope,
    ): LiveSegmentQueue = LiveSegmentQueue(
        bucketId = bucketId,
        streamId = streamId,
        minBatchSize = minBatchSize,
        flushIntervalMs = flushIntervalMs,
        scope = scope,
        flushFn = { segments, sequences ->
            segments.forEachIndexed { i, seg ->
                sealLiveSegment(bucketId, streamId, sequences.first + i, seg)
            }
        },
    )

    // MARK: - Helpers

    private inline fun <reified T> post(path: String, body: okhttp3.RequestBody): T {
        val base = (manifest.api.submitBaseUrl ?: manifest.api.baseUrl).trimEnd('/')
        val req = Request.Builder().url("$base$path").post(body).build()
        http.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) throw ShywareException("HTTP ${resp.code}")
            return json.decodeFromString(resp.body!!.string())
        }
    }
}
