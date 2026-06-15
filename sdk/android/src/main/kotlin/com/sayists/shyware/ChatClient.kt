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

// MARK: - Chat result types

@Serializable
data class Mailbox(
    @SerialName("mailbox_id") val mailboxId: String,
    val label: String,
    val address: String,
    val status: String = "open",
)

@Serializable
data class MailboxInbox(
    @SerialName("mailbox_id") val mailboxId: String,
    val dispatches: List<DispatchRecord> = emptyList(),
)

@Serializable
data class DispatchRecord(
    @SerialName("dispatch_id") val dispatchId: String,
    val subject: String,
    val status: String,
)

// MARK: - Manifest validation

fun assertChatManifest(config: ShyConfig) {
    require(config.contractVersion == "shychat-v1") {
        "contract_version must be shychat-v1"
    }
    requireNotNull(config.messaging) { "shyconfig must include a messaging block for shychat-v1." }
    require(config.anonLayer.blackBoxRequired) {
        "anon_layer.black_box_required must be true"
    }
}

// MARK: - Client

class ChatClient internal constructor(
    val manifest: ShyConfig,
) {
    private val http = OkHttpClient()
    private val json = Json { ignoreUnknownKeys = true }
    private val jsonMediaType = "application/json".toMediaType()

    companion object {
        fun from(manifest: ShyConfig): ChatClient {
            assertChatManifest(manifest)
            return ChatClient(manifest)
        }

        /** Build without asserting shychat-v1 contract version. Used by RestClient. */
        internal fun fromRaw(manifest: ShyConfig): ChatClient = ChatClient(manifest)
    }

    // MARK: - Mailbox

    suspend fun createMailbox(
        label: String,
        address: String,
        routeHint: String? = null,
    ): Mailbox = withContext(Dispatchers.IO) {
        val body = JSONObject().apply {
            put("label", label)
            put("address", address)
            if (routeHint != null) put("route_hint", routeHint)
        }.toString().toRequestBody(jsonMediaType)
        post<Mailbox>("/messages/mailboxes", body)
    }

    suspend fun getMailbox(mailboxId: String): Mailbox = withContext(Dispatchers.IO) {
        get("/messages/mailboxes/$mailboxId?include_content=true")
    }

    suspend fun getInbox(mailboxId: String): MailboxInbox = withContext(Dispatchers.IO) {
        get("/messages/mailboxes/$mailboxId/inbox")
    }

    // MARK: - Dispatch

    suspend fun queueDispatch(
        mailboxId: String,
        recipientAddress: String,
        subject: String,
        body: String,
        contentClass: String,
    ): Map<String, Any> = withContext(Dispatchers.IO) {
        val reqBody = JSONObject().apply {
            put("mailbox_id", mailboxId)
            put("recipient_address", recipientAddress)
            put("subject", subject)
            put("body", body)
            put("content_class", contentClass)
        }.toString().toRequestBody(jsonMediaType)
        postRaw("/messages/dispatches", reqBody)
    }

    suspend fun closeDispatch(dispatchId: String): Map<String, Any> = withContext(Dispatchers.IO) {
        val reqBody = JSONObject().toString().toRequestBody(jsonMediaType)
        postRaw("/messages/dispatches/$dispatchId/close", reqBody)
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

    private inline fun <reified T> post(path: String, body: okhttp3.RequestBody): T {
        val base = (manifest.api.submitBaseUrl ?: manifest.api.baseUrl).trimEnd('/')
        val req = Request.Builder().url("$base$path").post(body).build()
        http.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) throw ShywareException("HTTP ${resp.code}")
            return json.decodeFromString(resp.body!!.string())
        }
    }

    private fun postRaw(path: String, body: okhttp3.RequestBody): Map<String, Any> {
        val base = (manifest.api.submitBaseUrl ?: manifest.api.baseUrl).trimEnd('/')
        val req = Request.Builder().url("$base$path").post(body).build()
        http.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) throw ShywareException("HTTP ${resp.code}")
            return emptyMap()
        }
    }
}
