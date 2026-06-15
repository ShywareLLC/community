package com.sayists.shyware

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject

// MARK: - Manifest validation

fun assertBrowserManifest(config: ShyConfig) {
    require(config.contractVersion == "shybrowser-v1") {
        "contract_version must be shybrowser-v1"
    }
    val sealerMode = config.sealer?.mode
    require(sealerMode == "sealed_storage") {
        "shybrowser manifest must set sealer.mode=sealed_storage"
    }
}

// MARK: - Client

/**
 * BrowserClient mirrors shybrowser-v1: sealed local storage + optional sealed
 * identity-side submission for operator reconciliation.
 *
 * On Android, "local storage" is EncryptedSharedPreferences rather than
 * the browser's localStorage. storeSealedBrowserData seals the payload before
 * writing; submitList2IdentityAttribute seals the identity attribute before
 * posting to the API.
 *
 * deriveSealerKey is required when the sealer is active. The implementing app
 * provides a concrete lambda that returns a 32-byte AES-GCM key derived from
 * the current identity session.
 */
class BrowserClient private constructor(
    val manifest: ShyConfig,
    private val deriveSealerKey: (() -> ByteArray)? = null,
) {
    private val http = OkHttpClient()
    private val json = Json { ignoreUnknownKeys = true }
    private val jsonMediaType = "application/json".toMediaType()

    companion object {
        fun from(manifest: ShyConfig, deriveSealerKey: (() -> ByteArray)? = null): BrowserClient {
            assertBrowserManifest(manifest)
            return BrowserClient(manifest, deriveSealerKey)
        }
    }

    // MARK: - Local sealed storage

    /**
     * Seals `data` (JSON-encoded) and writes it to the provided store.
     * The implementor is responsible for persisting the record — on Android
     * use EncryptedSharedPreferences or DataStore.
     *
     * Returns the sealed payload bytes.
     */
    fun sealData(data: String): ByteArray {
        val key = requireSealerKey()
        return aesGcmEncrypt(data.toByteArray(Charsets.UTF_8), key)
    }

    fun unsealData(ciphertext: ByteArray): String {
        val key = requireSealerKey()
        return aesGcmDecrypt(ciphertext, key).toString(Charsets.UTF_8)
    }

    // MARK: - API: submit sealed browser data (List 1)

    suspend fun storeSealedBrowserData(data: String, category: String = "browser_session"): Map<String, Any> =
        withContext(Dispatchers.IO) {
            val sealed = sealData(data)
            val body = JSONObject().apply {
                put("category", category)
                put("list", 1)
                put("sealed_payload", java.util.Base64.getEncoder().encodeToString(sealed))
            }.toString().toRequestBody(jsonMediaType)
            post("/browser/submit", body)
        }

    // MARK: - API: submit List 2 identity attribute

    suspend fun submitList2IdentityAttribute(attribute: String, attributeType: String = "ip_address"): Map<String, Any> =
        withContext(Dispatchers.IO) {
            val sealed = sealData(attribute)
            val body = JSONObject().apply {
                put("category", attributeType)
                put("sealed_payload", java.util.Base64.getEncoder().encodeToString(sealed))
            }.toString().toRequestBody(jsonMediaType)
            post("/list2-identity", body)
        }

    // MARK: - Helpers

    private fun requireSealerKey(): ByteArray =
        checkNotNull(deriveSealerKey) {
            "deriveSealerKey is required when sealer is active."
        }.invoke()

    /**
     * AES-256-GCM encrypt. Returns IV (12 bytes) || ciphertext || tag.
     * The IV is randomly generated per call.
     */
    private fun aesGcmEncrypt(plaintext: ByteArray, key: ByteArray): ByteArray {
        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = javax.crypto.spec.SecretKeySpec(key, "AES")
        val iv = ByteArray(12).also { java.security.SecureRandom().nextBytes(it) }
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, keySpec, javax.crypto.spec.GCMParameterSpec(128, iv))
        val ciphertext = cipher.doFinal(plaintext)
        return iv + ciphertext
    }

    private fun aesGcmDecrypt(ivAndCiphertext: ByteArray, key: ByteArray): ByteArray {
        val iv = ivAndCiphertext.copyOf(12)
        val ciphertext = ivAndCiphertext.copyOfRange(12, ivAndCiphertext.size)
        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = javax.crypto.spec.SecretKeySpec(key, "AES")
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, keySpec, javax.crypto.spec.GCMParameterSpec(128, iv))
        return cipher.doFinal(ciphertext)
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
