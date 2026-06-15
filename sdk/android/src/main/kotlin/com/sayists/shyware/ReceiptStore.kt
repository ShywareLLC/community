package com.sayists.shyware

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable
data class BallotReceipt(
    val pollId: String,
    val ballotId: String,
    val ballotNonce: String,
    val choice: String,
    val identityHash: String,
    val submittedAtMs: Long = System.currentTimeMillis(),
)

/**
 * Stores ballot receipts in AES-256-GCM EncryptedSharedPreferences backed by
 * the Android Keystore. Keys are hardware-backed on supported devices.
 */
class EncryptedReceiptStore(context: Context, appId: String) {
    private val prefs = EncryptedSharedPreferences.create(
        context,
        "shyware_receipts_$appId",
        MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    fun save(receipt: BallotReceipt) {
        prefs.edit()
            .putString(receipt.pollId, Json.encodeToString(receipt))
            .apply()
    }

    fun load(pollId: String): BallotReceipt? {
        val json = prefs.getString(pollId, null) ?: return null
        return try { Json.decodeFromString(json) } catch (_: Exception) { null }
    }

    fun delete(pollId: String) {
        prefs.edit().remove(pollId).apply()
    }
}
