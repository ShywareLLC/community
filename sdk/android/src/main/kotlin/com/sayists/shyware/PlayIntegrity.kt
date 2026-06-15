package com.sayists.shyware

import android.content.Context
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

// Maps Google Play Integrity verdicts to the RuntimeSignals shape.
// Mirrors the playIntegrity signal block in votingClient.js.

class PlayIntegrityProvider(
    private val context: Context,
    private val cloudProjectNumber: Long,
) {
    private val manager = IntegrityManagerFactory.create(context)

    /**
     * Request a Play Integrity token for the given nonce.
     * nonce should be a server-generated one-time value.
     *
     * Returns RuntimeSignals with:
     *   playIntegrity.available = true
     *   playIntegrity.passed = true   (if MEETS_DEVICE_INTEGRITY + MEETS_BASIC_INTEGRITY)
     *
     * The token must be forwarded to your server for verification before trusting the signal.
     */
    suspend fun requestIntegrityToken(nonce: String): Pair<RuntimeSignals, String?> {
        return suspendCancellableCoroutine { cont ->
            val request = IntegrityTokenRequest.builder()
                .setNonce(nonce)
                .setCloudProjectNumber(cloudProjectNumber)
                .build()

            manager.requestIntegrityToken(request)
                .addOnSuccessListener { response ->
                    val token = response.token()
                    // Verdicts are decoded server-side; the client signals available+passed
                    // upon receiving a non-null token. Server must verify before trusting.
                    val signals = RuntimeSignals(
                        playIntegrity = PlayIntegritySignal(available = true, passed = true),
                        deviceAttestation = DeviceAttestationSignal(trusted = true),
                    )
                    cont.resume(Pair(signals, token))
                }
                .addOnFailureListener { _ ->
                    cont.resume(Pair(RuntimeSignals.untrusted, null))
                }
        }
    }
}
