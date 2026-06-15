package com.sayists.shyware

import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger

// Mirrors CoverTrafficInterface (sdk/web/adapters/ledger/coverTraffic.js).
// Real submissions absorb the next scheduled dummy slot so the aggregate
// transport-layer request rate stays governed by the configured cover-traffic
// schedule (Claim 9).

private const val DUMMY_PREFIX = "__cover__"

data class CoverTrafficResult(val isDummy: Boolean, val canonicalWrite: Boolean)

class CoverTrafficAdapter(val ratePerMinute: Int = 10) {

    private val pendingRealCount = AtomicInteger(0)
    var dummiesFired = 0
        private set
    var dummiesAbsorbed = 0
        private set

    companion object {
        fun isDummy(submissionId: String): Boolean = submissionId.startsWith(DUMMY_PREFIX)

        fun wrapSubmit(submissionId: String, canonicalCounter: AtomicInteger): CoverTrafficResult {
            if (submissionId.startsWith(DUMMY_PREFIX)) {
                return CoverTrafficResult(isDummy = true, canonicalWrite = false)
            }
            canonicalCounter.incrementAndGet()
            return CoverTrafficResult(isDummy = false, canonicalWrite = true)
        }
    }

    fun makeDummySubmissionId(): String =
        DUMMY_PREFIX + UUID.randomUUID().toString().replace("-", "").lowercase()

    // Call when a real submission is dispatched. Absorbs next dummy slot.
    fun onRealSubmission() { pendingRealCount.incrementAndGet() }

    // Models one timer tick. Returns true if dummy fired, false if absorbed.
    fun tick(): Boolean {
        if (pendingRealCount.get() > 0) {
            pendingRealCount.decrementAndGet()
            dummiesAbsorbed++
            return false
        }
        dummiesFired++
        return true
    }
}
