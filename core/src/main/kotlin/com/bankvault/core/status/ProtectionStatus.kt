package com.bankvault.core.status

import com.bankvault.core.network.NetworkAccessState

enum class StatusTone { GOOD, NEUTRAL, WARNING, BAD }

/** Dashboard status values from the specification. */
enum class ProtectionStatus(val label: String, val tone: StatusTone, val verified: Boolean) {
    PROTECTED("Protected", StatusTone.GOOD, true),
    BLOCKED("Blocked", StatusTone.GOOD, true),
    HIDDEN("Hidden", StatusTone.GOOD, true),
    ALLOWED("Allowed", StatusTone.NEUTRAL, true),
    VISIBLE("Visible", StatusTone.NEUTRAL, true),
    PENDING("Pending", StatusTone.WARNING, false),
    DEGRADED("Degraded", StatusTone.WARNING, false),
    MANUAL_SETUP_REQUIRED("Manual Setup Required", StatusTone.WARNING, false),
    VERIFICATION_UNAVAILABLE("Verification Unavailable", StatusTone.WARNING, false),
    UNSUPPORTED("Unsupported", StatusTone.BAD, false),
    ;

    init {
        // Invariant: green is reserved for verified protection.
        check(tone != StatusTone.GOOD || verified)
    }

    companion object {
        fun fromNetwork(s: NetworkAccessState): ProtectionStatus = when (s) {
            NetworkAccessState.BLOCKED_ALL, NetworkAccessState.BLOCKED_WIFI, NetworkAccessState.BLOCKED_MOBILE_DATA -> BLOCKED
            NetworkAccessState.TEMPORARILY_ALLOWED -> ALLOWED
            NetworkAccessState.PROTECTION_PENDING -> PENDING
            NetworkAccessState.PROTECTION_INACTIVE -> DEGRADED
            NetworkAccessState.MANUAL_SETUP_REQUIRED -> MANUAL_SETUP_REQUIRED
            NetworkAccessState.VERIFICATION_UNAVAILABLE -> VERIFICATION_UNAVAILABLE
        }

        /** Overall = worst of components; never GOOD if anything required is unverified. */
        fun overall(parts: Collection<ProtectionStatus>): ProtectionStatus {
            if (parts.isEmpty()) return PENDING
            val order = listOf(UNSUPPORTED, DEGRADED, PENDING, MANUAL_SETUP_REQUIRED, VERIFICATION_UNAVAILABLE)
            order.firstOrNull { it in parts }?.let { return it }
            return PROTECTED
        }
    }
}
