package com.bankvault.core.audit

enum class AuditType {
    AUTH_SUCCESS, AUTH_FAILURE, AUTH_LOCKOUT, APP_ACCESS_ATTEMPT, SESSION_STARTED, SESSION_ENDED,
    NETWORK_RESTRICTION_CHANGED, NETWORK_PROTECTION_FAILURE, THREAT_DETECTED, MALICIOUS_DOMAIN_BLOCKED,
    APP_VISIBILITY_CHANGED, PERMISSION_CHANGED, TAMPER_DETECTED, EMERGENCY_LOCK, RECOVERY, SETTINGS_CHANGED,
    THREAT_DB_UPDATED, LOG_CLEARED,
}

data class AuditEvent(
    val type: AuditType,
    val timestamp: Long,
    val packageName: String? = null,
    val detail: String = "",
)

/**
 * Last line of defence so the log never contains credentials or banking data, even if a caller
 * passes something it should not. Applied to every detail string before it is encrypted and stored.
 */
object AuditRedactor {
    private val URL_QUERY = Regex("""(https?://[^\s?#]+)[?#]\S*""")
    private val EMAIL = Regex("""[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}""")
    /** Any run of 4+ digits (OTP, PIN, account, card, phone, amount). Allowed separators inside. */
    private val DIGITS = Regex("""(?<![A-Za-z0-9])\d[\d\s-]{2,}\d(?![A-Za-z0-9])""")
    private val SECRET_KV = Regex("""(?i)\b(pin|otp|password|passcode|token|cvv|pass)\s*[:=]\s*\S+""")

    const val MAX_LEN = 300

    fun redact(s: String): String = s
        .replace(SECRET_KV) { "${it.groupValues[1]}=[redacted]" }
        .replace(URL_QUERY) { it.groupValues[1] + "?[redacted]" }
        .replace(EMAIL, "[email]")
        .replace(DIGITS) { m -> if (m.value.count(Char::isDigit) >= 4) "[number]" else m.value }
        .take(MAX_LEN)

    fun sanitize(e: AuditEvent): AuditEvent = e.copy(detail = redact(e.detail))
}

interface AuditSink {
    suspend fun record(event: AuditEvent)
}
