package com.bankvault.core.threat

enum class ThreatCategory { PHISHING, MALWARE, RANSOMWARE, BOTNET, COMMAND_AND_CONTROL, SPYWARE, SCAM, FRAUD_INVESTMENT, MALICIOUS_DOWNLOAD, TRACKER, ADVERTISING }

/** The four classifications from the specification. UNKNOWN is never treated as SAFE. */
enum class Verdict { SAFE, SUSPICIOUS, CONFIRMED_MALICIOUS, UNKNOWN }

enum class Severity { INFO, LOW, MEDIUM, HIGH, CRITICAL }

data class Finding(val code: String, val severity: Severity, val explanation: String)

data class UrlReport(
    val input: String,
    /** Normalised URL with query/fragment removed – the only form ever stored. */
    val sanitized: String?,
    val host: String?,
    val unicodeHost: String?,
    val registrableDomain: String?,
    val verdict: Verdict,
    val categories: Set<ThreatCategory>,
    val findings: List<Finding>,
    val score: Int,
)
