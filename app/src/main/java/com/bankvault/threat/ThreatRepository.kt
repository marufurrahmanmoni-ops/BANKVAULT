package com.bankvault.threat

import android.content.Context
import com.bankvault.BuildConfig
import com.bankvault.core.audit.AuditEvent
import com.bankvault.core.audit.AuditSink
import com.bankvault.core.audit.AuditType
import com.bankvault.core.threat.SignedFeedVerifier
import com.bankvault.core.threat.ThreatDatabase
import com.bankvault.core.threat.UrlAnalyzer
import com.bankvault.core.threat.UrlReport
import com.bankvault.core.threat.Verdict
import com.bankvault.data.DomainRuleDao
import com.bankvault.data.DomainRuleEntity
import com.bankvault.data.ScanDao
import com.bankvault.data.ScanEntity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import java.io.File

/**
 * Local threat intelligence:
 *  1. Bundled seed DB (assets/threatdb/seed.txt) – covered by the APK signature.
 *  2. Signed updates downloaded by [ThreatFeedWorker] – ECDSA-verified, version-monotonic,
 *     re-verified every time they are loaded from disk.
 * If an update has expired the last valid DB keeps working offline and the dashboard shows
 * "Degraded – threat database out of date".
 */
class ThreatRepository(
    private val context: Context,
    private val scans: ScanDao,
    private val rules: DomainRuleDao,
    private val audit: AuditSink,
    private val scope: CoroutineScope,
    private val now: () -> Long,
) {
    data class DbInfo(val version: Long, val entries: Int, val expiresAt: Long, val source: String) {
        fun stale(now: Long) = now >= expiresAt
    }

    private val updatedBody get() = File(context.filesDir, "threatdb/current.txt")
    private val updatedSig get() = File(context.filesDir, "threatdb/current.sig")

    val verifier: SignedFeedVerifier? = BuildConfig.FEED_PUBLIC_KEY_X509_B64.takeIf { it.isNotBlank() }?.let {
        runCatching { SignedFeedVerifier(mapOf(BuildConfig.FEED_PUBLIC_KEY_ID to SignedFeedVerifier.publicKeyFromBase64(it))) }.getOrNull()
    }

    @Volatile private var db: ThreatDatabase = ThreatDatabase.EMPTY
    private val _info = MutableStateFlow(DbInfo(0, 0, 0, "none"))
    val info: StateFlow<DbInfo> = _info

    @Volatile private var allow: Set<String> = emptySet()
    @Volatile private var block: Set<String> = emptySet()

    val analyzer = UrlAnalyzer(db = { db }, userAllow = { allow }, userBlock = { block })

    fun load() {
        val seed = runCatching { ThreatDatabase.parse(context.assets.open("threatdb/seed.txt").bufferedReader().readText()) }.getOrNull()
        val updated = runCatching {
            val body = updatedBody.readBytes(); val sig = updatedSig.readText()
            if (verifier?.signatureValid(body, sig, BuildConfig.FEED_PUBLIC_KEY_ID) == true) ThreatDatabase.parse(String(body)) else null
        }.getOrNull()
        val chosen = listOfNotNull(updated?.let { it to "signed feed" }, seed?.let { it to "bundled seed" }).maxByOrNull { it.first.version }
        if (chosen != null) {
            db = chosen.first
            _info.value = DbInfo(chosen.first.version, chosen.first.size, chosen.first.expiresAt, chosen.second)
        }
        scope.launch {
            rules.observe().collect { list ->
                allow = list.filter { it.action == "ALLOW" }.map { it.domain }.toSet()
                block = list.filter { it.action == "BLOCK" }.map { it.domain }.toSet()
            }
        }
    }

    /** Called by the worker with a downloaded update. Returns null on success or a rejection reason. */
    suspend fun acceptUpdate(body: ByteArray, sigB64: String): String? {
        val v = verifier ?: return "No feed public key configured in this build"
        return when (val r = v.verify(body, sigB64, BuildConfig.FEED_PUBLIC_KEY_ID, db.version, now())) {
            is SignedFeedVerifier.Result.Rejected -> {
                audit.record(AuditEvent(AuditType.TAMPER_DETECTED, now(), null, "Threat DB update rejected: ${r.reason}")); r.reason
            }
            is SignedFeedVerifier.Result.Accepted -> {
                updatedBody.parentFile?.mkdirs()
                // Write sig first, body last via temp+rename so a crash never leaves a mismatched pair loaded.
                updatedSig.writeText(sigB64)
                val tmp = File(updatedBody.parentFile, "current.tmp"); tmp.writeBytes(body); tmp.renameTo(updatedBody)
                db = r.db
                _info.value = DbInfo(r.db.version, r.db.size, r.db.expiresAt, "signed feed")
                audit.record(AuditEvent(AuditType.THREAT_DB_UPDATED, now(), null, "version=${r.db.version} entries=${r.db.size}"))
                null
            }
        }
    }

    suspend fun scan(input: String, source: String): UrlReport {
        val r = analyzer.analyze(input)
        r.sanitized?.let { scans.insert(ScanEntity(timestamp = now(), sanitizedUrl = it, verdict = r.verdict.name, categories = r.categories.joinToString())) }
        when (r.verdict) {
            Verdict.CONFIRMED_MALICIOUS -> audit.record(AuditEvent(AuditType.MALICIOUS_DOMAIN_BLOCKED, now(), null, "${r.host} (${r.categories.joinToString()}) via $source"))
            Verdict.SUSPICIOUS -> audit.record(AuditEvent(AuditType.THREAT_DETECTED, now(), null, "suspicious ${r.host} score=${r.score} via $source"))
            else -> Unit
        }
        return r
    }

    suspend fun addRule(domain: String, action: String, scope: String) =
        rules.put(DomainRuleEntity(domain.trim().lowercase().removePrefix("*."), action, scope, now()))
}
