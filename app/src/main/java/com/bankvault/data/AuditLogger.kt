package com.bankvault.data

import com.bankvault.core.audit.AuditEvent
import com.bankvault.core.audit.AuditRedactor
import com.bankvault.core.audit.AuditSink
import com.bankvault.core.audit.AuditType
import com.bankvault.security.KeystoreManager
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

class AuditLogger(private val dao: AuditDao) : AuditSink {

    override suspend fun record(event: AuditEvent) {
        val clean = AuditRedactor.sanitize(event)
        dao.insert(AuditEntity(
            type = clean.type.name,
            timestamp = clean.timestamp,
            packageName = clean.packageName,
            detailEnc = KeystoreManager.encrypt(clean.detail.toByteArray()),
        ))
    }

    fun observe(): Flow<List<AuditEvent>> = dao.observe().map { list -> list.map(::decode) }

    suspend fun all(): List<AuditEvent> = dao.all().map(::decode)

    suspend fun clear(now: Long) {
        dao.clear()
        record(AuditEvent(AuditType.LOG_CLEARED, now, null, "History cleared by owner after authentication"))
    }

    /** Plain-text export for the owner. Contains only already-redacted details. */
    suspend fun exportReport(): String = buildString {
        appendLine("BANKVAULT security report")
        appendLine("Generated: ${java.time.Instant.now()}")
        appendLine("Contains no PINs, OTPs, passwords or banking data.")
        appendLine()
        for (e in all()) appendLine("${java.time.Instant.ofEpochMilli(e.timestamp)}\t${e.type}\t${e.packageName ?: "-"}\t${e.detail}")
    }

    private fun decode(e: AuditEntity) = AuditEvent(
        runCatching { AuditType.valueOf(e.type) }.getOrDefault(AuditType.SETTINGS_CHANGED),
        e.timestamp, e.packageName,
        runCatching { String(KeystoreManager.decrypt(e.detailEnc)) }.getOrDefault("[unreadable]"),
    )
}
