package com.bankvault.data

import android.content.Context
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Index
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.Upsert
import kotlinx.coroutines.flow.Flow

@Entity(tableName = "protected_apps")
data class ProtectedAppEntity(
    @PrimaryKey val packageName: String,
    val label: String,
    val blockWifi: Boolean = true,
    val blockMobile: Boolean = true,
    val sessionDurationMs: Long = 180_000,
    val backgroundGraceMs: Long = 45_000,
    /** AuthPolicy name; null = use global policy. */
    val authPolicy: String? = null,
    val hideWhenLocked: Boolean = true,
    val addedAt: Long,
)

/** Detail text is redacted (AuditRedactor) and then AES-GCM encrypted with the Keystore data key. */
@Entity(tableName = "audit_log", indices = [Index("timestamp"), Index("type")])
data class AuditEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val type: String,
    val timestamp: Long,
    val packageName: String?,
    val detailEnc: ByteArray,
)

/** Only the sanitized URL (no query, no fragment) is ever stored. */
@Entity(tableName = "scan_history", indices = [Index("timestamp")])
data class ScanEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val timestamp: Long,
    val sanitizedUrl: String,
    val verdict: String,
    val categories: String,
)

@Entity(tableName = "domain_rules")
data class DomainRuleEntity(
    @PrimaryKey val domain: String,
    /** ALLOW or BLOCK */
    val action: String,
    /** THREAT or PRIVACY */
    val scope: String,
    val addedAt: Long,
)

@Dao
interface ProtectedAppDao {
    @Query("SELECT * FROM protected_apps ORDER BY label") fun observe(): Flow<List<ProtectedAppEntity>>
    @Query("SELECT * FROM protected_apps") suspend fun all(): List<ProtectedAppEntity>
    @Query("SELECT * FROM protected_apps WHERE packageName = :pkg") suspend fun get(pkg: String): ProtectedAppEntity?
    @Upsert suspend fun upsert(e: ProtectedAppEntity)
    @Query("DELETE FROM protected_apps WHERE packageName = :pkg") suspend fun delete(pkg: String)
}

@Dao
interface AuditDao {
    @Insert suspend fun insert(e: AuditEntity)
    @Query("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT :limit") fun observe(limit: Int = 500): Flow<List<AuditEntity>>
    @Query("SELECT * FROM audit_log ORDER BY timestamp DESC") suspend fun all(): List<AuditEntity>
    @Query("DELETE FROM audit_log") suspend fun clear()
    @Query("DELETE FROM audit_log WHERE timestamp < :before") suspend fun prune(before: Long)
}

@Dao
interface ScanDao {
    @Insert suspend fun insert(e: ScanEntity)
    @Query("SELECT * FROM scan_history ORDER BY timestamp DESC LIMIT 200") fun observe(): Flow<List<ScanEntity>>
    @Query("DELETE FROM scan_history") suspend fun clear()
}

@Dao
interface DomainRuleDao {
    @Query("SELECT * FROM domain_rules") fun observe(): Flow<List<DomainRuleEntity>>
    @Query("SELECT * FROM domain_rules") suspend fun all(): List<DomainRuleEntity>
    @Insert(onConflict = OnConflictStrategy.REPLACE) suspend fun put(e: DomainRuleEntity)
    @Query("DELETE FROM domain_rules WHERE domain = :d") suspend fun delete(d: String)
}

@Database(
    entities = [ProtectedAppEntity::class, AuditEntity::class, ScanEntity::class, DomainRuleEntity::class],
    version = 1,
    exportSchema = true,
)
abstract class BankVaultDatabase : RoomDatabase() {
    abstract fun apps(): ProtectedAppDao
    abstract fun audit(): AuditDao
    abstract fun scans(): ScanDao
    abstract fun domains(): DomainRuleDao

    companion object {
        fun create(context: Context): BankVaultDatabase =
            Room.databaseBuilder(context, BankVaultDatabase::class.java, "bankvault.db")
                // Migrations are explicit; we never fall back to a destructive migration silently,
                // because that would silently drop the protected-app list (= unprotect apps).
                .build()
    }
}
