package com.bankvault

import android.content.Context
import com.bankvault.apps.InstalledApps
import com.bankvault.compat.DeviceProfiler
import com.bankvault.core.audit.AuditEvent
import com.bankvault.core.audit.AuditType
import com.bankvault.core.auth.PinHasher
import com.bankvault.core.emergency.EmergencyLock
import com.bankvault.core.emergency.SensitiveStateWiper
import com.bankvault.core.util.SystemClock
import com.bankvault.data.AuditLogger
import com.bankvault.data.BankVaultDatabase
import com.bankvault.data.SettingsStore
import com.bankvault.managed.ManagedDeviceController
import com.bankvault.monitor.Alerts
import com.bankvault.network.NetworkCoordinator
import com.bankvault.network.OemManualBackend
import com.bankvault.root.RootFirewallBackend
import com.bankvault.security.Argon2idKdf
import com.bankvault.security.KeystoreManager
import com.bankvault.security.PinRepository
import com.bankvault.security.SecurePrefs
import com.bankvault.session.SessionCoordinator
import com.bankvault.stealth.StealthManager
import com.bankvault.tamper.TamperMonitor
import com.bankvault.threat.ThreatRepository
import com.bankvault.vpn.VpnBlackholeBackend
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow

/**
 * Manual dependency injection: one place that wires the modules together.
 * Every component takes its collaborators through its constructor, so each can be unit tested
 * (the platform-free logic lives in :core and is tested there).
 */
class AppGraph(val context: Context) {
    val clock = SystemClock
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    val db = BankVaultDatabase.create(context)
    val securePrefs = SecurePrefs(context)
    val settings = SettingsStore(securePrefs)
    val audit = AuditLogger(db.audit())
    val alerts = Alerts(context)
    val installed = InstalledApps(context)
    val pins = PinRepository(securePrefs, PinHasher(Argon2idKdf(), KeystoreManager.pepper), clock)
    val managed = ManagedDeviceController(context)
    val oem = OemManualBackend(context, securePrefs)
    val network = NetworkCoordinator(settings, db.apps(), installed, RootFirewallBackend(context), VpnBlackholeBackend(context), oem, audit) { clock.nowMillis() }
    val sessions = SessionCoordinator(clock, network, managed, audit) { settings.state.value.endOnScreenOff }
    val threats = ThreatRepository(context, db.scans(), db.domains(), audit, scope) { clock.nowMillis() }
    val tamper = TamperMonitor(context, settings, managed, audit, alerts)
    val profiler = DeviceProfiler(context, managed, tamper)
    val stealth = StealthManager(context)

    /** True while the BANKVAULT dashboard is unlocked (in-memory only; cleared by emergency/screen-off). */
    val dashboardUnlocked = MutableStateFlow(false)

    /**
     * When the owner taps a "Fix" button that opens Android Settings, the dashboard stays unlocked
     * for up to 2 minutes so they can come straight back. Screen-off still locks immediately.
     */
    @Volatile var returnGraceUntil = 0L
    fun expectReturn() { returnGraceUntil = clock.elapsedMillis() + RETURN_GRACE_MS }
    companion object { const val RETURN_GRACE_MS = 120_000L }

    init {
        managed.hideAsWell = { pkg -> db.apps().get(pkg)?.hideWhenLocked ?: true }
    }

    suspend fun protectedPackages(): Set<String> = db.apps().all().map { it.packageName }.toSet()

    suspend fun emergency(): EmergencyLock {
        val pkgs = protectedPackages()
        return EmergencyLock(clock, sessions.manager, network.engineForEmergency(), managed,
            object : SensitiveStateWiper {
                override suspend fun wipeTransientState() {
                    // BANKVAULT caches no credentials; transient state = sessions + unlocked flag + clipboard we may have set.
                    sessions.syncActive()
                    ClipboardGuard.clearIfOurs(context)
                }
                override suspend fun lockDashboard() { dashboardUnlocked.value = false }
            }, audit) { pkgs }
    }

    suspend fun recordRecovery(detail: String) =
        audit.record(AuditEvent(AuditType.RECOVERY, clock.nowMillis(), null, detail))
}

/** Clears the clipboard only if BANKVAULT itself put the current clip there (e.g. "copy sanitized URL"). */
object ClipboardGuard {
    @Volatile private var ourLabel: String? = null
    fun copy(context: Context, text: String) {
        val cm = context.getSystemService(android.content.ClipboardManager::class.java)
        val label = "bankvault-" + System.nanoTime()
        val clip = android.content.ClipData.newPlainText(label, text)
        cm.setPrimaryClip(clip); ourLabel = label
    }
    fun clearIfOurs(context: Context) {
        val cm = context.getSystemService(android.content.ClipboardManager::class.java)
        if (ourLabel != null && cm.primaryClipDescription?.label == ourLabel) runCatching { cm.clearPrimaryClip() }
        ourLabel = null
    }
}
