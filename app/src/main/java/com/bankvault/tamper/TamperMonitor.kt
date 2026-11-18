package com.bankvault.tamper

import android.app.AppOpsManager
import android.app.NotificationManager
import android.content.Context
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Process
import android.provider.Settings
import com.bankvault.core.audit.AuditEvent
import com.bankvault.core.audit.AuditSink
import com.bankvault.core.audit.AuditType
import com.bankvault.data.NetworkMode
import com.bankvault.data.SettingsStore
import com.bankvault.managed.ManagedDeviceController
import com.bankvault.monitor.Alerts
import com.bankvault.vpn.VpnController
import java.io.File
import java.security.MessageDigest

/**
 * Detects and REPORTS changes that weaken protection. It cannot prevent them: an ordinary app
 * cannot stop Force Stop, Safe Mode, uninstall or permission revocation (Device Owner can block
 * uninstall). Everything here uses public APIs only.
 */
class TamperMonitor(
    private val context: Context,
    private val settings: SettingsStore,
    private val managed: ManagedDeviceController,
    private val audit: AuditSink,
    private val alerts: Alerts,
) {
    enum class Severity { OK, INFO, WARNING, CRITICAL }
    data class Check(val id: String, val title: String, val severity: Severity, val detail: String)

    private var lastCritical = emptySet<String>()

    fun hasUsageAccess(): Boolean {
        val ops = context.getSystemService(AppOpsManager::class.java)
        return ops.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), context.packageName) == AppOpsManager.MODE_ALLOWED
    }

    fun canDrawOverlays() = Settings.canDrawOverlays(context)
    fun notificationsAllowed() = context.getSystemService(NotificationManager::class.java).areNotificationsEnabled()

    suspend fun run(): List<Check> {
        val out = mutableListOf<Check>()
        val mode = settings.state.value.networkMode
        out += if (hasUsageAccess()) Check("usage", "Usage access", Severity.OK, "Granted")
        else Check("usage", "Usage access", Severity.CRITICAL, "Revoked – BANKVAULT cannot detect protected app launches.")
        out += if (canDrawOverlays()) Check("overlay", "Display over other apps", Severity.OK, "Granted")
        else Check("overlay", "Display over other apps", Severity.WARNING, "Not granted – the lock screen may fail to appear in front of a banking app.")
        out += if (notificationsAllowed()) Check("notif", "Notifications", Severity.OK, "Allowed")
        else Check("notif", "Notifications", Severity.WARNING, "Blocked – you will not see protection alerts.")
        if (mode == NetworkMode.LOCAL_VPN) {
            val consent = VpnService.prepare(context) == null
            val st = VpnController.status.value
            out += when {
                !consent -> Check("vpn", "VPN permission", Severity.CRITICAL, "Revoked or taken by another VPN app – banking network isolation is OFF.")
                st is VpnController.Status.Revoked -> Check("vpn", "VPN", Severity.CRITICAL, "VPN was turned off by the system or another app.")
                st is VpnController.Status.Error -> Check("vpn", "VPN", Severity.CRITICAL, st.message)
                else -> Check("vpn", "VPN permission", Severity.OK, "Granted")
            }
        }
        if (mode == NetworkMode.NONE) out += Check("net", "Network isolation", Severity.WARNING, "No network isolation method selected.")
        val dev = Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
        out += Check("devopts", "Developer options", if (dev) Severity.INFO else Severity.OK, if (dev) "Enabled" else "Disabled")
        val adb = Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
        out += Check("adb", "USB debugging", if (adb) Severity.WARNING else Severity.OK,
            if (adb) "Enabled – anyone with a computer can bypass app-level protection (e.g. 'adb shell am force-stop')." else "Disabled")
        val rootHints = listOf("/system/xbin/su", "/system/bin/su", "/sbin/su", "/debug_ramdisk/su", "/data/adb/magisk").any { File(it).exists() }
        out += Check("root", "Root indicators", if (rootHints && mode != NetworkMode.ROOT_FIREWALL) Severity.INFO else Severity.OK,
            if (rootHints) "Root tools detected. Heuristic only." else "None found (heuristic only – absence is not proof).")
        out += Check("boot", "Bootloader state", Severity.INFO, "Not reliably detectable by apps without hardware key attestation – not verified.")
        out += if (managed.canRestrict) Check("owner", "Device/Profile Owner", Severity.OK, "Active – apps can be suspended; uninstall blocked: ${managed.isUninstallBlocked()}")
        else Check("owner", "Device/Profile Owner", Severity.INFO, "Not provisioned – banking apps cannot be suspended or hidden by BANKVAULT.")
        out += signatureCheck()
        out += Check("forcestop", "Force Stop / Safe Mode", Severity.INFO,
            "Cannot be prevented by any normal app. Device-Owner suspension and root rules stay in effect if BANKVAULT is stopped; the VPN restarts only if Always-on VPN is enabled; launch detection stops.")
        reportChanges(out)
        return out
    }

    private fun signatureCheck(): Check = try {
        val info = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        val certs = info.signingInfo?.apkContentsSigners ?: emptyArray()
        val fp = certs.firstOrNull()?.toByteArray()?.let { MessageDigest.getInstance("SHA-256").digest(it).joinToString(":") { b -> "%02X".format(b) } }
        Check("integrity", "App signature", Severity.OK, "SHA-256 ${fp?.take(23)}… (compare with docs/INSTALL.md for release builds)")
    } catch (e: Exception) { Check("integrity", "App signature", Severity.WARNING, "Could not read signature") }

    private suspend fun reportChanges(checks: List<Check>) {
        val critical = checks.filter { it.severity == Severity.CRITICAL }.map { it.id }.toSet()
        val newly = critical - lastCritical
        if (newly.isNotEmpty()) {
            val msg = checks.filter { it.id in newly }.joinToString("; ") { "${it.title}: ${it.detail}" }
            alerts.protectionLost(msg)
            audit.record(AuditEvent(AuditType.PERMISSION_CHANGED, System.currentTimeMillis(), null, msg))
        }
        lastCritical = critical
    }

    fun deviceModelLine() = "${Build.MANUFACTURER} ${Build.MODEL} · Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT}) · patch ${Build.VERSION.SECURITY_PATCH}"
}
