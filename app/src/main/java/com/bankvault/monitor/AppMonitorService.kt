package com.bankvault.monitor

import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import androidx.lifecycle.LifecycleService
import androidx.lifecycle.lifecycleScope
import com.bankvault.BankVaultApp
import com.bankvault.core.audit.AuditEvent
import com.bankvault.core.audit.AuditType
import com.bankvault.lock.LockActivity
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Best-effort launch detection + session timer.
 *
 * Detection uses UsageStatsManager ACTIVITY_RESUMED events (Usage access permission). This is
 * NOT a security boundary on its own: a protected app can be visible for a few hundred ms before
 * the lock screen appears, and nothing runs if the owner/attacker force-stops BANKVAULT. The real
 * boundaries are the network block (VPN/root) and package suspension (Device Owner).
 */
class AppMonitorService : LifecycleService() {

    companion object {
        private const val POLL_MS = 350L
        fun startIfPossible(ctx: Context) {
            runCatching { ctx.startForegroundService(Intent(ctx, AppMonitorService::class.java)) }
        }
    }

    private val graph get() = (application as BankVaultApp).graph
    private var protectedPkgs: Set<String> = emptySet()
    private var lastForeground: String? = null
    private var lastAttemptLog = 0L

    private val screenReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == Intent.ACTION_SCREEN_OFF) {
                graph.dashboardUnlocked.value = false
                lifecycleScope.launch { graph.sessions.screenOff() }
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        startForeground(Alerts.ID_MONITOR, graph.alerts.monitorNotification("Protection active"),
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        registerReceiver(screenReceiver, IntentFilter(Intent.ACTION_SCREEN_OFF), Context.RECEIVER_NOT_EXPORTED)

        lifecycleScope.launch { graph.db.apps().observe().collect { list ->
            protectedPkgs = list.map { it.packageName }.toSet()
            safe("apps changed") { graph.sessions.updateConfigs(list); graph.network.reconcileFromStore() }
        } }
        lifecycleScope.launch { pollForeground() }
        lifecycleScope.launch { while (isActive) { safe("session tick") { graph.sessions.tick() }; delay(1_000) } }
        lifecycleScope.launch { while (isActive) { safe("tamper check") { graph.tamper.run(); graph.network.verifyAll() }; delay(60_000) } }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        super.onStartCommand(intent, flags, startId)
        return START_STICKY
    }

    /** One failing iteration must never kill the protection service. */
    private suspend fun safe(where: String, block: suspend () -> Unit) {
        try { block() } catch (e: kotlinx.coroutines.CancellationException) { throw e } catch (e: Exception) {
            com.bankvault.CrashReporter.recordHandled(this, "monitor: $where", e)
        }
    }

    private suspend fun pollForeground() {
        val usm = getSystemService(UsageStatsManager::class.java)
        var since = System.currentTimeMillis() - 5_000
        val ev = UsageEvents.Event()
        while (lifecycleScope.isActive) {
            val now = System.currentTimeMillis()
            var resumed: String? = null
            runCatching {
                val events = usm.queryEvents(since, now)
                while (events.hasNextEvent()) {
                    events.getNextEvent(ev)
                    if (ev.eventType == UsageEvents.Event.ACTIVITY_RESUMED) resumed = ev.packageName
                }
            }
            since = now - 1 // overlap by 1 ms so no event is lost between windows
            val fg = resumed
            if (fg != null && fg != lastForeground) {
                lastForeground = fg
                safe("foreground change") {
                    graph.sessions.onForeground(fg)
                    if (fg in protectedPkgs && !graph.sessions.isUnlocked(fg)) onProtectedLaunch(fg)
                }
            }
            delay(POLL_MS)
        }
    }

    private suspend fun onProtectedLaunch(pkg: String) {
        val now = System.currentTimeMillis()
        if (now - lastAttemptLog > 5_000) {
            lastAttemptLog = now
            graph.audit.record(AuditEvent(AuditType.APP_ACCESS_ATTEMPT, now, pkg, "Protected app opened while locked; lock screen shown"))
        }
        startActivity(Intent(this, LockActivity::class.java)
            .putExtra(LockActivity.EXTRA_PACKAGE, pkg)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_NO_ANIMATION or Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS))
    }

    override fun onDestroy() {
        runCatching { unregisterReceiver(screenReceiver) }
        super.onDestroy()
    }
}

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val app = context.applicationContext as BankVaultApp
        val pending = goAsync()
        app.graph.scope.launch {
            try {
                val event = if (intent.action == Intent.ACTION_BOOT_COMPLETED) "Device rebooted" else "BANKVAULT updated"
                // Sessions are in memory only, so every app is locked after reboot/update.
                val pkgs = app.graph.protectedPackages()
                if (pkgs.isNotEmpty()) {
                    app.graph.network.reconcileFromStore()
                    app.graph.managed.restrict(pkgs)
                    app.graph.recordRecovery("$event: restrictions re-applied to ${pkgs.size} app(s)")
                }
                if (app.graph.pins.isSet()) AppMonitorService.startIfPossible(context)
            } finally { pending.finish() }
        }
    }
}
