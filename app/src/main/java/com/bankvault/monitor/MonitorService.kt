package com.bankvault.monitor

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import com.bankvault.CrashReporter
import com.bankvault.R
import com.bankvault.data.Locker
import com.bankvault.data.Store
import com.bankvault.data.Unlocks
import com.bankvault.lock.LockActivity
import com.bankvault.ui.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/** Watches which app is opened (Usage access) and shows the lock screen over locked apps. */
class MonitorService : Service() {
    companion object {
        private const val CHANNEL = "bv_lock"
        private const val ID = 1
        fun start(ctx: Context) {
            try { ContextCompat.startForegroundService(ctx, Intent(ctx, MonitorService::class.java)) }
            catch (e: Exception) { CrashReporter.recordHandled(ctx, "start lock service", e) }
        }
        fun stop(ctx: Context) { runCatching { ctx.stopService(Intent(ctx, MonitorService::class.java)) } }
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var lastShown = ""
    private var lastShownAt = 0L

    private val screenOff = object : BroadcastReceiver() {
        override fun onReceive(c: Context, i: Intent) { runCatching { Locker.lockNow(applicationContext) } }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        try {
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(NotificationChannel(CHANNEL, "App lock", NotificationManager.IMPORTANCE_LOW).apply { setShowBadge(false) })
            val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
            val n = Notification.Builder(this, CHANNEL).setSmallIcon(R.drawable.ic_lock).setContentTitle("BANKVAULT")
                .setContentText("App lock is on").setOngoing(true).setContentIntent(open).build()
            val type = if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0
            ServiceCompat.startForeground(this, ID, n, type)
            ContextCompat.registerReceiver(this, screenOff, IntentFilter(Intent.ACTION_SCREEN_OFF), ContextCompat.RECEIVER_NOT_EXPORTED)
        } catch (e: Exception) {
            CrashReporter.recordHandled(this, "lock service start", e); stopSelf(); return
        }
        scope.launch { loop() }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int) = START_STICKY

    private suspend fun loop() {
        val usm = getSystemService(UsageStatsManager::class.java)
        var since = System.currentTimeMillis() - 3_000
        val ev = UsageEvents.Event()
        while (scope.isActive) {
            try {
                val now = System.currentTimeMillis()
                var fg: String? = null
                val events = usm.queryEvents(since, now)
                while (events.hasNextEvent()) {
                    events.getNextEvent(ev)
                    if (ev.eventType == UsageEvents.Event.ACTIVITY_RESUMED) fg = ev.packageName
                }
                since = now - 1
                val grace = Store.relock.graceMs
                val relocked = if (fg != null) Unlocks.onForeground(fg, packageName, now, grace) else Unlocks.tick(now, grace)
                Locker.relocked(applicationContext, relocked)
                if (fg != null && fg in Store.lockedApps() && !Unlocks.isUnlocked(fg)) showLock(fg, now)
            } catch (e: Exception) {
                CrashReporter.recordHandled(this, "lock loop", e)
                delay(2_000)
            }
            delay(300)
        }
    }

    private fun showLock(pkg: String, now: Long) {
        if (pkg == lastShown && now - lastShownAt < 1_500) return
        lastShown = pkg; lastShownAt = now
        startActivity(Intent(this, LockActivity::class.java).putExtra(LockActivity.EXTRA_PKG, pkg)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_NO_ANIMATION or Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS))
    }

    override fun onDestroy() {
        runCatching { unregisterReceiver(screenOff) }
        scope.cancel()
        super.onDestroy()
    }
}

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        try { Store.init(context); Locker.refresh(context) } catch (e: Exception) { CrashReporter.recordHandled(context, "boot", e) }
    }
}
