package com.bankvault.emergency

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.widget.RemoteViews
import android.widget.Toast
import com.bankvault.BankVaultApp
import com.bankvault.R
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

private val triggerScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

/** Runs the emergency sequence. Safe to call from anywhere; never touches calling or SIM. */
fun triggerEmergency(context: Context, source: String, onDone: (Boolean) -> Unit = {}) {
    val app = context.applicationContext as BankVaultApp
    triggerScope.launch {
        val r = app.graph.emergency().trigger(source)
        app.graph.network.verifyAll() // publish the real post-lock state to the dashboard
        onDone(r.fullySucceeded)
    }
}

/** Quick Settings tile. Works from the lock screen; no authentication needed to LOCK (only to unlock). */
class EmergencyTileService : TileService() {
    override fun onTileAdded() {
        (application as BankVaultApp).graph.settings.update { it.copy(tileAdded = true) }
    }
    override fun onTileRemoved() {
        (application as BankVaultApp).graph.settings.update { it.copy(tileAdded = false) }
    }
    override fun onStartListening() {
        qsTile?.apply { state = Tile.STATE_INACTIVE; label = getString(R.string.tile_label); updateTile() }
    }
    override fun onClick() {
        qsTile?.apply { state = Tile.STATE_ACTIVE; updateTile() }
        triggerEmergency(this, "quick_settings_tile") { ok ->
            qsTile?.apply { state = Tile.STATE_INACTIVE; subtitle = if (ok) "Locked" else "Locked (partial)"; updateTile() }
        }
    }
}

class EmergencyReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val pending = goAsync()
        triggerEmergency(context, "home_widget") { ok ->
            android.os.Handler(android.os.Looper.getMainLooper()).post {
                Toast.makeText(context, if (ok) "BANKVAULT: emergency lock applied" else "BANKVAULT: lock applied – some steps unavailable, open app for details", Toast.LENGTH_LONG).show()
            }
            pending.finish()
        }
    }
}

class EmergencyWidgetProvider : AppWidgetProvider() {
    override fun onUpdate(context: Context, manager: AppWidgetManager, ids: IntArray) {
        val pi = PendingIntent.getBroadcast(context, 0, Intent(context, EmergencyReceiver::class.java), PendingIntent.FLAG_IMMUTABLE)
        val views = RemoteViews(context.packageName, R.layout.widget_emergency).apply { setOnClickPendingIntent(R.id.widget_lock, pi) }
        manager.updateAppWidget(ComponentName(context, EmergencyWidgetProvider::class.java), views)
    }
}
