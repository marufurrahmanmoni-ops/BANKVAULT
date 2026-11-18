package com.bankvault.monitor

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import com.bankvault.R
import com.bankvault.ui.MainActivity

/** Notifications never contain app names of protected apps on the lock screen (VISIBILITY_PRIVATE + public version). */
class Alerts(private val context: Context) {
    companion object {
        const val CH_STATUS = "bv_status"
        const val CH_ALERT = "bv_alert"
        const val ID_MONITOR = 1001
        const val ID_ALERT = 1002
    }

    private val nm = context.getSystemService(NotificationManager::class.java)

    fun ensureChannels() {
        nm.createNotificationChannel(NotificationChannel(CH_STATUS, context.getString(R.string.monitor_channel), NotificationManager.IMPORTANCE_LOW).apply {
            lockscreenVisibility = Notification.VISIBILITY_SECRET; setShowBadge(false)
        })
        nm.createNotificationChannel(NotificationChannel(CH_ALERT, context.getString(R.string.alert_channel), NotificationManager.IMPORTANCE_HIGH).apply {
            lockscreenVisibility = Notification.VISIBILITY_PRIVATE
        })
    }

    private fun openApp() = PendingIntent.getActivity(context, 0,
        Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK), PendingIntent.FLAG_IMMUTABLE)

    fun monitorNotification(text: String): Notification =
        Notification.Builder(context, CH_STATUS)
            .setSmallIcon(R.drawable.ic_lock)
            .setContentTitle("BANKVAULT")
            .setContentText(text)
            .setOngoing(true)
            .setContentIntent(openApp())
            .setVisibility(Notification.VISIBILITY_SECRET)
            .build()

    fun protectionLost(text: String) {
        val publicVersion = Notification.Builder(context, CH_ALERT).setSmallIcon(R.drawable.ic_lock)
            .setContentTitle("BANKVAULT security alert").build()
        nm.notify(ID_ALERT, Notification.Builder(context, CH_ALERT)
            .setSmallIcon(R.drawable.ic_lock)
            .setContentTitle("Protection degraded")
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setVisibility(Notification.VISIBILITY_PRIVATE)
            .setPublicVersion(publicVersion)
            .setContentIntent(openApp())
            .setAutoCancel(true)
            .build())
    }
}
