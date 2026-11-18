package com.bankvault.hide

import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import com.bankvault.data.Store

class AdminReceiver : DeviceAdminReceiver()

/**
 * Hiding another app's icon is only allowed for a Device Owner app (Android rule).
 * Without it, BANKVAULT shows how to use the phone's own "Hide apps" feature instead.
 */
object Hider {
    private fun dpm(ctx: Context) = ctx.getSystemService(DevicePolicyManager::class.java)
    private fun admin(ctx: Context) = ComponentName(ctx, AdminReceiver::class.java)

    fun available(ctx: Context): Boolean = runCatching { dpm(ctx).isDeviceOwnerApp(ctx.packageName) }.getOrDefault(false)

    fun isHidden(ctx: Context, pkg: String) = available(ctx) && runCatching { dpm(ctx).isApplicationHidden(admin(ctx), pkg) }.getOrDefault(false)

    private fun setHidden(ctx: Context, pkg: String, hidden: Boolean) {
        if (available(ctx)) runCatching { dpm(ctx).setApplicationHidden(admin(ctx), pkg, hidden) }
    }

    /** Apply the owner's choice for one app given its lock state. */
    fun apply(ctx: Context, pkg: String, unlocked: Boolean) =
        setHidden(ctx, pkg, !unlocked && pkg in Store.hidden.value && pkg in Store.lockedApps())

    fun applyAll(ctx: Context) {
        if (!available(ctx)) return
        (Store.hidden.value + Store.lockedApps()).forEach { apply(ctx, it, com.bankvault.data.Unlocks.isUnlocked(it)) }
    }

    fun unhide(ctx: Context, pkg: String) = setHidden(ctx, pkg, false)

    const val ADB_COMMAND = "adb shell dpm set-device-owner com.bankvault/.hide.AdminReceiver"
}
