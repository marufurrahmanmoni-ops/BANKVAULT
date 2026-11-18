package com.bankvault.data

import android.content.Context
import com.bankvault.hide.Hider
import com.bankvault.monitor.MonitorService
import com.bankvault.net.NetBlock

/** One place that applies every effect of locking/unlocking, so all features stay in sync. */
object Locker {
    fun unlocked(ctx: Context, pkg: String) {
        Unlocks.unlock(pkg)
        Hider.apply(ctx, pkg, unlocked = true)
        NetBlock.update(ctx)
    }

    fun relocked(ctx: Context, pkgs: Set<String>) {
        if (pkgs.isEmpty()) return
        pkgs.forEach { Hider.apply(ctx, it, unlocked = false) }
        NetBlock.update(ctx)
    }

    fun lockNow(ctx: Context) = relocked(ctx, Unlocks.lockAll())

    /** After any settings change. */
    fun refresh(ctx: Context) {
        Hider.applyAll(ctx)
        NetBlock.update(ctx)
        if (Store.pinSet() && Store.lockedApps().isNotEmpty()) MonitorService.start(ctx) else MonitorService.stop(ctx)
    }
}
