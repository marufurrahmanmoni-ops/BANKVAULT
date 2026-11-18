package com.bankvault.net

import android.content.Context
import android.content.Intent
import android.net.VpnService
import com.bankvault.CrashReporter
import com.bankvault.data.Store
import com.bankvault.data.Unlocks
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * "Network access off" for locked apps, using a LOCAL VPN that only contains the locked apps and
 * drops their traffic. No server, nothing is read or sent anywhere, other apps are not affected.
 */
object NetBlock {
    sealed class Status {
        data object Off : Status()
        data object NeedsPermission : Status()
        data class Blocking(val apps: Int) : Status()
        data object NothingToBlock : Status()
        data class Problem(val message: String) : Status()
    }

    val status = MutableStateFlow<Status>(Status.Off)
    val statusFlow: StateFlow<Status> get() = status

    /** Apps that must have no network right now. */
    fun blockedNow(): Set<String> = if (Store.netBlock.value) Store.lockedApps() - Unlocks.unlocked.value else emptySet()

    /** Re-apply after any change (lock/unlock, setting changed). Never throws. */
    fun update(ctx: Context) {
        try {
            when {
                !Store.netBlock.value -> { stop(ctx); status.value = Status.Off }
                VpnService.prepare(ctx) != null -> { stop(ctx); status.value = Status.NeedsPermission }
                else -> ctx.startService(Intent(ctx, BlockVpnService::class.java))
            }
        } catch (e: Exception) {
            CrashReporter.recordHandled(ctx, "network block update", e)
            status.value = Status.Problem("Could not start: ${e.message ?: e.javaClass.simpleName}")
        }
    }

    private fun stop(ctx: Context) {
        runCatching { ctx.startService(Intent(ctx, BlockVpnService::class.java).setAction(BlockVpnService.ACTION_STOP)) }
    }
}
