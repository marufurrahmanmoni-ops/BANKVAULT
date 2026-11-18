package com.bankvault.managed

import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.UserManager
import com.bankvault.core.emergency.AppAccessController

class BankVaultAdminReceiver : DeviceAdminReceiver() {
    override fun onEnabled(context: Context, intent: Intent) {
        // When BANKVAULT becomes Device Owner we immediately protect ourselves from uninstall.
        ManagedDeviceController(context).onBecameAdmin()
    }

    companion object {
        fun component(ctx: Context) = ComponentName(ctx, BankVaultAdminReceiver::class.java)
    }
}

/**
 * Mode B – only does anything when BANKVAULT is Device Owner or Profile Owner.
 *
 *  - setPackagesSuspended(): the protected app cannot start at all while locked; launcher shows
 *    it greyed out, its notifications are hidden and it cannot run background work. This is the
 *    strongest app-access boundary available to a non-system app.
 *  - setApplicationHidden(): removes the app from the launcher (Stealth). Owner/PO only.
 *  - setUninstallBlocked(): BANKVAULT cannot be uninstalled without first removing it as owner.
 *
 * None of these provide a per-app network firewall; network isolation still uses VPN or root.
 */
class ManagedDeviceController(private val context: Context) : AppAccessController {
    private val dpm = context.getSystemService(DevicePolicyManager::class.java)
    private val admin = BankVaultAdminReceiver.component(context)

    val isDeviceOwner get() = dpm.isDeviceOwnerApp(context.packageName)
    val isProfileOwner get() = dpm.isProfileOwnerApp(context.packageName)
    override val canRestrict: Boolean get() = isDeviceOwner || isProfileOwner

    var hideAsWell: suspend (String) -> Boolean = { true }

    override suspend fun restrict(packages: Set<String>): Set<String> {
        if (!canRestrict || packages.isEmpty()) return emptySet()
        val failed = dpm.setPackagesSuspended(admin, packages.toTypedArray(), true).toSet()
        val ok = packages - failed
        ok.filter { hideAsWell(it) }.forEach { runCatching { dpm.setApplicationHidden(admin, it, true) } }
        return ok.filter { isSuspended(it) }.toSet()
    }

    override suspend fun release(packages: Set<String>): Set<String> {
        if (!canRestrict || packages.isEmpty()) return emptySet()
        packages.forEach { runCatching { dpm.setApplicationHidden(admin, it, false) } }
        val failed = dpm.setPackagesSuspended(admin, packages.toTypedArray(), false).toSet()
        return (packages - failed).filter { !isSuspended(it) }.toSet()
    }

    fun isSuspended(pkg: String): Boolean = runCatching { dpm.isPackageSuspended(admin, pkg) }.getOrDefault(false)
    fun isHidden(pkg: String): Boolean = runCatching { dpm.isApplicationHidden(admin, pkg) }.getOrDefault(false)

    fun onBecameAdmin() {
        if (!canRestrict) return
        runCatching { dpm.setUninstallBlocked(admin, context.packageName, true) }
    }

    fun isUninstallBlocked(): Boolean = canRestrict && runCatching { dpm.isUninstallBlocked(admin, context.packageName) }.getOrDefault(false)

    /** Recovery: release every app and drop owner status so the phone returns to normal. */
    fun relinquish(packages: Set<String>) {
        if (!canRestrict) return
        packages.forEach {
            runCatching { dpm.setApplicationHidden(admin, it, false) }
        }
        runCatching { dpm.setPackagesSuspended(admin, packages.toTypedArray(), false) }
        runCatching { dpm.setUninstallBlocked(admin, context.packageName, false) }
        runCatching { dpm.clearUserRestriction(admin, UserManager.DISALLOW_UNINSTALL_APPS) }
        if (isDeviceOwner) runCatching { @Suppress("DEPRECATION") dpm.clearDeviceOwnerApp(context.packageName) }
        else if (isProfileOwner) runCatching { @Suppress("DEPRECATION") dpm.clearProfileOwner(admin) }
    }
}
