package com.bankvault.stealth

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager

/**
 * Hides BANKVAULT's own launcher icon by disabling the `.Launcher` activity-alias.
 * Recovery paths that always stay available (docs/RECOVERY.md):
 *   1. Long-press the "Emergency Lock" Quick Settings tile -> opens BANKVAULT.
 *   2. Share any link to "Scan link with BANKVAULT" -> "Open BANKVAULT" button.
 *   3. Settings > Apps > BANKVAULT stays listed (we never hide from Settings).
 * Hiding is refused until the Quick Settings tile has been added, so the owner always has a way back.
 *
 * Hiding OTHER apps' icons is only possible with Device Owner (setApplicationHidden) or with the
 * phone's own "Hide apps" feature; see ManagedDeviceController and the Stealth screen.
 */
class StealthManager(private val context: Context) {
    private val alias = ComponentName(context, "com.bankvault.Launcher")

    fun isLauncherHidden(): Boolean =
        context.packageManager.getComponentEnabledSetting(alias) == PackageManager.COMPONENT_ENABLED_STATE_DISABLED

    fun setLauncherHidden(hidden: Boolean, tileAdded: Boolean): Boolean {
        if (hidden && !tileAdded) return false
        context.packageManager.setComponentEnabledSetting(alias,
            if (hidden) PackageManager.COMPONENT_ENABLED_STATE_DISABLED else PackageManager.COMPONENT_ENABLED_STATE_ENABLED,
            PackageManager.DONT_KILL_APP)
        return isLauncherHidden() == hidden
    }
}
