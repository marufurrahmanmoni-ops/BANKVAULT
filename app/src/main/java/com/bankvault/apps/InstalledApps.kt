package com.bankvault.apps

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable

data class LaunchableApp(val packageName: String, val label: String, val uid: Int, val icon: Drawable?, val suggested: Boolean)

/**
 * Lists apps that have a launcher entry. Uses the <queries> MAIN/LAUNCHER declaration, so no
 * QUERY_ALL_PACKAGES permission is needed – banking apps always have a launcher entry.
 * If an app is not visible (e.g. hidden by the OEM "Hide apps" feature) the owner can add it by
 * package name, see [resolveManually].
 */
class InstalledApps(private val context: Context) {

    companion object {
        /**
         * Package names of common Bangladeshi financial apps, used ONLY to pre-tick suggestions
         * among apps that are actually installed. Verify against the Play Store listing; wrong
         * entries simply never match.
         */
        val FINANCIAL_HINTS = setOf(
            "com.bKash.customerapp",      // bKash
            "com.konasl.nagad",           // Nagad
            "com.dbbl.mbs.apps.main",     // Rocket (DBBL)
        )
        private val KEYWORDS = listOf("bank", "pay", "wallet", "bkash", "nagad", "rocket", "upay", "finance", "money", "crypto", "trade", "invest")
    }

    fun launchable(): List<LaunchableApp> {
        val pm = context.packageManager
        val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        return pm.queryIntentActivities(intent, PackageManager.ResolveInfoFlags.of(0))
            .asSequence()
            .map { it.activityInfo.applicationInfo }
            .distinctBy { it.packageName }
            .filter { it.packageName != context.packageName }
            .map { ai ->
                val label = pm.getApplicationLabel(ai).toString()
                LaunchableApp(ai.packageName, label, ai.uid, runCatching { pm.getApplicationIcon(ai) }.getOrNull(),
                    suggested = ai.packageName in FINANCIAL_HINTS || KEYWORDS.any { k -> label.lowercase().contains(k) || ai.packageName.lowercase().contains(k) })
            }
            .sortedWith(compareByDescending<LaunchableApp> { it.suggested }.thenBy { it.label.lowercase() })
            .toList()
    }

    /** Manual entry: works only if the package is visible to us; otherwise returns null and the UI explains why. */
    fun resolveManually(packageName: String): LaunchableApp? = try {
        val ai = context.packageManager.getApplicationInfo(packageName.trim(), PackageManager.ApplicationInfoFlags.of(0))
        LaunchableApp(ai.packageName, context.packageManager.getApplicationLabel(ai).toString(), ai.uid, null, false)
    } catch (_: PackageManager.NameNotFoundException) { null }

    fun uidOf(packageName: String): Int? = resolveManually(packageName)?.uid

    fun launchIntent(packageName: String): Intent? = context.packageManager.getLaunchIntentForPackage(packageName)
}
