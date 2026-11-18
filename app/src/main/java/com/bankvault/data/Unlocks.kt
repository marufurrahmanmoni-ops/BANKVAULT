package com.bankvault.data

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * Which locked apps are temporarily unlocked. In memory only: a reboot or app restart locks
 * everything again. An app relocks when you leave it (after the chosen grace time) or the
 * screen turns off.
 */
object Unlocks {
    /** Screens that appear "on top" of an app without really leaving it. */
    private val IGNORE = setOf(
        "android", "com.android.systemui", "com.android.permissioncontroller",
        "com.google.android.permissioncontroller", "com.android.vpndialogs",
    )

    private val leftAt = HashMap<String, Long?>()   // pkg -> time it went to background (null = in front)
    private val _unlocked = MutableStateFlow<Set<String>>(emptySet())
    val unlocked: StateFlow<Set<String>> get() = _unlocked

    @Synchronized fun unlock(pkg: String) { leftAt[pkg] = null; publish() }
    @Synchronized fun isUnlocked(pkg: String) = pkg in leftAt

    /** @return packages that just relocked */
    @Synchronized fun onForeground(fg: String, ownPkg: String, now: Long, graceMs: Long): Set<String> {
        if (fg in IGNORE || fg == ownPkg) return emptySet()
        for (p in leftAt.keys.toList()) {
            if (p == fg) leftAt[p] = null else if (leftAt[p] == null) leftAt[p] = now
        }
        return tick(now, graceMs)
    }

    @Synchronized fun tick(now: Long, graceMs: Long): Set<String> {
        val expired = leftAt.filter { (_, t) -> t != null && now - t >= graceMs }.keys
        expired.forEach { leftAt.remove(it) }
        if (expired.isNotEmpty()) publish()
        return expired
    }

    @Synchronized fun lockAll(): Set<String> { val all = leftAt.keys.toSet(); leftAt.clear(); publish(); return all }
    @Synchronized fun relock(pkg: String) { leftAt.remove(pkg); publish() }

    private fun publish() { _unlocked.value = leftAt.keys.toSet() }
}
