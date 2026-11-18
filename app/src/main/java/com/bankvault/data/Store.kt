package com.bankvault.data

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** When a locked app locks again after you leave it. */
enum class Relock(val label: String, val graceMs: Long) {
    IMMEDIATELY("Immediately when I leave the app", 0),
    ONE_MINUTE("1 minute after I leave", 60_000),
    FIVE_MINUTES("5 minutes after I leave", 300_000),
}

/** All app data. Only the PIN *hash* is stored (never the PIN). Nothing leaves the phone. */
object Store {
    private lateinit var sp: SharedPreferences
    private val _locked = MutableStateFlow<Set<String>>(emptySet())
    val locked: StateFlow<Set<String>> get() = _locked

    fun init(ctx: Context) {
        if (::sp.isInitialized) return
        sp = ctx.applicationContext.getSharedPreferences("bankvault", Context.MODE_PRIVATE)
        _locked.value = sp.getStringSet("locked", emptySet())!!.toSet()
        _hidden.value = sp.getStringSet("hidden", emptySet())!!.toSet()
        _netBlock.value = sp.getBoolean("netblock", false)
    }

    fun pinRecord(): String? = sp.getString("pin", null)
    fun setPinRecord(v: String) = sp.edit().putString("pin", v).commit()
    fun pinSet() = pinRecord() != null

    fun lockedApps(): Set<String> = _locked.value
    fun setLocked(pkg: String, locked: Boolean) {
        val n = if (locked) _locked.value + pkg else _locked.value - pkg
        sp.edit().putStringSet("locked", n).apply(); _locked.value = n
    }

    /** Apps the owner wants hidden while locked (only possible with Device Owner). */
    private val _hidden = MutableStateFlow<Set<String>>(emptySet())
    val hidden: StateFlow<Set<String>> get() = _hidden
    fun setHidden(pkg: String, hide: Boolean) {
        val n = if (hide) _hidden.value + pkg else _hidden.value - pkg
        sp.edit().putStringSet("hidden", n).apply(); _hidden.value = n
    }

    /** Network access off for locked apps (local VPN). */
    private val _netBlock = MutableStateFlow(false)
    val netBlock: StateFlow<Boolean> get() = _netBlock
    fun setNetBlock(on: Boolean) { sp.edit().putBoolean("netblock", on).apply(); _netBlock.value = on }

    var relock: Relock
        get() = runCatching { Relock.valueOf(sp.getString("relock", null) ?: "") }.getOrDefault(Relock.IMMEDIATELY)
        set(v) { sp.edit().putString("relock", v.name).apply() }

    var fingerprint: Boolean
        get() = sp.getBoolean("fingerprint", true)
        set(v) { sp.edit().putBoolean("fingerprint", v).apply() }

    // Brute-force counter (persisted, survives reboot)
    var failures: Int
        get() = sp.getInt("fail", 0)
        set(v) { sp.edit().putInt("fail", v).commit() }
    var lockedUntil: Long
        get() = sp.getLong("until", 0)
        set(v) { sp.edit().putLong("until", v).commit() }
    var lastEvent: Long
        get() = sp.getLong("last", 0)
        set(v) { sp.edit().putLong("last", v).commit() }
}
