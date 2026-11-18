package com.bankvault.data

import com.bankvault.core.auth.AuthPolicy
import com.bankvault.security.SecurePrefs
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

enum class NetworkMode(val title: String) {
    NONE("Off"),
    OEM_MANUAL("Phone's own network-access setting (manual)"),
    LOCAL_VPN("Local blackhole VPN (recommended without root)"),
    ROOT_FIREWALL("Root firewall (iptables)"),
}

enum class SecurityProfile(val title: String) {
    BANKING_LOCKDOWN("Banking Lockdown"),
    SAFE_INTERNET("Safe Internet"),
    MAXIMUM_SECURITY("Maximum Security"),
    PRIVATE_MODE("Private Mode"),
    EMERGENCY_LOCKDOWN("Emergency Lockdown"),
}

data class SettingsSnapshot(
    val authPolicy: AuthPolicy = AuthPolicy.PIN_ONLY,
    val settingsAuthPolicy: AuthPolicy = AuthPolicy.PIN_ONLY,
    val networkMode: NetworkMode = NetworkMode.NONE,
    val profile: SecurityProfile = SecurityProfile.BANKING_LOCKDOWN,
    val stealthLauncherHidden: Boolean = false,
    val tileAdded: Boolean = false,
    val feedUrl: String = "",
    val externalIntelEnabled: Boolean = false,
    val trackerWarnings: Boolean = false,
    val threatDbVersion: Long = 0,
    val endOnScreenOff: Boolean = true,
)

/** Settings are encrypted at rest; changes require authentication in the UI layer. */
class SettingsStore(private val prefs: SecurePrefs) {
    private val _state = MutableStateFlow(load())
    val state: StateFlow<SettingsSnapshot> = _state

    private fun load() = SettingsSnapshot(
        authPolicy = enumOr(prefs.getString("auth_policy"), AuthPolicy.PIN_ONLY),
        settingsAuthPolicy = enumOr(prefs.getString("settings_auth_policy"), AuthPolicy.PIN_ONLY),
        networkMode = enumOr(prefs.getString("network_mode"), NetworkMode.NONE),
        profile = enumOr(prefs.getString("profile"), SecurityProfile.BANKING_LOCKDOWN),
        stealthLauncherHidden = prefs.getBool("stealth_launcher"),
        tileAdded = prefs.getBool("tile_added"),
        feedUrl = prefs.getString("feed_url") ?: "",
        externalIntelEnabled = prefs.getBool("external_intel"),
        trackerWarnings = prefs.getBool("tracker_warnings"),
        threatDbVersion = prefs.getLong("threat_db_version"),
        endOnScreenOff = prefs.getBool("end_on_screen_off", true),
    )

    fun update(block: (SettingsSnapshot) -> SettingsSnapshot) {
        val n = block(_state.value)
        prefs.putString("auth_policy", n.authPolicy.name)
        prefs.putString("settings_auth_policy", n.settingsAuthPolicy.name)
        prefs.putString("network_mode", n.networkMode.name)
        prefs.putString("profile", n.profile.name)
        prefs.putBool("stealth_launcher", n.stealthLauncherHidden)
        prefs.putBool("tile_added", n.tileAdded)
        prefs.putString("feed_url", n.feedUrl)
        prefs.putBool("external_intel", n.externalIntelEnabled)
        prefs.putBool("tracker_warnings", n.trackerWarnings)
        prefs.putLong("threat_db_version", n.threatDbVersion)
        prefs.putBool("end_on_screen_off", n.endOnScreenOff)
        _state.value = n
    }

    private inline fun <reified E : Enum<E>> enumOr(v: String?, def: E): E =
        v?.let { s -> enumValues<E>().firstOrNull { it.name == s } } ?: def
}
