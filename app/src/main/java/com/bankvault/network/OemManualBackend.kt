package com.bankvault.network

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import com.bankvault.core.network.AppRef
import com.bankvault.core.network.BackendKind
import com.bankvault.core.network.DesiredAccess
import com.bankvault.core.network.Enforcement
import com.bankvault.core.network.IsolationBackend
import com.bankvault.security.SecurePrefs

/**
 * Mode A network option: the phone's own per-app network switch.
 *
 * Research result (docs/FEASIBILITY.md §5A): Realme UI / ColorOS expose per-app Wi-Fi / Mobile
 * Data toggles in system Settings, but there is NO public API for third-party apps to read or
 * change them. BANKVAULT therefore only opens the right screen and explains what to switch, and
 * reports MANUAL_SETUP_REQUIRED, or VERIFICATION_UNAVAILABLE once the owner confirms – never
 * "Blocked". Note this OEM switch is static: it is not lifted during an authenticated session.
 */
class OemManualBackend(private val context: Context, private val prefs: SecurePrefs) : IsolationBackend {
    override val kind = BackendKind.OEM_MANUAL
    override suspend fun isAvailable() = true

    fun markConfirmed(pkg: String, confirmed: Boolean) = prefs.putBool("oem_confirmed_$pkg", confirmed)
    private fun confirmed(pkg: String) = prefs.getBool("oem_confirmed_$pkg")

    override suspend fun apply(policies: Map<AppRef, DesiredAccess>) = policies.mapValues { (a, d) -> verify(a, d) }

    override suspend fun verify(app: AppRef, expected: DesiredAccess): Enforcement =
        if (confirmed(app.packageName)) Enforcement.AppliedUnverified(expected, "Configured by owner in system settings; Android offers no API to confirm it.")
        else Enforcement.ManualRequired(instructions())

    override suspend fun rollback() = true

    fun instructions(): String {
        val m = Build.MANUFACTURER.lowercase()
        return if (m == "realme" || m == "oppo" || m == "oneplus")
            "Realme UI 3.0+ / ColorOS 12+: Settings > Mobile network > Data usage > Network access > choose this app > select 'Disable' " +
            "(neither Wi-Fi nor mobile data). Realme UI 1.0/2.0: Settings > SIM card & mobile data > Data usage > Network permissions. " +
            "Realme UI R/Go/S/T/U editions: Settings > Network & internet > Mobile network > Network permissions. " +
            "This setting stays on during BANKVAULT sessions – switch it back manually when you need the app."
        else
            "Open the app's info page > Mobile data & Wi-Fi (or Data usage) and turn off network access if your phone offers it. " +
            "Stock Android only offers 'Background data', which is NOT a full block."
    }

    fun appInfoIntent(pkg: String) = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$pkg"))
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
}
