package com.bankvault.dns

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.provider.Settings

/**
 * VPN-free, device-wide DNS protection = Android Private DNS (DNS-over-TLS) pointed at a
 * filtering resolver. Third-party apps cannot change Private DNS (needs WRITE_SECURE_SETTINGS),
 * so BANKVAULT recommends a hostname, opens Settings, and then VERIFIES via public LinkProperties.
 *
 * This filters every app on the device; it is not a per-app firewall.
 */
object PrivateDnsInspector {
    data class Provider(val name: String, val hostname: String, val blocks: String)

    /**
     * Public DoT hostnames of security-filtering resolvers. Verify the provider's current
     * documentation and privacy policy before recommending; the owner chooses.
     */
    val PROVIDERS = listOf(
        Provider("Cloudflare for Families (malware)", "security.cloudflare-dns.com", "Malware"),
        Provider("Quad9", "dns.quad9.net", "Malware & phishing (threat-intel based)"),
        Provider("AdGuard DNS", "dns.adguard-dns.com", "Ads, trackers, phishing"),
        Provider("CleanBrowsing Security", "security-filter-dns.cleanbrowsing.org", "Phishing, malware"),
    )

    data class Status(val active: Boolean, val serverName: String?, val knownFilteringProvider: Provider?)

    fun status(context: Context): Status {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val lp = cm.getLinkProperties(cm.activeNetwork) ?: return Status(false, null, null)
        val name = lp.privateDnsServerName
        // isPrivateDnsActive is true for both "automatic" (opportunistic) and strict mode;
        // only strict mode with a hostname guarantees the filtering resolver is used.
        val active = lp.isPrivateDnsActive && name != null
        return Status(active, name, PROVIDERS.firstOrNull { it.hostname.equals(name, true) })
    }

    /** No public Intent opens the Private DNS dialog directly; open Network settings. */
    fun settingsIntent() = Intent(Settings.ACTION_WIRELESS_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
}
