package com.bankvault.core.compat

/** The eight support levels from the specification. */
enum class Support(val label: String) {
    FULLY_SUPPORTED("Fully supported"),
    SUPPORTED_WITH_USER_PERMISSION("Supported with user permission"),
    MANUAL_SETUP_REQUIRED("Manual setup required"),
    REQUIRES_DEVICE_OWNER("Requires Device Owner"),
    REQUIRES_OEM_PRIVILEGE("Requires OEM privilege"),
    REQUIRES_ROOT("Requires root"),
    OPTIONAL_VPN_REQUIRED("Optional VPN required"),
    UNSUPPORTED("Unsupported"),
}

enum class Feature(val title: String) {
    SEPARATE_PIN("Independent security PIN"),
    BIOMETRIC("Strong biometric unlock"),
    APP_LAUNCH_DETECTION("Detect protected app launch"),
    APP_SUSPEND("Block protected app from running (suspend)"),
    APP_HIDE_LAUNCHER("Hide protected app from launcher"),
    UNINSTALL_PROTECTION("Prevent uninstall of BANKVAULT"),
    PER_APP_NETWORK_BLOCK("Per-app Wi-Fi + Mobile Data block"),
    PER_APP_WIFI_ONLY("Block Wi-Fi only / Mobile Data only"),
    NETWORK_VERIFICATION("Verify network block automatically"),
    PRIVATE_DNS_FILTERING("Device-wide malicious-domain DNS filtering"),
    LINK_SCANNER("Link / QR / Share scanner"),
    OWN_SCREEN_PROTECTION("Protect BANKVAULT screens (FLAG_SECURE)"),
    EMERGENCY_TILE("Emergency lock Quick Settings tile"),
    TAMPER_MONITOR("Permission / setting tamper monitor"),
    FORCE_STOP_PREVENTION("Prevent Force Stop / Safe Mode bypass"),
}

data class DeviceProfile(
    val manufacturer: String,
    val model: String,
    val sdkInt: Int,
    val securityPatch: String,
    val oemVersion: String?,
    val isDeviceOwner: Boolean,
    val isProfileOwner: Boolean,
    val rootGranted: Boolean,
    val usageAccessGranted: Boolean,
    val vpnConsentGranted: Boolean,
    val strongBiometricEnrolled: Boolean,
    val notificationsAllowed: Boolean,
) {
    val isRealmeOrOppo: Boolean get() = manufacturer.lowercase() in setOf("realme", "oppo", "oneplus")
    val managed: Boolean get() = isDeviceOwner || isProfileOwner
}

data class CompatEntry(val feature: Feature, val support: Support, val active: Boolean, val note: String)

/**
 * Builds the per-device compatibility matrix. "support" is what the platform allows;
 * "active" is whether BANKVAULT currently has what it needs to actually do it.
 */
object CapabilityResolver {
    fun matrix(d: DeviceProfile): List<CompatEntry> = listOf(
        CompatEntry(Feature.SEPARATE_PIN, Support.FULLY_SUPPORTED, true, "Argon2id hash peppered with a Keystore HMAC key."),
        CompatEntry(Feature.BIOMETRIC, if (d.strongBiometricEnrolled) Support.FULLY_SUPPORTED else Support.MANUAL_SETUP_REQUIRED,
            d.strongBiometricEnrolled, if (d.strongBiometricEnrolled) "BiometricPrompt, BIOMETRIC_STRONG, Keystore-bound." else "No strong fingerprint/face enrolled yet – PIN is used. Enrol one in Android Settings."),
        CompatEntry(Feature.APP_LAUNCH_DETECTION, Support.SUPPORTED_WITH_USER_PERMISSION, d.usageAccessGranted,
            "UsageStatsManager polling. Best-effort: an app may be visible for a fraction of a second before the lock screen covers it."),
        CompatEntry(Feature.APP_SUSPEND, Support.REQUIRES_DEVICE_OWNER, d.managed,
            "DevicePolicyManager.setPackagesSuspended – the app cannot run at all while locked. This is the real security boundary."),
        CompatEntry(Feature.APP_HIDE_LAUNCHER, if (d.managed) Support.REQUIRES_DEVICE_OWNER else if (d.isRealmeOrOppo) Support.MANUAL_SETUP_REQUIRED else Support.REQUIRES_DEVICE_OWNER,
            d.managed, if (d.managed) "DevicePolicyManager.setApplicationHidden." else if (d.isRealmeOrOppo) "Use Settings > Privacy > Hide apps (Realme UI / ColorOS). BANKVAULT cannot verify it." else "Unmanaged phone: third-party apps cannot hide other apps."),
        CompatEntry(Feature.UNINSTALL_PROTECTION, Support.REQUIRES_DEVICE_OWNER, d.managed, "DevicePolicyManager.setUninstallBlocked."),
        CompatEntry(Feature.PER_APP_NETWORK_BLOCK,
            when { d.rootGranted -> Support.REQUIRES_ROOT; else -> Support.OPTIONAL_VPN_REQUIRED },
            d.rootGranted || d.vpnConsentGranted,
            if (d.rootGranted) "iptables/ip6tables UID rules." else "Local blackhole VPN (no server, no inspection). Alternatively OEM Settings > Data usage > per-app network access (manual, unverifiable)."),
        CompatEntry(Feature.PER_APP_WIFI_ONLY, if (d.rootGranted) Support.REQUIRES_ROOT else Support.OPTIONAL_VPN_REQUIRED,
            d.rootGranted || d.vpnConsentGranted, if (d.rootGranted) "Interface-based rules (wlan+ / rmnet+ / ccmni+)." else "VPN re-plans on network change; a short transition window exists."),
        CompatEntry(Feature.NETWORK_VERIFICATION, if (d.rootGranted || d.vpnConsentGranted) Support.FULLY_SUPPORTED else Support.OPTIONAL_VPN_REQUIRED,
            d.rootGranted || d.vpnConsentGranted, "Root: reads live iptables. VPN: checks the tunnel is up with the right app list. OEM manual: not verifiable."),
        CompatEntry(Feature.PRIVATE_DNS_FILTERING, Support.MANUAL_SETUP_REQUIRED, false,
            "Third-party apps cannot set Private DNS (needs WRITE_SECURE_SETTINGS). BANKVAULT guides you and verifies via LinkProperties."),
        CompatEntry(Feature.LINK_SCANNER, Support.FULLY_SUPPORTED, true, "Offline analyzer + signed local threat database."),
        CompatEntry(Feature.OWN_SCREEN_PROTECTION, Support.FULLY_SUPPORTED, true, "FLAG_SECURE on BANKVAULT windows only – it cannot protect other apps' screens."),
        CompatEntry(Feature.EMERGENCY_TILE, Support.SUPPORTED_WITH_USER_PERMISSION, true, "User adds the tile from the Quick Settings editor."),
        CompatEntry(Feature.TAMPER_MONITOR, Support.FULLY_SUPPORTED, true, "Detects revoked permissions, VPN loss, developer options, ADB, root indicators."),
        CompatEntry(Feature.FORCE_STOP_PREVENTION, if (d.isDeviceOwner) Support.REQUIRES_DEVICE_OWNER else Support.UNSUPPORTED, false,
            "No ordinary app can prevent Force Stop or Safe Mode. Device-Owner suspension and root iptables rules persist if BANKVAULT is stopped; the local VPN only comes back if Always-on VPN is enabled."),
    )
}
