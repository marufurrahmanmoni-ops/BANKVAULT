package com.bankvault.compat

import android.content.Context
import android.net.VpnService
import android.os.Build
import androidx.biometric.BiometricManager
import com.bankvault.core.compat.CapabilityResolver
import com.bankvault.core.compat.CompatEntry
import com.bankvault.core.compat.DeviceProfile
import com.bankvault.managed.ManagedDeviceController
import com.bankvault.root.RootShell
import com.bankvault.tamper.TamperMonitor

class DeviceProfiler(
    private val context: Context,
    private val managed: ManagedDeviceController,
    private val tamper: TamperMonitor,
) {
    /** Reads the ROM version via public Build fields only (no hidden SystemProperties). */
    private fun oemVersion(): String? = Build.DISPLAY.takeIf { it.isNotBlank() }

    suspend fun profile(checkRoot: Boolean): DeviceProfile = DeviceProfile(
        manufacturer = Build.MANUFACTURER,
        model = Build.MODEL,
        sdkInt = Build.VERSION.SDK_INT,
        securityPatch = Build.VERSION.SECURITY_PATCH,
        oemVersion = oemVersion(),
        isDeviceOwner = managed.isDeviceOwner,
        isProfileOwner = managed.isProfileOwner,
        // Root is only probed when the owner explicitly asks (it triggers the root manager prompt).
        rootGranted = checkRoot && RootShell.isRootGranted(),
        usageAccessGranted = tamper.hasUsageAccess(),
        vpnConsentGranted = VpnService.prepare(context) == null,
        strongBiometricEnrolled = BiometricManager.from(context).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS,
        notificationsAllowed = tamper.notificationsAllowed(),
    )

    suspend fun matrix(checkRoot: Boolean = false): Pair<DeviceProfile, List<CompatEntry>> =
        profile(checkRoot).let { it to CapabilityResolver.matrix(it) }
}
