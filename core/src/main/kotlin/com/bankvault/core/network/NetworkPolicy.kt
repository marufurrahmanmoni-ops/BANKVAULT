package com.bankvault.core.network

/** The eight user-visible network states required by the specification. */
enum class NetworkAccessState {
    BLOCKED_WIFI,
    BLOCKED_MOBILE_DATA,
    BLOCKED_ALL,
    TEMPORARILY_ALLOWED,
    PROTECTION_PENDING,
    PROTECTION_INACTIVE,
    MANUAL_SETUP_REQUIRED,
    VERIFICATION_UNAVAILABLE,
}

enum class Transport { WIFI, CELLULAR }

/** What the owner wants while the app is locked. */
data class LockedNetworkRule(val blockWifi: Boolean = true, val blockMobile: Boolean = true) {
    val blocksAnything get() = blockWifi || blockMobile
}

/** What a backend should enforce right now for one app. */
data class DesiredAccess(val allowWifi: Boolean, val allowMobile: Boolean) {
    companion object {
        val ALLOW_ALL = DesiredAccess(true, true)
        fun forLocked(rule: LockedNetworkRule) = DesiredAccess(!rule.blockWifi, !rule.blockMobile)
    }
}

enum class BackendKind { ROOT_FIREWALL, LOCAL_VPN, OEM_MANUAL, NONE }

/** Result of a backend's attempt to apply or check a policy. */
sealed class Enforcement {
    /** Backend applied the policy and confirmed it by reading the live state back. */
    data class Verified(val access: DesiredAccess) : Enforcement()
    /** Backend says it applied the policy but has no way to read it back. */
    data class AppliedUnverified(val access: DesiredAccess, val why: String) : Enforcement()
    /** The owner must act in OEM / system settings; BANKVAULT cannot confirm it. */
    data class ManualRequired(val instructions: String) : Enforcement()
    data object Pending : Enforcement()
    data class Failed(val error: String) : Enforcement()
    data object NoBackend : Enforcement()
}

/**
 * Pure mapping from (requested, enforcement) to the dashboard state.
 * The core rule of the project: a *requested* policy is never shown as *applied*.
 */
object NetworkStateResolver {
    fun resolve(requested: DesiredAccess, sessionActive: Boolean, enforcement: Enforcement): NetworkAccessState =
        when (enforcement) {
            Enforcement.NoBackend -> NetworkAccessState.PROTECTION_INACTIVE
            is Enforcement.Failed -> NetworkAccessState.PROTECTION_INACTIVE
            Enforcement.Pending -> NetworkAccessState.PROTECTION_PENDING
            is Enforcement.ManualRequired -> NetworkAccessState.MANUAL_SETUP_REQUIRED
            is Enforcement.AppliedUnverified -> NetworkAccessState.VERIFICATION_UNAVAILABLE
            is Enforcement.Verified -> {
                val v = enforcement.access
                when {
                    // A verified state that differs from what we asked for is a failure, not success.
                    v != requested -> NetworkAccessState.PROTECTION_PENDING
                    sessionActive && v.allowWifi && v.allowMobile -> NetworkAccessState.TEMPORARILY_ALLOWED
                    !v.allowWifi && !v.allowMobile -> NetworkAccessState.BLOCKED_ALL
                    !v.allowWifi -> NetworkAccessState.BLOCKED_WIFI
                    !v.allowMobile -> NetworkAccessState.BLOCKED_MOBILE_DATA
                    // Locked app, verified, but rule blocks nothing: protection is off by owner choice.
                    else -> NetworkAccessState.PROTECTION_INACTIVE
                }
            }
        }
}

/**
 * Something that can restrict an app's network. Implementations:
 * root iptables (app/.../root), local VpnService blackhole (app/.../vpn), OEM manual guide.
 */
interface IsolationBackend {
    val kind: BackendKind
    suspend fun isAvailable(): Boolean
    /** Apply the complete desired policy set (backends reconcile, not patch). */
    suspend fun apply(policies: Map<AppRef, DesiredAccess>): Map<AppRef, Enforcement>
    suspend fun verify(app: AppRef, expected: DesiredAccess): Enforcement
    /** Remove every rule BANKVAULT installed. Used by recovery / uninstall. */
    suspend fun rollback(): Boolean
}

data class AppRef(val packageName: String, val uid: Int)
