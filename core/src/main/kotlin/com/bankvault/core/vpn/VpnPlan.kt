package com.bankvault.core.vpn

import com.bankvault.core.network.AppRef
import com.bankvault.core.network.DesiredAccess
import com.bankvault.core.network.Transport

/**
 * Planning for the optional local "blackhole" VPN (Mode D).
 *
 * Design: the VPN is established with addAllowedApplication() for *only* the locked apps that
 * must be blocked on the current transport. Their packets arrive on the TUN interface and are
 * dropped; nothing is forwarded, so no remote server, no TLS interception and no traffic
 * collection is involved. Every other app is outside the VPN and uses the network normally.
 *
 * Critical Android behaviour encoded here:
 *  - A VpnService.Builder with NO allowed/disallowed apps routes EVERY app through the VPN.
 *    An empty blackhole set must therefore STOP the VPN, never establish it.
 *  - Both 0.0.0.0/0 and ::/0 must be routed or IPv6 traffic bypasses the tunnel.
 *  - DNS servers inside the tunnel (unreachable) prevent DNS leaks from blocked apps.
 */
sealed class VpnPlan {
    data object Stop : VpnPlan()
    data class Establish(
        val blackholePackages: Set<String>,
        val ipv4Address: String = "10.215.173.1",
        val ipv4Prefix: Int = 32,
        val ipv6Address: String = "fd00:b4b:7a17::1",
        val ipv6Prefix: Int = 128,
        val routes: List<Pair<String, Int>> = listOf("0.0.0.0" to 0, "::" to 0),
        val dnsServers: List<String> = listOf("10.215.173.53", "fd00:b4b:7a17::53"),
        val mtu: Int = 1500,
        /** True when some rule depends on the transport, so a network switch must re-plan. */
        val transportSensitive: Boolean,
    ) : VpnPlan()
}

object VpnPlanner {
    /**
     * @param current the current default transport, or null if unknown / switching. When unknown
     *        every app that blocks ANY transport is blackholed (fail closed).
     */
    fun plan(policies: Map<AppRef, DesiredAccess>, current: Transport?, ownPackage: String): VpnPlan {
        val blocked = policies.filter { (app, access) ->
            app.packageName != ownPackage && when (current) {
                Transport.WIFI -> !access.allowWifi
                Transport.CELLULAR -> !access.allowMobile
                null -> !access.allowWifi || !access.allowMobile
            }
        }.keys.map { it.packageName }.toSet()
        if (blocked.isEmpty()) return VpnPlan.Stop
        val sensitive = policies.values.any { it.allowWifi != it.allowMobile }
        return VpnPlan.Establish(blackholePackages = blocked, transportSensitive = sensitive)
    }

    /** Which apps are effectively blocked by a plan on a given transport (for verification/UI). */
    fun effective(plan: VpnPlan, app: AppRef): DesiredAccess =
        if (plan is VpnPlan.Establish && app.packageName in plan.blackholePackages) DesiredAccess(false, false)
        else DesiredAccess.ALLOW_ALL
}
