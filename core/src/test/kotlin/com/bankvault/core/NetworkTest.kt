package com.bankvault.core

import com.bankvault.core.network.*
import com.bankvault.core.root.IptablesPlan
import com.bankvault.core.vpn.VpnPlan
import com.bankvault.core.vpn.VpnPlanner
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkTest {
    private val bank = AppRef("com.example.dummybank", 10_234)
    private val wallet = AppRef("com.example.dummywallet", 10_235)

    /** Backend that records policies and reports them back as verified (like root/VPN read-back). */
    private class FakeBackend(var mode: String = "verified") : IsolationBackend {
        override val kind = BackendKind.ROOT_FIREWALL
        val live = mutableMapOf<AppRef, DesiredAccess>()
        override suspend fun isAvailable() = mode != "down"
        override suspend fun apply(policies: Map<AppRef, DesiredAccess>): Map<AppRef, Enforcement> {
            if (mode == "throw") throw IllegalStateException("su denied")
            live.clear(); live.putAll(policies)
            return policies.mapValues { (a, _) -> verify(a, policies.getValue(a)) }
        }
        override suspend fun verify(app: AppRef, expected: DesiredAccess): Enforcement = when (mode) {
            "unverified" -> Enforcement.AppliedUnverified(expected, "no read-back")
            "manual" -> Enforcement.ManualRequired("open settings")
            "tampered" -> Enforcement.Verified(DesiredAccess.ALLOW_ALL)
            else -> Enforcement.Verified(live[app] ?: DesiredAccess.ALLOW_ALL)
        }
        override suspend fun rollback(): Boolean { live.clear(); return true }
    }

    @Test fun resolverNeverShowsRequestedAsApplied() {
        val req = DesiredAccess(false, false)
        assertEquals(NetworkAccessState.PROTECTION_INACTIVE, NetworkStateResolver.resolve(req, false, Enforcement.NoBackend))
        assertEquals(NetworkAccessState.PROTECTION_PENDING, NetworkStateResolver.resolve(req, false, Enforcement.Pending))
        assertEquals(NetworkAccessState.VERIFICATION_UNAVAILABLE, NetworkStateResolver.resolve(req, false, Enforcement.AppliedUnverified(req, "")))
        assertEquals(NetworkAccessState.MANUAL_SETUP_REQUIRED, NetworkStateResolver.resolve(req, false, Enforcement.ManualRequired("")))
        assertEquals(NetworkAccessState.BLOCKED_ALL, NetworkStateResolver.resolve(req, false, Enforcement.Verified(req)))
        // Verified state differs from request (rule removed by someone) -> not "blocked".
        assertEquals(NetworkAccessState.PROTECTION_PENDING, NetworkStateResolver.resolve(req, false, Enforcement.Verified(DesiredAccess.ALLOW_ALL)))
    }

    @Test fun wifiAndMobileStatesIndependent() {
        assertEquals(NetworkAccessState.BLOCKED_WIFI, NetworkStateResolver.resolve(DesiredAccess(false, true), false, Enforcement.Verified(DesiredAccess(false, true))))
        assertEquals(NetworkAccessState.BLOCKED_MOBILE_DATA, NetworkStateResolver.resolve(DesiredAccess(true, false), false, Enforcement.Verified(DesiredAccess(true, false))))
    }

    @Test fun lockUnlockRelockCycle() = runBlocking {
        val be = FakeBackend(); val eng = NetworkIsolationEngine { be }
        eng.setProtected(bank, LockedNetworkRule()); eng.setProtected(wallet, LockedNetworkRule())
        assertTrue(eng.status().all { it.state == NetworkAccessState.PROTECTION_PENDING })
        eng.reconcile()
        assertTrue(eng.status().all { it.state == NetworkAccessState.BLOCKED_ALL })
        assertEquals(NetworkAccessState.TEMPORARILY_ALLOWED, eng.allow(bank).state)
        assertEquals(NetworkAccessState.BLOCKED_ALL, eng.status().first { it.app == wallet }.state) // other app still blocked
        assertEquals(NetworkAccessState.BLOCKED_ALL, eng.block(bank).state)
    }

    @Test fun backendFailuresAreReportedHonestly() = runBlocking {
        val be = FakeBackend(); val eng = NetworkIsolationEngine { be }
        eng.setProtected(bank, LockedNetworkRule())
        be.mode = "throw"; assertEquals(NetworkAccessState.PROTECTION_INACTIVE, eng.reconcile().single().state)
        be.mode = "down"; assertEquals(NetworkAccessState.PROTECTION_INACTIVE, eng.reconcile().single().state)
        be.mode = "unverified"; assertEquals(NetworkAccessState.VERIFICATION_UNAVAILABLE, eng.reconcile().single().state)
        be.mode = "manual"; assertEquals(NetworkAccessState.MANUAL_SETUP_REQUIRED, eng.reconcile().single().state)
        be.mode = "verified"; eng.reconcile()
        be.mode = "tampered"; assertEquals(NetworkAccessState.PROTECTION_PENDING, eng.verifyAll().single().state)
        assertEquals(NetworkAccessState.PROTECTION_INACTIVE, NetworkIsolationEngine { null }.also { it.setProtected(bank, LockedNetworkRule()) }.reconcile().single().state)
    }

    // ---------- VPN planning ----------

    @Test fun vpnNeverEstablishedWithEmptyAppList() {
        // Empty allowed-app list would route EVERY app into the blackhole.
        assertEquals(VpnPlan.Stop, VpnPlanner.plan(emptyMap(), Transport.WIFI, "com.bankvault"))
        assertEquals(VpnPlan.Stop, VpnPlanner.plan(mapOf(bank to DesiredAccess.ALLOW_ALL), Transport.WIFI, "com.bankvault"))
    }

    @Test fun vpnRoutesIpv4AndIpv6AndDns() {
        val p = VpnPlanner.plan(mapOf(bank to DesiredAccess(false, false)), Transport.CELLULAR, "com.bankvault") as VpnPlan.Establish
        assertEquals(setOf(bank.packageName), p.blackholePackages)
        assertTrue(p.routes.contains("0.0.0.0" to 0)); assertTrue(p.routes.contains("::" to 0))
        assertTrue(p.dnsServers.any { it.contains(':') } && p.dnsServers.any { it.contains('.') })
    }

    @Test fun vpnPerTransportAndFailClosed() {
        val wifiOnly = mapOf(bank to DesiredAccess(allowWifi = false, allowMobile = true))
        assertTrue(VpnPlanner.plan(wifiOnly, Transport.WIFI, "x") is VpnPlan.Establish)
        assertEquals(VpnPlan.Stop, VpnPlanner.plan(wifiOnly, Transport.CELLULAR, "x"))
        val unknown = VpnPlanner.plan(wifiOnly, null, "x") as VpnPlan.Establish
        assertTrue(unknown.transportSensitive && bank.packageName in unknown.blackholePackages)
        assertEquals(VpnPlan.Stop, VpnPlanner.plan(mapOf(AppRef("com.bankvault", 10_100) to DesiredAccess(false, false)), Transport.WIFI, "com.bankvault"))
    }

    // ---------- Root firewall ----------

    @Test fun iptablesOnlyTouchesOwnChainBothFamilies() {
        val cmds = IptablesPlan.applyCommands(mapOf(bank to DesiredAccess(false, false), wallet to DesiredAccess(false, true)))
        assertFalse(cmds.any { it.contains("-F OUTPUT") || it.contains("-P ") || it.contains("-X OUTPUT") })
        assertTrue(cmds.any { it.startsWith("ip6tables") && it.contains("--uid-owner 10234 -j REJECT") })
        assertTrue(cmds.any { it.startsWith("iptables ") && it.contains("--uid-owner 10234 -j REJECT") })
        assertTrue(cmds.any { it.contains("-o wlan+ -m owner --uid-owner 10235 -j REJECT") })
        assertFalse(cmds.any { it.contains("-o ccmni+ -m owner --uid-owner 10235") })
        assertTrue(cmds.all { it.contains(IptablesPlan.CHAIN) })
    }

    @Test fun iptablesRefusesSystemUids() {
        try { IptablesPlan.applyCommands(mapOf(AppRef("android", 1000) to DesiredAccess(false, false))); throw AssertionError("must refuse") }
        catch (_: IllegalArgumentException) {}
        try { IptablesPlan.backupCommands("/data/x; rm -rf /"); throw AssertionError("must refuse") } catch (_: IllegalArgumentException) {}
    }

    @Test fun iptablesVerificationReadsLiveState() {
        val v4 = """
            -N bankvault_out
            -A bankvault_out -o lo -m owner --uid-owner 10234 -j RETURN
            -A bankvault_out -m owner --uid-owner 10234 -j REJECT --reject-with icmp-port-unreachable
            -A bankvault_out -o wlan+ -m owner --uid-owner 10235 -j REJECT --reject-with icmp-port-unreachable
            -A bankvault_out -j RETURN
        """.trimIndent()
        val v6 = v4.replace("icmp-port-unreachable", "icmp6-port-unreachable")
        assertEquals(DesiredAccess(false, false), IptablesPlan.parseEnforced(v4, v6, 10234, true))
        assertEquals(DesiredAccess(false, true), IptablesPlan.parseEnforced(v4, v6, 10235, true))
        assertEquals(DesiredAccess.ALLOW_ALL, IptablesPlan.parseEnforced(v4, v6, 10234, jumpPresent = false))
        // IPv6 rule missing -> must not report as blocked (IPv6 leak).
        assertEquals(DesiredAccess.ALLOW_ALL, IptablesPlan.parseEnforced(v4, "-N bankvault_out", 10234, true))
    }

    @Test fun iptablesRollbackRemovesOnlyOurs() {
        val r = IptablesPlan.rollbackCommands()
        assertTrue(r.all { it.contains(IptablesPlan.CHAIN) })
        assertEquals(6, r.size)
    }
}
