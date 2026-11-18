package com.bankvault.core

import com.bankvault.core.audit.*
import com.bankvault.core.compat.*
import com.bankvault.core.emergency.*
import com.bankvault.core.network.*
import com.bankvault.core.session.SessionConfig
import com.bankvault.core.session.SessionManager
import com.bankvault.core.status.ProtectionStatus
import com.bankvault.core.status.StatusTone
import com.bankvault.core.util.FakeClock
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MiscTest {
    @Test fun auditRedactsCredentialsAndOtps() {
        val r = AuditRedactor.redact("OTP 482915 for acct 1234-5678-9012 pin=4321 token: abcdef https://x.test/a?otp=1 mail a.b@c.com code 12")
        assertFalse(r.contains("482915")); assertFalse(r.contains("1234")); assertFalse(r.contains("4321"))
        assertFalse(r.contains("abcdef")); assertFalse(r.contains("otp=1")); assertFalse(r.contains("a.b@c.com"))
        assertTrue(r.contains("code 12")) // short numbers like counts are kept
        assertTrue(AuditRedactor.redact("x".repeat(1000)).length <= AuditRedactor.MAX_LEN)
    }

    @Test fun greenOnlyForVerifiedProtection() {
        for (s in ProtectionStatus.entries) if (s.tone == StatusTone.GOOD) assertTrue(s.verified)
        assertEquals(ProtectionStatus.VERIFICATION_UNAVAILABLE, ProtectionStatus.fromNetwork(NetworkAccessState.VERIFICATION_UNAVAILABLE))
        assertFalse(ProtectionStatus.VERIFICATION_UNAVAILABLE.tone == StatusTone.GOOD)
        assertEquals(ProtectionStatus.DEGRADED, ProtectionStatus.overall(listOf(ProtectionStatus.PROTECTED, ProtectionStatus.DEGRADED)))
        assertEquals(ProtectionStatus.PROTECTED, ProtectionStatus.overall(listOf(ProtectionStatus.PROTECTED, ProtectionStatus.BLOCKED)))
        assertEquals(ProtectionStatus.PENDING, ProtectionStatus.overall(emptyList()))
    }

    private fun profile(managed: Boolean = false, root: Boolean = false, vpn: Boolean = false) = DeviceProfile(
        "realme", "RMX3999", 35, "2026-10-01", "RMX_15.0", managed, false, root, true, vpn, true, true)

    @Test fun compatibilityMatrixIsHonest() {
        val m = CapabilityResolver.matrix(profile()).associateBy { it.feature }
        assertEquals(Support.MANUAL_SETUP_REQUIRED, m.getValue(Feature.APP_HIDE_LAUNCHER).support)
        assertFalse(m.getValue(Feature.APP_SUSPEND).active)
        assertFalse(m.getValue(Feature.PER_APP_NETWORK_BLOCK).active)
        assertFalse(m.getValue(Feature.FORCE_STOP_PREVENTION).active)
        assertEquals(Feature.entries.size, m.size)
        val vpn = CapabilityResolver.matrix(profile(vpn = true)).associateBy { it.feature }
        assertTrue(vpn.getValue(Feature.PER_APP_NETWORK_BLOCK).active)
        assertEquals(Support.OPTIONAL_VPN_REQUIRED, vpn.getValue(Feature.PER_APP_NETWORK_BLOCK).support)
        assertTrue(CapabilityResolver.matrix(profile(managed = true)).first { it.feature == Feature.APP_SUSPEND }.active)
    }

    private class Sink : AuditSink { val events = mutableListOf<AuditEvent>(); override suspend fun record(event: AuditEvent) { events += AuditRedactor.sanitize(event) } }

    @Test fun emergencyLockReportsWhatActuallyHappened() = runBlocking {
        val clock = FakeClock(); val bank = AppRef("com.example.dummybank", 10_234)
        val sm = SessionManager(clock) { SessionConfig() }
        val backend = object : IsolationBackend {
            override val kind = BackendKind.LOCAL_VPN
            override suspend fun isAvailable() = true
            override suspend fun apply(policies: Map<AppRef, DesiredAccess>) = policies.mapValues { Enforcement.Verified(it.value) as Enforcement }
            override suspend fun verify(app: AppRef, expected: DesiredAccess): Enforcement = Enforcement.Verified(expected)
            override suspend fun rollback() = true
        }
        val net = NetworkIsolationEngine { backend }.apply { setProtected(bank, LockedNetworkRule()) }
        sm.onAuthenticated(bank.packageName); net.allow(bank)
        var wiped = false; var locked = false
        val sink = Sink()
        val lock = EmergencyLock(clock, sm, net,
            object : AppAccessController {
                override val canRestrict = false
                override suspend fun restrict(packages: Set<String>) = emptySet<String>()
                override suspend fun release(packages: Set<String>) = emptySet<String>()
            },
            object : SensitiveStateWiper { override suspend fun wipeTransientState() { wiped = true }; override suspend fun lockDashboard() { locked = true } },
            sink) { setOf(bank.packageName) }
        val r = lock.trigger("qs_tile")
        assertTrue(sm.activePackages().isEmpty())
        assertEquals(NetworkAccessState.BLOCKED_ALL, net.status().single().state)
        assertTrue(wiped && locked)
        // Unmanaged phone: suspension is SKIPPED (honestly reported), not counted as a failure.
        assertTrue(r.fullySucceeded)
        assertEquals(listOf("Suspend / hide protected apps"), r.skipped.map { it.name })
        assertFalse(r.steps.single { it.name.startsWith("Suspend") }.ok)
        assertEquals(AuditType.EMERGENCY_LOCK, sink.events.single().type)
        assertTrue(sink.events.single().detail.contains("Suspend / hide protected apps:skipped (not available on this phone)"))
    }
}
