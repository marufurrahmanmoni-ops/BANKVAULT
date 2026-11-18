package com.bankvault.core

import com.bankvault.core.session.*
import com.bankvault.core.util.FakeClock
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SessionTest {
    private val bank = "com.example.dummybank"
    private val clock = FakeClock()
    private val sm = SessionManager(clock) { SessionConfig(durationMillis = 60_000, backgroundGraceMillis = 20_000) }

    @Test fun lockedByDefault() { assertEquals(SessionState.Locked, sm.state(bank)) }

    @Test fun sessionExpiresAfterDuration() {
        sm.onAuthenticated(bank)
        clock.advance(59_999); assertTrue(sm.tick().isEmpty())
        clock.advance(1); assertEquals(listOf(SessionEffect.Revoke(bank, EndReason.EXPIRED)), sm.tick())
        assertEquals(SessionState.Locked, sm.state(bank))
    }

    @Test fun briefAppSwitchKeepsSession() {
        sm.onAuthenticated(bank)
        sm.onForegroundChanged("com.android.messaging") // copy OTP
        clock.advance(15_000); assertTrue(sm.tick().isEmpty())
        sm.onForegroundChanged(bank)
        clock.advance(15_000); assertTrue(sm.tick().isEmpty())
        assertTrue(sm.state(bank) is SessionState.Active)
    }

    @Test fun longBackgroundEndsSession() {
        sm.onAuthenticated(bank); sm.onForegroundChanged("com.android.launcher")
        clock.advance(20_000)
        assertEquals(listOf(SessionEffect.Revoke(bank, EndReason.INACTIVITY)), sm.tick())
    }

    @Test fun screenOffEmergencyRebootEndSessions() {
        sm.onAuthenticated(bank); assertEquals(EndReason.SCREEN_OFF, (sm.onScreenOff().single() as SessionEffect.Revoke).reason)
        sm.onAuthenticated(bank); assertEquals(EndReason.EMERGENCY_LOCK, (sm.onEmergencyLock().single() as SessionEffect.Revoke).reason)
        sm.onAuthenticated(bank); assertEquals(EndReason.REBOOT, (sm.onReboot().single() as SessionEffect.Revoke).reason)
        assertTrue(sm.activePackages().isEmpty())
    }

    @Test fun wallClockChangeCannotExtendSession() {
        sm.onAuthenticated(bank)
        clock.now -= 3_600_000 // user sets clock back
        clock.elapsed += 60_000
        assertEquals(EndReason.EXPIRED, (sm.tick().single() as SessionEffect.Revoke).reason)
    }

    @Test fun configValidation() {
        try { SessionConfig(durationMillis = 1_000); throw AssertionError("should reject") } catch (_: IllegalArgumentException) {}
        assertEquals(listOf(30_000L, 60_000L, 180_000L, 300_000L, 600_000L), SessionConfig.PRESETS)
    }
}
