package com.bankvault.core

import com.bankvault.core.auth.*
import com.bankvault.core.util.FakeClock
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class AuthTest {
    private fun hmacPepper(key: String) = Pepper { input ->
        Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key.toByteArray(), "HmacSHA256")) }.doFinal(input)
    }
    private val hasher = PinHasher(Pbkdf2Kdf(iterations = 2_000), hmacPepper("device-key-A"))

    @Test fun pinPolicyRejectsWeakPins() {
        assertTrue(PinPolicy.validate("12345".toCharArray()) is PinPolicy.Result.Rejected)      // too short
        assertTrue(PinPolicy.validate("123456789".toCharArray()) is PinPolicy.Result.Rejected)  // too long
        assertTrue(PinPolicy.validate("111111".toCharArray()) is PinPolicy.Result.Rejected)
        assertTrue(PinPolicy.validate("123456".toCharArray()) is PinPolicy.Result.Rejected)
        assertTrue(PinPolicy.validate("876543".toCharArray()) is PinPolicy.Result.Rejected)
        assertTrue(PinPolicy.validate("12a456".toCharArray()) is PinPolicy.Result.Rejected)
        assertEquals(PinPolicy.Result.Ok, PinPolicy.validate("482915".toCharArray()))
        assertEquals(PinPolicy.Result.Ok, PinPolicy.validate("48291573".toCharArray()))
    }

    @Test fun correctPinVerifiesWrongPinFails() {
        val rec = hasher.hash("482915".toCharArray())
        assertTrue(hasher.verify("482915".toCharArray(), rec))
        assertFalse(hasher.verify("482916".toCharArray(), rec))
        assertFalse(hasher.verify("4829150".toCharArray(), rec))
    }

    @Test fun recordNeverContainsPlaintextAndRoundTrips() {
        val rec = hasher.hash("482915".toCharArray())
        val enc = rec.encode()
        assertFalse(enc.contains("482915"))
        assertEquals(rec, PinRecord.decode(enc))
        assertEquals(16, rec.salt.size)
    }

    @Test fun saltMakesHashesUnique() {
        val a = hasher.hash("482915".toCharArray()); val b = hasher.hash("482915".toCharArray())
        assertFalse(a.hash.contentEquals(b.hash))
    }

    @Test fun hashIsBoundToDevicePepper() {
        val rec = hasher.hash("482915".toCharArray())
        val otherDevice = PinHasher(Pbkdf2Kdf(iterations = 2_000), hmacPepper("device-key-B"))
        assertFalse("copied DB must not verify on another device key", otherDevice.verify("482915".toCharArray(), rec))
    }

    @Test fun rehashDetectedWhenParamsChange() {
        val rec = hasher.hash("482915".toCharArray())
        assertTrue(PinHasher(Pbkdf2Kdf(iterations = 4_000), hmacPepper("device-key-A")).needsRehash(rec))
        assertFalse(hasher.needsRehash(rec))
    }

    @Test fun progressiveLockout() {
        val clock = FakeClock(); val lim = AttemptLimiter(InMemoryAttemptStore(), clock)
        lim.recordFailure(); lim.recordFailure()
        assertEquals(AttemptLimiter.Gate.Open, lim.gate())
        val g3 = lim.recordFailure()
        assertTrue(g3 is AttemptLimiter.Gate.Locked && g3.remainingMillis == 30_000L)
        clock.advance(30_000); assertEquals(AttemptLimiter.Gate.Open, lim.gate())
        lim.recordFailure(); val g5 = lim.recordFailure()
        assertTrue(g5 is AttemptLimiter.Gate.Locked && g5.remainingMillis == 60_000L)
        repeat(7) { clock.advance(3_600_000); lim.recordFailure() }
        val g = lim.gate(); assertTrue(g is AttemptLimiter.Gate.Locked && g.remainingMillis == 3_600_000L)
        lim.recordSuccess(); assertEquals(0, lim.failures())
    }

    @Test fun lockoutSurvivesRebootAndClockRollback() {
        val store = InMemoryAttemptStore(); val clock = FakeClock()
        val lim = AttemptLimiter(store, clock); repeat(3) { lim.recordFailure() }
        // "Reboot": new limiter instance, same persisted store, monotonic clock reset.
        val clock2 = FakeClock(now = clock.now, elapsed = 0)
        val afterReboot = AttemptLimiter(store, clock2)
        assertTrue(afterReboot.gate() is AttemptLimiter.Gate.Locked)
        // Attacker sets wall clock back one day.
        clock2.now -= 86_400_000L
        val g = afterReboot.gate()
        assertTrue("rollback must not shorten lockout", g is AttemptLimiter.Gate.Locked && g.remainingMillis == 30_000L)
    }

    @Test fun biometricOnlyFallsBackToPin() {
        val r = AuthRequirements.required(AuthPolicy.BIOMETRIC_ONLY, strongBiometricUsable = false)
        assertEquals(setOf(AuthFactor.PIN), r.factors); assertTrue(r.degraded)
        val both = AuthRequirements.required(AuthPolicy.PIN_AND_BIOMETRIC, true)
        val ch = AuthChallenge(both); ch.satisfy(AuthFactor.PIN)
        assertFalse(ch.complete); ch.satisfy(AuthFactor.BIOMETRIC_STRONG); assertTrue(ch.complete)
    }
}
