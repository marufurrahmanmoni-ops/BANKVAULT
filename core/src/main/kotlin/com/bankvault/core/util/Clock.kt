package com.bankvault.core.util

/**
 * Time source abstraction so that security logic (sessions, lockouts, feed expiry)
 * is deterministic and testable.
 *
 * [nowMillis] is wall-clock time (persistable, survives reboot, but can be changed by the user).
 * [elapsedMillis] is monotonic time since boot (cannot be changed by the user, resets on reboot).
 * Security decisions that must survive reboot use wall time with roll-back detection;
 * short-lived session timers use monotonic time.
 */
interface Clock {
    fun nowMillis(): Long
    fun elapsedMillis(): Long
}

object SystemClock : Clock {
    override fun nowMillis(): Long = System.currentTimeMillis()
    override fun elapsedMillis(): Long = System.nanoTime() / 1_000_000
}

/** Manually driven clock for tests. */
class FakeClock(var now: Long = 1_700_000_000_000L, var elapsed: Long = 0L) : Clock {
    override fun nowMillis(): Long = now
    override fun elapsedMillis(): Long = elapsed
    fun advance(ms: Long) {
        now += ms
        elapsed += ms
    }
}
