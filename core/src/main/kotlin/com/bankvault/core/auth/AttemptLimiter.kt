package com.bankvault.core.auth

import com.bankvault.core.util.Clock

/** Persisted brute-force state. Must be stored encrypted and survive reboot. */
data class AttemptState(
    val consecutiveFailures: Int = 0,
    val lockedUntilWall: Long = 0L,
    val lastEventWall: Long = 0L,
)

interface AttemptStore {
    fun load(): AttemptState
    fun save(state: AttemptState)
}

class InMemoryAttemptStore(private var s: AttemptState = AttemptState()) : AttemptStore {
    override fun load() = s
    override fun save(state: AttemptState) { s = state }
}

/**
 * Progressive delays against PIN guessing.
 *
 * Reboot does not reset the counter (it is persisted). Setting the clock backwards does not
 * shorten a lockout: if the wall clock is earlier than the last recorded event we keep the
 * remaining lockout measured from that event.
 */
class AttemptLimiter(
    private val store: AttemptStore,
    private val clock: Clock,
    private val schedule: List<Pair<Int, Long>> = DEFAULT_SCHEDULE,
) {
    sealed class Gate {
        data object Open : Gate()
        data class Locked(val remainingMillis: Long) : Gate()
    }

    fun gate(): Gate {
        val st = store.load()
        val now = clock.nowMillis()
        if (st.lockedUntilWall == 0L) return Gate.Open
        val effectiveNow = if (now < st.lastEventWall) st.lastEventWall else now // clock rollback guard
        val remaining = st.lockedUntilWall - effectiveNow
        return if (remaining > 0) Gate.Locked(remaining) else Gate.Open
    }

    fun recordFailure(): Gate {
        val st = store.load()
        val now = maxOf(clock.nowMillis(), st.lastEventWall)
        val failures = st.consecutiveFailures + 1
        val delay = delayFor(failures)
        store.save(AttemptState(failures, if (delay > 0) now + delay else 0L, now))
        return gate()
    }

    fun recordSuccess() {
        store.save(AttemptState(0, 0L, maxOf(clock.nowMillis(), store.load().lastEventWall)))
    }

    fun failures(): Int = store.load().consecutiveFailures

    internal fun delayFor(failures: Int): Long =
        schedule.lastOrNull { failures >= it.first }?.second ?: 0L

    companion object {
        /** failures-threshold -> lockout length */
        val DEFAULT_SCHEDULE = listOf(
            3 to 30_000L,
            5 to 60_000L,
            7 to 5 * 60_000L,
            10 to 15 * 60_000L,
            12 to 60 * 60_000L,
        )
    }
}
