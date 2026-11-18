package com.bankvault.core.session

import com.bankvault.core.util.Clock

enum class EndReason {
    EXPIRED, SCREEN_OFF, EMERGENCY_LOCK, INACTIVITY, REBOOT, POLICY_INVALID, MANUAL
}

data class SessionConfig(
    /** Absolute session length. Presets: 30s, 1m, 3m, 5m, 10m or custom. */
    val durationMillis: Long = 3 * 60_000L,
    /**
     * How long the protected app may stay in the background (e.g. while the owner copies an OTP
     * from SMS) before the session ends. This is BANKVAULT's "inactivity threshold": a third-party
     * app cannot observe touches inside another app, so inactivity is measured as continuous time
     * away from the protected app.
     */
    val backgroundGraceMillis: Long = 45_000L,
    val endOnScreenOff: Boolean = true,
) {
    init {
        require(durationMillis in MIN_DURATION..MAX_DURATION) { "Session duration out of range" }
        require(backgroundGraceMillis in 0..durationMillis) { "Grace must be within session duration" }
    }

    companion object {
        const val MIN_DURATION = 10_000L
        const val MAX_DURATION = 60 * 60_000L
        val PRESETS = listOf(30_000L, 60_000L, 180_000L, 300_000L, 600_000L)
    }
}

sealed class SessionState {
    data object Locked : SessionState()
    data class Active(val startedAt: Long, val expiresAt: Long, val inForeground: Boolean, val backgroundSince: Long?) : SessionState()
}

sealed class SessionEffect {
    data class Grant(val packageName: String, val expiresAtElapsed: Long) : SessionEffect()
    data class Revoke(val packageName: String, val reason: EndReason) : SessionEffect()
}

/**
 * Pure session state machine. Uses the monotonic clock: sessions never survive a reboot
 * (monotonic time resets, and [onReboot] clears everything), and changing the wall clock
 * cannot extend a session.
 *
 * The caller turns [SessionEffect]s into real actions (unsuspend/unhide, firewall allow, ...)
 * and is responsible for reporting failures – a Grant effect is a *request*, not proof.
 */
class SessionManager(private val clock: Clock, private val configFor: (String) -> SessionConfig) {
    private val sessions = linkedMapOf<String, SessionState.Active>()

    fun state(pkg: String): SessionState = sessions[pkg] ?: SessionState.Locked
    fun activePackages(): Set<String> = sessions.keys.toSet()

    /** Call only after [com.bankvault.core.auth.AuthChallenge.complete] is true for [pkg]. */
    fun onAuthenticated(pkg: String): SessionEffect.Grant {
        val now = clock.elapsedMillis()
        val cfg = configFor(pkg)
        val s = SessionState.Active(now, now + cfg.durationMillis, inForeground = true, backgroundSince = null)
        sessions[pkg] = s
        return SessionEffect.Grant(pkg, s.expiresAt)
    }

    fun onForegroundChanged(foregroundPkg: String?): List<SessionEffect> {
        val now = clock.elapsedMillis()
        for ((pkg, s) in sessions.entries.toList()) {
            val fg = pkg == foregroundPkg
            sessions[pkg] = when {
                fg -> s.copy(inForeground = true, backgroundSince = null)
                s.inForeground -> s.copy(inForeground = false, backgroundSince = now)
                else -> s
            }
        }
        return tick()
    }

    /** Evaluate timers. Call periodically (e.g. every second while any session is active). */
    fun tick(): List<SessionEffect> {
        val now = clock.elapsedMillis()
        val out = mutableListOf<SessionEffect>()
        for ((pkg, s) in sessions.entries.toList()) {
            val cfg = configFor(pkg)
            val reason = when {
                now >= s.expiresAt -> EndReason.EXPIRED
                s.backgroundSince != null && now - s.backgroundSince >= cfg.backgroundGraceMillis -> EndReason.INACTIVITY
                else -> null
            }
            if (reason != null) {
                sessions.remove(pkg)
                out += SessionEffect.Revoke(pkg, reason)
            }
        }
        return out
    }

    fun onScreenOff(): List<SessionEffect> =
        endWhere(EndReason.SCREEN_OFF) { configFor(it).endOnScreenOff }

    fun onEmergencyLock(): List<SessionEffect> = endWhere(EndReason.EMERGENCY_LOCK) { true }
    fun onReboot(): List<SessionEffect> = endWhere(EndReason.REBOOT) { true }
    fun onPolicyInvalid(): List<SessionEffect> = endWhere(EndReason.POLICY_INVALID) { true }
    fun end(pkg: String): List<SessionEffect> = endWhere(EndReason.MANUAL) { it == pkg }

    fun remainingMillis(pkg: String): Long =
        sessions[pkg]?.let { (it.expiresAt - clock.elapsedMillis()).coerceAtLeast(0) } ?: 0

    private fun endWhere(reason: EndReason, pred: (String) -> Boolean): List<SessionEffect> =
        sessions.keys.filter(pred).map { sessions.remove(it); SessionEffect.Revoke(it, reason) }
}
