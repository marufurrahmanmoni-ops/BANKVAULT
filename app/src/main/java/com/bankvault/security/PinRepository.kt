package com.bankvault.security

import com.bankvault.core.auth.AttemptLimiter
import com.bankvault.core.auth.AttemptState
import com.bankvault.core.auth.AttemptStore
import com.bankvault.core.auth.PinHasher
import com.bankvault.core.auth.PinPolicy
import com.bankvault.core.auth.PinRecord
import com.bankvault.core.util.Clock
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Stores the security PIN verifier and the separate recovery PIN verifier.
 * There is no master/developer PIN and no bypass: if both PINs are forgotten the documented
 * recovery is to remove BANKVAULT via Android Settings (docs/RECOVERY.md), which restores the
 * banking apps; the banking apps' own data and accounts are never touched.
 */
class PinRepository(private val prefs: SecurePrefs, private val hasher: PinHasher, clock: Clock) {

    enum class Kind(val key: String) { MAIN("pin_main"), RECOVERY("pin_recovery") }

    sealed class VerifyResult {
        data object Ok : VerifyResult()
        data class Wrong(val failures: Int) : VerifyResult()
        data class LockedOut(val remainingMillis: Long) : VerifyResult()
        data object NotSet : VerifyResult()
    }

    private val attemptStore = object : AttemptStore {
        override fun load() = AttemptState(
            prefs.getLong("att_fail").toInt(), prefs.getLong("att_until"), prefs.getLong("att_last"))
        override fun save(state: AttemptState) {
            prefs.putLong("att_fail", state.consecutiveFailures.toLong())
            prefs.putLong("att_until", state.lockedUntilWall)
            prefs.putLong("att_last", state.lastEventWall)
        }
    }
    val limiter = AttemptLimiter(attemptStore, clock)

    fun isSet(kind: Kind = Kind.MAIN) = prefs.getString(kind.key) != null

    suspend fun set(kind: Kind, pin: CharArray): PinPolicy.Result = withContext(Dispatchers.Default) {
        val v = PinPolicy.validate(pin)
        if (v is PinPolicy.Result.Ok) prefs.putString(kind.key, hasher.hash(pin).encode())
        v
    }

    /** Brute-force gate is shared between main and recovery PIN. */
    suspend fun verify(kind: Kind, pin: CharArray): VerifyResult = withContext(Dispatchers.Default) {
        val gate = limiter.gate()
        if (gate is AttemptLimiter.Gate.Locked) return@withContext VerifyResult.LockedOut(gate.remainingMillis)
        val rec = prefs.getString(kind.key)?.let { runCatching { PinRecord.decode(it) }.getOrNull() }
            ?: return@withContext VerifyResult.NotSet
        if (hasher.verify(pin, rec)) {
            limiter.recordSuccess()
            if (hasher.needsRehash(rec)) prefs.putString(kind.key, hasher.hash(pin).encode())
            VerifyResult.Ok
        } else {
            when (val g = limiter.recordFailure()) {
                is AttemptLimiter.Gate.Locked -> VerifyResult.LockedOut(g.remainingMillis)
                AttemptLimiter.Gate.Open -> VerifyResult.Wrong(limiter.failures())
            }
        }
    }
}
