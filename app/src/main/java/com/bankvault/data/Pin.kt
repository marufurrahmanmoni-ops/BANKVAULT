package com.bankvault.data

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.bankvault.core.auth.AttemptLimiter
import com.bankvault.core.auth.AttemptState
import com.bankvault.core.auth.AttemptStore
import com.bankvault.core.auth.Pbkdf2Kdf
import com.bankvault.core.auth.Pepper
import com.bankvault.core.auth.PinHasher
import com.bankvault.core.auth.PinPolicy
import com.bankvault.core.auth.PinRecord
import com.bankvault.core.util.SystemClock
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey

/**
 * PIN check: PBKDF2-SHA256 (salted) over an HMAC made with a key that never leaves the phone's
 * secure hardware (Android Keystore). Wrong attempts are rate-limited with growing delays.
 */
object Pin {
    sealed class Result {
        data object Ok : Result()
        data class Wrong(val failures: Int) : Result()
        data class Wait(val millis: Long) : Result()
    }

    private const val KEY = "bankvault_pin_pepper"

    private fun pepperKey(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(KEY, null) as? SecretKey)?.let { return it }
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore")
        kg.init(KeyGenParameterSpec.Builder(KEY, KeyProperties.PURPOSE_SIGN).setDigests(KeyProperties.DIGEST_SHA256).build())
        return kg.generateKey()
    }

    private val pepper = Pepper { input -> synchronized(this) { Mac.getInstance("HmacSHA256").run { init(pepperKey()); doFinal(input) } } }
    private val hasher by lazy { PinHasher(Pbkdf2Kdf(iterations = 120_000), pepper) }

    private val limiter by lazy {
        AttemptLimiter(object : AttemptStore {
            override fun load() = AttemptState(Store.failures, Store.lockedUntil, Store.lastEvent)
            override fun save(state: AttemptState) {
                Store.failures = state.consecutiveFailures; Store.lockedUntil = state.lockedUntilWall; Store.lastEvent = state.lastEventWall
            }
        }, SystemClock)
    }

    fun validate(pin: CharArray): String? = (PinPolicy.validate(pin) as? PinPolicy.Result.Rejected)?.reason

    /** Call off the main thread (hashing takes ~0.2 s). */
    fun set(pin: CharArray) { Store.setPinRecord(hasher.hash(pin).encode()) }

    fun waitMillis(): Long = (limiter.gate() as? AttemptLimiter.Gate.Locked)?.remainingMillis ?: 0

    /** Call off the main thread. */
    fun check(pin: CharArray): Result {
        val wait = waitMillis(); if (wait > 0) return Result.Wait(wait)
        val rec = Store.pinRecord()?.let { runCatching { PinRecord.decode(it) }.getOrNull() } ?: return Result.Wrong(0)
        return if (hasher.verify(pin, rec)) { limiter.recordSuccess(); Result.Ok }
        else when (val g = limiter.recordFailure()) {
            is AttemptLimiter.Gate.Locked -> Result.Wait(g.remainingMillis)
            AttemptLimiter.Gate.Open -> Result.Wrong(limiter.failures())
        }
    }
}
