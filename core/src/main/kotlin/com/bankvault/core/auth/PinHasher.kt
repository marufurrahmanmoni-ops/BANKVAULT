package com.bankvault.core.auth

import com.bankvault.core.util.b64
import com.bankvault.core.util.unb64
import com.bankvault.core.util.wipe
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * Device-bound secret applied to the PIN before the slow hash.
 * On Android this is an HMAC-SHA256 key that lives inside Android Keystore (non-exportable),
 * so a copied database cannot be brute-forced off-device: a 6-digit PIN only has 10^6 values,
 * and the slow hash alone is not enough to protect such a small space.
 */
fun interface Pepper {
    fun apply(input: ByteArray): ByteArray
}

/** Stored PIN verifier. Never contains the PIN itself. */
data class PinRecord(
    val algorithm: String,
    val params: String,
    val salt: ByteArray,
    val hash: ByteArray,
) {
    fun encode(): String = listOf(algorithm, params, salt.b64(), hash.b64()).joinToString("$")

    companion object {
        fun decode(s: String): PinRecord {
            val p = s.split("$")
            require(p.size == 4) { "Malformed PIN record" }
            return PinRecord(p[0], p[1], p[2].unb64(), p[3].unb64())
        }
    }

    override fun equals(other: Any?): Boolean =
        other is PinRecord && algorithm == other.algorithm && params == other.params &&
            salt.contentEquals(other.salt) && hash.contentEquals(other.hash)

    override fun hashCode(): Int = algorithm.hashCode() * 31 + hash.contentHashCode()
}

/** A slow, salted key-derivation function. */
interface Kdf {
    val algorithm: String
    val params: String
    fun derive(secret: ByteArray, salt: ByteArray, params: String): ByteArray
}

/**
 * PBKDF2-HMAC-SHA256, available in every JVM and Android. Used for JVM tests and as a fallback.
 * The Android app uses Argon2id (BouncyCastle) via [Kdf] – see app/.../auth/Argon2idKdf.kt.
 */
class Pbkdf2Kdf(private val iterations: Int = 600_000) : Kdf {
    override val algorithm = "pbkdf2-sha256"
    override val params = "i=$iterations"

    override fun derive(secret: ByteArray, salt: ByteArray, params: String): ByteArray {
        val iter = params.removePrefix("i=").toInt()
        // PBEKeySpec wants chars; hex-encode the (peppered) bytes so no information is lost.
        val chars = secret.joinToString("") { "%02x".format(it) }.toCharArray()
        val spec = PBEKeySpec(chars, salt, iter, 256)
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
            chars.wipe()
        }
    }
}

class PinHasher(
    private val kdf: Kdf,
    private val pepper: Pepper,
    private val random: SecureRandom = SecureRandom(),
) {
    fun hash(pin: CharArray): PinRecord {
        require(PinPolicy.validate(pin) is PinPolicy.Result.Ok) { "PIN violates policy" }
        val salt = ByteArray(16).also(random::nextBytes)
        return PinRecord(kdf.algorithm, kdf.params, salt, derive(pin, salt, kdf.params))
    }

    fun verify(pin: CharArray, record: PinRecord): Boolean {
        if (record.algorithm != kdf.algorithm) return false
        val candidate = derive(pin, record.salt, record.params)
        return try {
            MessageDigest.isEqual(candidate, record.hash) // constant time
        } finally {
            candidate.wipe()
        }
    }

    /** True when a stored record uses weaker parameters and should be re-hashed after a successful unlock. */
    fun needsRehash(record: PinRecord): Boolean =
        record.algorithm != kdf.algorithm || record.params != kdf.params

    private fun derive(pin: CharArray, salt: ByteArray, params: String): ByteArray {
        val raw = ByteArray(pin.size) { pin[it].code.toByte() }
        val peppered = pepper.apply(raw)
        raw.wipe()
        return try {
            kdf.derive(peppered, salt, params)
        } finally {
            peppered.wipe()
        }
    }
}
