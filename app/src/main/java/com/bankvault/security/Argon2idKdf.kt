package com.bankvault.security

import com.bankvault.core.auth.Kdf
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters

/**
 * Argon2id via BouncyCastle (pure Java, no native code).
 * Defaults: 64 MiB, 3 passes, 1 lane – roughly 0.3–0.8 s on 2023+ mid-range phones.
 * Combined with the Keystore pepper this makes offline guessing infeasible and online guessing
 * is capped by [com.bankvault.core.auth.AttemptLimiter].
 */
class Argon2idKdf(
    private val memoryKiB: Int = 64 * 1024,
    private val iterations: Int = 3,
    private val parallelism: Int = 1,
) : Kdf {
    override val algorithm = "argon2id"
    override val params = "m=$memoryKiB,t=$iterations,p=$parallelism"

    override fun derive(secret: ByteArray, salt: ByteArray, params: String): ByteArray {
        val kv = params.split(',').associate { it.substringBefore('=') to it.substringAfter('=').toInt() }
        val p = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withMemoryAsKB(kv.getValue("m"))
            .withIterations(kv.getValue("t"))
            .withParallelism(kv.getValue("p"))
            .withSalt(salt)
            .build()
        val out = ByteArray(32)
        Argon2BytesGenerator().apply { init(p) }.generateBytes(secret, out)
        return out
    }
}
