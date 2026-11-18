package com.bankvault.core.threat

import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Local threat-intelligence store. Lookups walk the domain suffix chain, so listing
 * "evil.example" also matches "login.evil.example".
 */
class ThreatDatabase private constructor(
    val version: Long,
    val issuedAt: Long,
    val expiresAt: Long,
    private val entries: Map<String, Set<ThreatCategory>>,
    private val allow: Set<String>,
) {
    val size: Int get() = entries.size

    fun lookup(host: String): Set<ThreatCategory> {
        val out = mutableSetOf<ThreatCategory>()
        for (d in DomainUtils.suffixChain(host)) entries[d]?.let(out::addAll)
        return out
    }

    fun isAllowlisted(host: String): Boolean = DomainUtils.suffixChain(host).any { it in allow }

    fun isExpired(now: Long) = now >= expiresAt

    companion object {
        const val MAGIC = "BANKVAULT-THREATDB 1"
        val EMPTY = ThreatDatabase(0, 0, Long.MAX_VALUE, emptyMap(), emptySet())

        private val DOMAIN = Regex("^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9-]{2,63}$")

        /**
         * Parse an already signature-verified body. Unknown categories and malformed lines are
         * skipped (forward compatible); a wrong header is rejected.
         */
        fun parse(body: String): ThreatDatabase {
            val lines = body.lineSequence().map(String::trim).filter { it.isNotEmpty() && !it.startsWith("#") }.toList()
            require(lines.firstOrNull() == MAGIC) { "Not a BANKVAULT threat database" }
            var version = -1L; var issued = -1L; var expires = -1L
            val map = HashMap<String, MutableSet<ThreatCategory>>()
            val allow = HashSet<String>()
            for (l in lines.drop(1)) {
                val (k, v) = l.split(Regex("\\s+"), limit = 2).let { it[0].lowercase() to it.getOrElse(1) { "" }.trim().lowercase() }
                when (k) {
                    "version" -> version = v.toLong()
                    "issued" -> issued = v.toLong()
                    "expires" -> expires = v.toLong()
                    "allow" -> if (DOMAIN.matches(v)) allow += v
                    else -> {
                        val cat = ThreatCategory.entries.firstOrNull { it.name.equals(k, true) } ?: continue
                        if (DOMAIN.matches(v)) map.getOrPut(v) { mutableSetOf() } += cat
                    }
                }
            }
            require(version > 0 && issued > 0 && expires > issued) { "Missing or invalid header fields" }
            return ThreatDatabase(version, issued, expires, map, allow)
        }
    }
}

/**
 * Verifies signed threat-database updates (ECDSA P-256 / SHA-256, supported on every Android
 * version). Only public keys ship in the APK; the signing key stays with the feed publisher.
 */
class SignedFeedVerifier(private val trustedKeys: Map<String, PublicKey>) {

    sealed class Result {
        data class Accepted(val db: ThreatDatabase) : Result()
        data class Rejected(val reason: String) : Result()
    }

    /**
     * @param keyId which trusted key signed the update.
     * @param signatureB64 DER ECDSA signature over the exact UTF-8 body bytes.
     */
    fun verify(body: ByteArray, signatureB64: String, keyId: String, currentVersion: Long, now: Long): Result {
        val key = trustedKeys[keyId] ?: return Result.Rejected("Unknown signing key '$keyId'")
        val sigOk = try {
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(key); update(body); verify(Base64.getDecoder().decode(signatureB64.trim()))
            }
        } catch (e: Exception) { false }
        if (!sigOk) return Result.Rejected("Signature verification failed")
        val db = try { ThreatDatabase.parse(body.toString(Charsets.UTF_8)) } catch (e: Exception) {
            return Result.Rejected("Malformed database: ${e.message}")
        }
        if (db.version <= currentVersion) return Result.Rejected("Rollback/replay: version ${db.version} <= $currentVersion")
        if (db.isExpired(now)) return Result.Rejected("Database already expired")
        if (db.issuedAt > now + 24 * 3600_000L) return Result.Rejected("Issued in the future")
        return Result.Accepted(db)
    }

    /** Signature check only – used when re-loading an already accepted DB from local storage. */
    fun signatureValid(body: ByteArray, signatureB64: String, keyId: String): Boolean {
        val key = trustedKeys[keyId] ?: return false
        return try {
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(key); update(body); verify(Base64.getDecoder().decode(signatureB64.trim()))
            }
        } catch (e: Exception) { false }
    }

    companion object {
        fun publicKeyFromBase64(x509b64: String): PublicKey =
            KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(x509b64)))
    }
}
