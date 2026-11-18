package com.bankvault.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.bankvault.core.auth.Pepper
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * All BANKVAULT keys live in AndroidKeyStore, are non-exportable, and are StrongBox-backed when
 * the device has a StrongBox secure element (falls back to TEE otherwise).
 *
 *  - PEPPER_KEY  HMAC-SHA256 applied to the PIN before Argon2id. Makes an extracted DB useless.
 *  - DATA_KEY    AES-256-GCM for settings, audit log details and attempt counters.
 *  - BIO_KEY     AES-256-GCM, requires BIOMETRIC_STRONG for every use and is invalidated when a
 *                new biometric is enrolled (re-enrolment detection).
 */
object KeystoreManager {
    private const val STORE = "AndroidKeyStore"
    private const val PEPPER_KEY = "bv_pepper_v1"
    private const val DATA_KEY = "bv_data_v1"
    const val BIO_KEY = "bv_bio_v1"

    private val ks: KeyStore get() = KeyStore.getInstance(STORE).apply { load(null) }

    val pepper: Pepper = Pepper { input ->
        Mac.getInstance("HmacSHA256").run { init(pepperKey()); doFinal(input) }
    }

    private fun pepperKey(): SecretKey = (ks.getKey(PEPPER_KEY, null) as? SecretKey)
        ?: generate(KeyProperties.KEY_ALGORITHM_HMAC_SHA256) {
            KeyGenParameterSpec.Builder(PEPPER_KEY, KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
        }

    private fun dataKey(): SecretKey = (ks.getKey(DATA_KEY, null) as? SecretKey)
        ?: generate(KeyProperties.KEY_ALGORITHM_AES) {
            KeyGenParameterSpec.Builder(DATA_KEY, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
        }

    /** Generate with StrongBox when present, otherwise TEE. */
    @Synchronized
    private fun generate(algorithm: String, spec: () -> KeyGenParameterSpec.Builder): SecretKey {
        val kg = KeyGenerator.getInstance(algorithm, STORE)
        return try {
            kg.init(spec().setIsStrongBoxBacked(true).build()); kg.generateKey()
        } catch (_: Exception) {
            kg.init(spec().build()); kg.generateKey()
        }
    }

    fun encrypt(plain: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding"); c.init(Cipher.ENCRYPT_MODE, dataKey())
        return c.iv + c.doFinal(plain)
    }

    fun decrypt(blob: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, dataKey(), GCMParameterSpec(128, blob, 0, 12))
        return c.doFinal(blob, 12, blob.size - 12)
    }

    // ---- Biometric-bound key ----

    fun bioCipherForEncrypt(): Cipher? = try {
        Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, bioKey()) }
    } catch (e: android.security.keystore.KeyPermanentlyInvalidatedException) {
        // New fingerprint enrolled since setup: refuse biometric, require PIN, then re-create key.
        null
    } catch (e: Exception) {
        null // no strong biometric enrolled yet, or keystore error: caller falls back to PIN
    }

    fun isBioKeyInvalidated(): Boolean = bioCipherForEncrypt() == null

    fun resetBioKey() { ks.deleteEntry(BIO_KEY) }

    private fun bioKey(): SecretKey = (ks.getKey(BIO_KEY, null) as? SecretKey)
        ?: generate(KeyProperties.KEY_ALGORITHM_AES) {
            KeyGenParameterSpec.Builder(BIO_KEY, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                .setInvalidatedByBiometricEnrollment(true)
        }
}
