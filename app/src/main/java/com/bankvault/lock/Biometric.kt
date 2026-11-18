package com.bankvault.lock

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.bankvault.security.KeystoreManager

object Biometric {
    enum class Availability { USABLE, NOT_ENROLLED, NO_HARDWARE, REENROLLED }

    fun availability(ctx: Context): Availability {
        return when (BiometricManager.from(ctx).canAuthenticate(BIOMETRIC_STRONG)) {
            BiometricManager.BIOMETRIC_SUCCESS ->
                if (KeystoreManager.isBioKeyInvalidated()) Availability.REENROLLED else Availability.USABLE
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> Availability.NOT_ENROLLED
            else -> Availability.NO_HARDWARE
        }
    }

    /**
     * Class 3 (strong) biometric bound to a Keystore key through a CryptoObject. Success is only
     * accepted if the Keystore actually lets us use the key, i.e. the TEE confirmed the biometric.
     * Device credential (the phone's screen-lock PIN) is deliberately NOT allowed as fallback –
     * the fallback is BANKVAULT's own PIN.
     */
    fun authenticate(activity: FragmentActivity, title: String, subtitle: String, onResult: (Boolean, String?) -> Unit) {
        val cipher = KeystoreManager.bioCipherForEncrypt() ?: return onResult(false, "Biometric key unavailable – use your BANKVAULT PIN")
        val prompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val ok = runCatching { result.cryptoObject?.cipher?.doFinal(byteArrayOf(1)) != null }.getOrDefault(false)
                onResult(ok, if (ok) null else "Biometric could not be confirmed by the secure hardware")
            }
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) = onResult(false, errString.toString())
            override fun onAuthenticationFailed() { /* prompt stays open, user may retry */ }
        })
        prompt.authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle(title).setSubtitle(subtitle)
                .setAllowedAuthenticators(BIOMETRIC_STRONG)
                .setNegativeButtonText("Use BANKVAULT PIN")
                .setConfirmationRequired(false)
                .build(),
            BiometricPrompt.CryptoObject(cipher),
        )
    }
}
