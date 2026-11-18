package com.bankvault.core.auth

enum class AuthFactor { PIN, BIOMETRIC_STRONG }

enum class AuthPolicy { PIN_ONLY, BIOMETRIC_ONLY, PIN_AND_BIOMETRIC }

/**
 * Decides which factors a given unlock requires.
 *
 * BIOMETRIC_ONLY falls back to PIN when no Class 3 (strong) biometric is enrolled/available or
 * when the biometric was re-enrolled (Keystore key invalidated) – the owner is never locked out.
 * PIN_AND_BIOMETRIC without an available biometric degrades to PIN and the caller must surface
 * this as a DEGRADED status rather than silently pretending two factors were used.
 */
object AuthRequirements {
    data class Requirement(val factors: Set<AuthFactor>, val degraded: Boolean, val reason: String? = null)

    fun required(policy: AuthPolicy, strongBiometricUsable: Boolean): Requirement = when (policy) {
        AuthPolicy.PIN_ONLY -> Requirement(setOf(AuthFactor.PIN), false)
        AuthPolicy.BIOMETRIC_ONLY ->
            if (strongBiometricUsable) Requirement(setOf(AuthFactor.BIOMETRIC_STRONG), false)
            else Requirement(setOf(AuthFactor.PIN), true, "Strong biometric unavailable – PIN fallback")
        AuthPolicy.PIN_AND_BIOMETRIC ->
            if (strongBiometricUsable) Requirement(setOf(AuthFactor.PIN, AuthFactor.BIOMETRIC_STRONG), false)
            else Requirement(setOf(AuthFactor.PIN), true, "Strong biometric unavailable – PIN only")
    }
}

/** Collects factors for one unlock attempt. */
class AuthChallenge(val requirement: AuthRequirements.Requirement) {
    private val satisfied = mutableSetOf<AuthFactor>()
    fun satisfy(f: AuthFactor) { if (f in requirement.factors) satisfied += f }
    val complete: Boolean get() = satisfied.containsAll(requirement.factors)
    val remaining: Set<AuthFactor> get() = requirement.factors - satisfied
}
