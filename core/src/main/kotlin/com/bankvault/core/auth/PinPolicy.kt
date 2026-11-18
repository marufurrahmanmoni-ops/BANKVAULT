package com.bankvault.core.auth

/** Rules for the BANKVAULT security PIN (independent of the phone's screen-lock PIN). */
object PinPolicy {
    const val MIN_LENGTH = 6
    const val MAX_LENGTH = 8

    sealed class Result {
        data object Ok : Result()
        data class Rejected(val reason: String) : Result()
    }

    fun validate(pin: CharArray): Result {
        if (pin.size !in MIN_LENGTH..MAX_LENGTH) {
            return Result.Rejected("PIN must be $MIN_LENGTH to $MAX_LENGTH digits")
        }
        if (!pin.all { it in '0'..'9' }) return Result.Rejected("PIN must contain digits only")
        if (pin.all { it == pin[0] }) return Result.Rejected("PIN must not repeat a single digit")
        if (isSequential(pin, +1) || isSequential(pin, -1)) {
            return Result.Rejected("PIN must not be a simple ascending or descending sequence")
        }
        return Result.Ok
    }

    private fun isSequential(pin: CharArray, step: Int): Boolean =
        (1 until pin.size).all { (pin[it] - pin[it - 1]) == step }
}
