package com.bankvault.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.bankvault.AppGraph
import com.bankvault.core.auth.PinPolicy
import com.bankvault.core.util.wipe
import com.bankvault.security.PinRepository
import kotlinx.coroutines.launch

/**
 * Owner-controlled recovery of a forgotten BANKVAULT PIN using the separate recovery PIN.
 * Shares the same brute-force limiter as the main PIN. There is no other bypass.
 */
@Composable
fun ForgotPinScreen(graph: AppGraph, onDone: () -> Unit) {
    val scope = rememberCoroutineScope()
    var stage by remember { mutableIntStateOf(0) }
    var first by remember { mutableStateOf<CharArray?>(null) }
    var msg by remember { mutableStateOf<String?>(null) }
    Column(Modifier.fillMaxSize().padding(20.dp)) {
        Text("Reset BANKVAULT PIN", style = MaterialTheme.typography.headlineSmall)
        Dim(when (stage) { 0 -> "Enter your recovery PIN"; 1 -> "Choose a new BANKVAULT PIN"; else -> "Repeat the new PIN" })
        msg?.let { Text(it, color = BvColors.Warning) }
        PinPad(submitLabel = "Next") { pin -> scope.launch {
            when (stage) {
                0 -> when (val r = graph.pins.verify(PinRepository.Kind.RECOVERY, pin)) {
                    PinRepository.VerifyResult.Ok -> { stage = 1; msg = null; graph.recordRecovery("Recovery PIN used to reset main PIN") }
                    is PinRepository.VerifyResult.LockedOut -> msg = "Too many attempts. Try again in ${formatDuration(r.remainingMillis)}."
                    PinRepository.VerifyResult.NotSet -> msg = "No recovery PIN was set. See docs/RECOVERY.md (uninstall via Android Settings)."
                    is PinRepository.VerifyResult.Wrong -> msg = "Wrong recovery PIN"
                }
                1 -> when (val v = PinPolicy.validate(pin)) {
                    PinPolicy.Result.Ok -> { first = pin.copyOf(); stage = 2; msg = null }
                    is PinPolicy.Result.Rejected -> msg = v.reason
                }
                else -> {
                    val f = first
                    if (f != null && f.contentEquals(pin)) { graph.pins.set(PinRepository.Kind.MAIN, pin); f.wipe(); first = null; onDone() }
                    else { msg = "PINs do not match"; stage = 1; f?.wipe(); first = null }
                }
            }
            pin.wipe()
        } }
        TextButton(onClick = onDone) { Text("Cancel") }
    }
}
