package com.bankvault.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.bankvault.AppGraph
import com.bankvault.core.audit.AuditEvent
import com.bankvault.core.audit.AuditType
import com.bankvault.core.auth.PinPolicy
import com.bankvault.core.util.wipe
import com.bankvault.security.PinRepository
import kotlinx.coroutines.launch

/** Step 0 intro, 1 set PIN, 2 confirm, 3 recovery PIN, 4 confirm recovery, 5 done. */
@Composable
fun OnboardingScreen(activity: FragmentActivity, graph: AppGraph, onDone: () -> Unit) {
    var step by remember { mutableIntStateOf(0) }
    var first by remember { mutableStateOf<CharArray?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberSafeScope()

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp)) {
        Text("BANKVAULT", style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(8.dp))
        when (step) {
            0 -> {
                Text("A separate lock for your banking apps, independent of your phone's screen lock.")
                Spacer(Modifier.height(12.dp))
                Dim("What BANKVAULT can and cannot do on this phone is shown honestly on the dashboard. " +
                    "Nothing is reported as protected until it has been applied and checked. " +
                    "No PIN, OTP, password or banking screen is ever collected. Everything stays on this device.")
                Spacer(Modifier.height(16.dp))
                Button(onClick = { step = 1 }) { Text("Set up security PIN") }
            }
            1, 2, 3, 4 -> {
                val recovery = step >= 3
                Text(when (step) {
                    1 -> "Choose a 6–8 digit BANKVAULT PIN"
                    2 -> "Enter the PIN again"
                    3 -> "Choose a separate RECOVERY PIN (write it down and keep it offline)"
                    else -> "Enter the recovery PIN again"
                }, style = MaterialTheme.typography.titleMedium)
                Dim("Do not reuse your phone's screen-lock PIN or any banking PIN.")
                error?.let { Text(it, color = BvColors.Bad) }
                PinPad(submitLabel = "Next") { pin ->
                    if (step == 1 || step == 3) {
                        when (val v = PinPolicy.validate(pin)) {
                            is PinPolicy.Result.Rejected -> { error = v.reason; pin.wipe() }
                            PinPolicy.Result.Ok -> { first = pin; error = null; step++ }
                        }
                    } else {
                        val a = first
                        if (a == null || !a.contentEquals(pin)) { error = "PINs do not match"; a?.wipe(); first = null; step--; pin.wipe() }
                        else scope.launch {
                            val kind = if (recovery) PinRepository.Kind.RECOVERY else PinRepository.Kind.MAIN
                            graph.pins.set(kind, pin); a.wipe(); pin.wipe(); first = null; error = null
                            graph.audit.record(AuditEvent(AuditType.SETTINGS_CHANGED, graph.clock.nowMillis(), null, "${kind.name} PIN set"))
                            step++
                        }
                    }
                }
            }
            else -> {
                Text("PINs saved.", style = MaterialTheme.typography.titleMedium)
                Dim("Next: choose your banking apps and grant the permissions BANKVAULT needs. Each permission is explained before Android asks for it.")
                Spacer(Modifier.height(16.dp))
                Button(onClick = onDone) { Text("Open dashboard") }
            }
        }
    }
}
