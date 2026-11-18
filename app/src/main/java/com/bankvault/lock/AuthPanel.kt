package com.bankvault.lock

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.bankvault.AppGraph
import com.bankvault.core.audit.AuditEvent
import com.bankvault.core.audit.AuditType
import com.bankvault.core.auth.AuthChallenge
import com.bankvault.core.auth.AuthFactor
import com.bankvault.core.auth.AuthPolicy
import com.bankvault.core.auth.AuthRequirements
import com.bankvault.core.util.wipe
import com.bankvault.security.KeystoreManager
import com.bankvault.security.PinRepository
import com.bankvault.ui.BvColors
import com.bankvault.ui.Dim
import com.bankvault.ui.PinPad
import com.bankvault.ui.formatDuration
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Independent authentication UI used by both the app-lock screen and the dashboard/settings lock.
 * Enforces the configured [AuthPolicy] through core's AuthChallenge; nothing here can complete
 * a challenge without the PIN verifier and/or the Keystore-confirmed biometric.
 */
@Composable
fun AuthPanel(
    activity: FragmentActivity,
    graph: AppGraph,
    policy: AuthPolicy,
    title: String,
    subtitle: String,
    packageName: String? = null,
    onSuccess: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val bio = remember { Biometric.availability(activity) }
    var challenge by remember { mutableStateOf(AuthChallenge(AuthRequirements.required(policy, bio == Biometric.Availability.USABLE))) }
    var message by remember { mutableStateOf<String?>(null) }
    var lockedFor by remember { mutableLongStateOf(0L) }
    var busy by remember { mutableStateOf(false) }
    var tick by remember { mutableStateOf(0) }

    LaunchedEffect(lockedFor) {
        while (lockedFor > 0) { delay(1_000); lockedFor = (lockedFor - 1_000).coerceAtLeast(0) }
    }

    fun audit(type: AuditType, detail: String) = scope.launch {
        graph.audit.record(AuditEvent(type, graph.clock.nowMillis(), packageName, detail))
    }

    fun checkComplete() {
        if (challenge.complete) {
            if (bio == Biometric.Availability.REENROLLED) KeystoreManager.resetBioKey() // re-arm biometric after PIN proof
            audit(AuditType.AUTH_SUCCESS, "factors=${challenge.requirement.factors.joinToString()}")
            onSuccess()
        } else tick++
    }

    fun startBiometric() = Biometric.authenticate(activity, title, subtitle) { ok, err ->
        if (ok) { challenge.satisfy(AuthFactor.BIOMETRIC_STRONG); checkComplete() }
        else {
            if (err != null) message = err
            // "Biometric only" always keeps a PIN fallback; "PIN + biometric" stays two-factor (use recovery if biometric is broken).
            if (policy == AuthPolicy.BIOMETRIC_ONLY && AuthFactor.PIN !in challenge.requirement.factors) {
                challenge = AuthChallenge(AuthRequirements.Requirement(setOf(AuthFactor.PIN), degraded = true, reason = "Biometric not used – enter your BANKVAULT PIN"))
            }
        }
    }

    LaunchedEffect(Unit) {
        val st = graph.pins.limiter.gate()
        if (st is com.bankvault.core.auth.AttemptLimiter.Gate.Locked) lockedFor = st.remainingMillis
        if (AuthFactor.BIOMETRIC_STRONG in challenge.requirement.factors && lockedFor == 0L) startBiometric()
    }

    Column(Modifier.fillMaxWidth().padding(16.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        Text(title, style = MaterialTheme.typography.headlineSmall, textAlign = TextAlign.Center)
        Spacer(Modifier.height(4.dp))
        Dim(subtitle)
        challenge.requirement.reason?.let { Spacer(Modifier.height(6.dp)); Text(it, color = BvColors.Warning, style = MaterialTheme.typography.bodySmall) }
        if (bio == Biometric.Availability.REENROLLED) Text("A new fingerprint/face was enrolled on this phone. Enter your BANKVAULT PIN to re-enable biometric unlock.",
            color = BvColors.Warning, style = MaterialTheme.typography.bodySmall, textAlign = TextAlign.Center)
        if (tick > 0 && !challenge.complete) Text("Now complete: ${challenge.remaining.joinToString { if (it == AuthFactor.PIN) "PIN" else "biometric" }}",
            style = MaterialTheme.typography.bodySmall)
        if (lockedFor > 0) Text("Too many wrong attempts. Try again in ${formatDuration(lockedFor)}.", color = BvColors.Bad)
        message?.let { Text(it, color = BvColors.Warning, style = MaterialTheme.typography.bodySmall) }

        if (AuthFactor.PIN in challenge.remaining) {
            PinPad(enabled = lockedFor == 0L && !busy) { pin ->
                busy = true
                scope.launch {
                    val r = graph.pins.verify(PinRepository.Kind.MAIN, pin); pin.wipe()
                    busy = false
                    when (r) {
                        PinRepository.VerifyResult.Ok -> { challenge.satisfy(AuthFactor.PIN); message = null; checkComplete() }
                        is PinRepository.VerifyResult.Wrong -> { message = "Wrong PIN (${r.failures} failed)"; audit(AuditType.AUTH_FAILURE, "wrong PIN #${r.failures}") }
                        is PinRepository.VerifyResult.LockedOut -> { lockedFor = r.remainingMillis; audit(AuditType.AUTH_LOCKOUT, "locked ${r.remainingMillis / 1000}s") }
                        PinRepository.VerifyResult.NotSet -> message = "No PIN configured"
                    }
                }
            }
        }
        if (AuthFactor.BIOMETRIC_STRONG in challenge.remaining) {
            Spacer(Modifier.height(8.dp))
            OutlinedButton(enabled = lockedFor == 0L, onClick = { startBiometric() }) {
                Icon(Icons.Filled.Fingerprint, null); Spacer(Modifier.padding(4.dp)); Text("Use biometric")
            }
        }
    }
}
