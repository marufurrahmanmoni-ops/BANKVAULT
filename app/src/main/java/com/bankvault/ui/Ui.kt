package com.bankvault.ui

import android.widget.Toast
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.bankvault.CrashReporter
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob

object C {
    val Bg = Color(0xFF0B1220); val Card = Color(0xFF131C2E); val Accent = Color(0xFF3FB68B)
    val Dim = Color(0xFF93A1BC); val Warn = Color(0xFFF2A93B); val Bad = Color(0xFFE5484D)
}

@Composable
fun Theme(content: @Composable () -> Unit) = MaterialTheme(
    colorScheme = darkColorScheme(primary = C.Accent, background = C.Bg, surface = C.Card, onPrimary = Color(0xFF04140D),
        onBackground = Color(0xFFE7ECF5), onSurface = Color(0xFFE7ECF5), onSurfaceVariant = C.Dim, error = C.Bad),
    content = content,
)

@Composable
fun Dim(text: String, modifier: Modifier = Modifier) =
    Text(text, color = C.Dim, style = MaterialTheme.typography.bodySmall, modifier = modifier)

@Composable
fun Section(title: String, modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    Card(modifier.fillMaxWidth().padding(vertical = 6.dp), colors = CardDefaults.cardColors(containerColor = C.Card), shape = RoundedCornerShape(18.dp)) {
        Column(Modifier.padding(16.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium); Spacer(Modifier.height(6.dp)); content()
        }
    }
}

/** Coroutine scope whose failures show a message instead of closing the app. */
@Composable
fun rememberSafeScope(): CoroutineScope {
    val ctx = LocalContext.current.applicationContext
    val base = rememberCoroutineScope()
    return remember(base) {
        CoroutineScope(base.coroutineContext + SupervisorJob(base.coroutineContext[Job]) + CoroutineExceptionHandler { _, e ->
            CrashReporter.recordHandled(ctx, "screen action", e)
            Toast.makeText(ctx, "Something went wrong: ${e.message ?: e.javaClass.simpleName}", Toast.LENGTH_LONG).show()
        })
    }
}

/** Number pad. Digits kept in a CharArray and wiped after use. */
@Composable
fun PinPad(enabled: Boolean = true, submitLabel: String = "OK", onSubmit: (CharArray) -> Unit) {
    val buf = remember { CharArray(8) }
    var len by remember { mutableIntStateOf(0) }
    Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.padding(vertical = 14.dp)) {
            repeat(8) { i -> Box(Modifier.size(12.dp).clip(CircleShape).background(if (i < len) C.Accent else Color(0xFF2A3550))) }
        }
        for (r in listOf(listOf("1", "2", "3"), listOf("4", "5", "6"), listOf("7", "8", "9"), listOf("⌫", "0", "ok")))
            Row(horizontalArrangement = Arrangement.spacedBy(16.dp), modifier = Modifier.padding(vertical = 5.dp)) {
                for (k in r) Box(Modifier.size(70.dp), contentAlignment = Alignment.Center) {
                    when (k) {
                        "⌫" -> TextButton(enabled = enabled && len > 0, onClick = { len--; buf[len] = '\u0000' }) { Text("Delete") }
                        "ok" -> TextButton(enabled = enabled && len >= 6, onClick = {
                            val pin = buf.copyOf(len); buf.fill('\u0000'); len = 0; onSubmit(pin)
                        }) { Text(submitLabel, fontWeight = FontWeight.Bold) }
                        else -> FilledTonalButton(enabled = enabled && len < 8, onClick = { buf[len] = k[0]; len++ },
                            modifier = Modifier.size(66.dp), shape = CircleShape) { Text(k, fontSize = 22.sp) }
                    }
                }
            }
    }
}

object Fingerprint {
    fun available(a: FragmentActivity) =
        runCatching { BiometricManager.from(a).canAuthenticate(BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS }.getOrDefault(false)

    fun ask(a: FragmentActivity, title: String, onOk: () -> Unit) {
        try {
            BiometricPrompt(a, ContextCompat.getMainExecutor(a), object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = onOk()
            }).authenticate(BiometricPrompt.PromptInfo.Builder().setTitle(title)
                .setAllowedAuthenticators(BIOMETRIC_STRONG).setNegativeButtonText("Use PIN").build())
        } catch (e: Exception) { CrashReporter.recordHandled(a, "fingerprint", e) }
    }
}

fun mmss(ms: Long): String { val s = (ms + 999) / 1000; return if (s >= 60) "${s / 60} min ${s % 60} s" else "$s s" }
