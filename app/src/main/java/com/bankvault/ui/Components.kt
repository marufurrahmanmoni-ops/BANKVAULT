package com.bankvault.ui

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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Backspace
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.bankvault.core.auth.PinPolicy
import com.bankvault.core.status.ProtectionStatus

@Composable
fun StatusChip(status: ProtectionStatus, modifier: Modifier = Modifier) {
    Row(
        modifier
            .clip(RoundedCornerShape(50))
            .background(status.color().copy(alpha = 0.16f))
            .padding(horizontal = 10.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(Modifier.size(8.dp).clip(CircleShape).background(status.color()))
        Spacer(Modifier.width(6.dp))
        Text(status.label, color = status.color(), fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
fun SectionCard(title: String, status: ProtectionStatus? = null, modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    Card(
        modifier.fillMaxWidth().padding(vertical = 6.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        shape = RoundedCornerShape(18.dp),
    ) {
        Column(Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(title, style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                if (status != null) StatusChip(status)
            }
            Spacer(Modifier.height(8.dp))
            content()
        }
    }
}

@Composable
fun Dim(text: String, modifier: Modifier = Modifier) =
    Text(text, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall, modifier = modifier)

/**
 * Numeric PIN pad. Digits are kept in a CharArray (not a String) and wiped after submission.
 * No copy/paste, no system keyboard (so keyboard apps never see the PIN).
 */
@Composable
fun PinPad(
    maxLength: Int = PinPolicy.MAX_LENGTH,
    minLength: Int = PinPolicy.MIN_LENGTH,
    enabled: Boolean = true,
    submitLabel: String = "Unlock",
    onSubmit: (CharArray) -> Unit,
) {
    val buf = remember { CharArray(PinPolicy.MAX_LENGTH) }
    var len by remember { mutableIntStateOf(0) }
    Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.padding(vertical = 16.dp)) {
            repeat(maxLength) { i ->
                Box(Modifier.size(14.dp).clip(CircleShape).background(
                    if (i < len) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surfaceVariant))
            }
        }
        val rows = listOf(listOf("1", "2", "3"), listOf("4", "5", "6"), listOf("7", "8", "9"), listOf("del", "0", "ok"))
        for (r in rows) Row(horizontalArrangement = Arrangement.spacedBy(18.dp), modifier = Modifier.padding(vertical = 6.dp)) {
            for (k in r) Box(Modifier.size(72.dp), contentAlignment = Alignment.Center) {
                when (k) {
                    "del" -> IconButton(enabled = enabled && len > 0, onClick = { len--; buf[len] = '\u0000' }) {
                        Icon(Icons.AutoMirrored.Filled.Backspace, contentDescription = "Delete")
                    }
                    "ok" -> TextButton(enabled = enabled && len >= minLength, onClick = {
                        val pin = buf.copyOf(len); buf.fill('\u0000'); len = 0; onSubmit(pin)
                    }) { Text(submitLabel, fontWeight = FontWeight.Bold) }
                    else -> FilledTonalButton(enabled = enabled && len < maxLength, onClick = { buf[len] = k[0]; len++ },
                        modifier = Modifier.size(68.dp), shape = CircleShape) { Text(k, fontSize = 22.sp) }
                }
            }
        }
    }
}

fun formatDuration(ms: Long): String {
    val s = (ms / 1000).coerceAtLeast(0)
    return when {
        s >= 60 && s % 60 == 0L -> "${s / 60} min"
        s >= 60 -> "${s / 60} min ${s % 60} s"
        else -> "$s s"
    }
}
