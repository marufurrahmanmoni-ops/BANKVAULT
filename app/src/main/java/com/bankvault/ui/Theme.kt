package com.bankvault.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import com.bankvault.core.status.ProtectionStatus
import com.bankvault.core.status.StatusTone

object BvColors {
    val Background = Color(0xFF0B1220)
    val Surface = Color(0xFF131C2E)
    val SurfaceHigh = Color(0xFF1B2640)
    val Accent = Color(0xFF3FB68B)
    val TextDim = Color(0xFF93A1BC)
    // Status tones. GOOD (green) is only ever used for VERIFIED protection – see ProtectionStatus.
    val Good = Color(0xFF2FBF71)
    val Neutral = Color(0xFF7C8DB5)
    val Warning = Color(0xFFF2A93B)
    val Bad = Color(0xFFE5484D)
}

fun ProtectionStatus.color(): Color = when (tone) {
    StatusTone.GOOD -> BvColors.Good
    StatusTone.NEUTRAL -> BvColors.Neutral
    StatusTone.WARNING -> BvColors.Warning
    StatusTone.BAD -> BvColors.Bad
}

@Composable
fun BankVaultTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = BvColors.Accent,
            onPrimary = Color(0xFF04140D),
            background = BvColors.Background,
            surface = BvColors.Surface,
            surfaceVariant = BvColors.SurfaceHigh,
            onBackground = Color(0xFFE7ECF5),
            onSurface = Color(0xFFE7ECF5),
            onSurfaceVariant = BvColors.TextDim,
            error = BvColors.Bad,
        ),
        content = content,
    )
}
