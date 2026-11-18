package com.bankvault.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.bankvault.BuildConfig
import com.bankvault.R

const val DEVELOPER_NAME = "Md. Marufur Rahman Moni"

@Composable
fun AboutCard() {
    SectionCard("About") {
        Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
            Image(
                painter = painterResource(R.drawable.developer_photo),
                contentDescription = "Photo of $DEVELOPER_NAME",
                contentScale = ContentScale.Crop,
                modifier = Modifier
                    .size(120.dp)
                    .clip(CircleShape)
                    .border(3.dp, MaterialTheme.colorScheme.primary, CircleShape),
            )
            Spacer(Modifier.height(12.dp))
            Text(DEVELOPER_NAME, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold, textAlign = TextAlign.Center)
            Dim("Developer")
            Spacer(Modifier.height(12.dp))
            Text("BANKVAULT", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.primary)
            Dim("Version ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})")
            Spacer(Modifier.height(6.dp))
            Dim("Banking app protection for Android. Everything stays on this device – no PINs, OTPs or banking data are ever collected.")
        }
    }
}
