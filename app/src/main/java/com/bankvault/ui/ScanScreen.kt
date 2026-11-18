package com.bankvault.ui

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.bankvault.AppGraph
import com.bankvault.ClipboardGuard
import com.bankvault.core.threat.UrlAnalyzer
import com.bankvault.core.threat.UrlNormalizer
import com.bankvault.core.threat.UrlReport
import com.bankvault.core.threat.Verdict
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL

fun Verdict.color(): Color = when (this) {
    Verdict.SAFE -> BvColors.Good
    Verdict.UNKNOWN -> BvColors.Neutral
    Verdict.SUSPICIOUS -> BvColors.Warning
    Verdict.CONFIRMED_MALICIOUS -> BvColors.Bad
}

fun Verdict.label(): String = when (this) {
    Verdict.SAFE -> "Safe (verified)"
    Verdict.UNKNOWN -> "Unknown – not verified"
    Verdict.SUSPICIOUS -> "Suspicious"
    Verdict.CONFIRMED_MALICIOUS -> "Confirmed malicious"
}

/**
 * Expands a short link by asking ONLY the shortener for its redirect (HEAD, redirects not
 * followed). The final destination is never contacted. Stops at the first non-shortener hop.
 */
suspend fun expandShortLink(url: String): List<String> = withContext(Dispatchers.IO) {
    val chain = mutableListOf(url)
    var current = url
    repeat(5) {
        val p = UrlNormalizer.parse(current) ?: return@withContext chain
        val reg = com.bankvault.core.threat.DomainUtils.registrable(p.host)
        if (reg !in UrlAnalyzer.SHORTENERS || p.scheme != "https") return@withContext chain
        val c = (URL(current).openConnection() as HttpURLConnection).apply {
            instanceFollowRedirects = false; requestMethod = "HEAD"; connectTimeout = 8_000; readTimeout = 8_000
        }
        val loc = (try { c.getHeaderField("Location") } finally { c.disconnect() }) ?: return@withContext chain
        current = URL(URL(current), loc).toString(); chain += current
    }
    chain
}

@Composable
fun ScanScreen(graph: AppGraph, initialText: String?, source: String = "manual") {
    val ctx = LocalContext.current
    val scope = rememberSafeScope()
    var input by remember { mutableStateOf(initialText ?: "") }
    var report by remember { mutableStateOf<UrlReport?>(null) }
    var chain by remember { mutableStateOf<List<String>>(emptyList()) }
    var confirmOpen by remember { mutableStateOf(false) }
    var info by remember { mutableStateOf<String?>(null) }
    val history by graph.db.scans().observe().collectAsStateWithLifecycle(emptyList())

    fun scan(text: String, src: String) = scope.launch { chain = emptyList(); report = graph.threats.scan(text, src) }
    LaunchedEffect(initialText) { if (!initialText.isNullOrBlank()) scan(initialText, source) }

    LazyColumn(Modifier.fillMaxSize().padding(16.dp)) {
        item {
            Text("Link & QR scanner", style = MaterialTheme.typography.headlineSmall)
            Dim("Checks links offline against BANKVAULT's threat database and phishing heuristics. Links are never opened automatically. Only the address without its parameters is kept in history.")
            OutlinedTextField(input, { input = it }, label = { Text("Paste a link or message") }, modifier = Modifier.fillMaxWidth())
            Row {
                Button(onClick = { scan(input, "paste") }, enabled = input.isNotBlank()) { Text("Scan") }
                Spacer(Modifier.padding(4.dp))
                OutlinedButton(onClick = {
                    GmsBarcodeScanning.getClient(ctx).startScan()
                        .addOnSuccessListener { code -> code.rawValue?.let { input = it; scan(it, "qr") } }
                        .addOnFailureListener { info = "QR scanner unavailable on this device" }
                }) { Icon(Icons.Filled.QrCodeScanner, null); Text(" Scan QR") }
            }
            info?.let { Dim(it) }
        }
        report?.let { r ->
            item {
                SectionCard("Result") {
                    Text(r.verdict.label(), color = r.verdict.color(), fontWeight = FontWeight.Bold, style = MaterialTheme.typography.titleLarge)
                    r.unicodeHost?.let { h -> Text(if (h != r.host) "$h  (${r.host})" else h) }
                    r.sanitized?.let { Dim(it) }
                    Spacer(Modifier.height(6.dp))
                    r.findings.forEach { f -> Text("• ${f.explanation}", style = MaterialTheme.typography.bodyMedium) }
                    if (chain.size > 1) { Spacer(Modifier.height(6.dp)); Dim("Redirect chain:"); chain.forEach { Dim("→ $it") } }
                    Spacer(Modifier.height(8.dp))
                    Row {
                        if (r.findings.any { it.code == "SHORTENER" }) TextButton(onClick = { scope.launch {
                            chain = runCatching { expandShortLink(r.sanitized ?: r.input) }.getOrDefault(emptyList())
                            chain.lastOrNull()?.takeIf { chain.size > 1 }?.let { report = graph.threats.scan(it, "expanded") }
                        } }) { Text("Expand short link") }
                        when (r.verdict) {
                            Verdict.SAFE -> TextButton(onClick = { open(ctx, r.sanitized) }) { Text("Open") }
                            Verdict.UNKNOWN -> TextButton(onClick = { confirmOpen = true }) { Text("Open anyway…") }
                            else -> TextButton(onClick = { r.sanitized?.let { ClipboardGuard.copy(ctx, it) } }) { Text("Copy (for reporting)") }
                        }
                    }
                    r.host?.let { host -> Row {
                        TextButton(onClick = { scope.launch { graph.threats.addRule(host, "BLOCK", "THREAT"); info = "$host added to your blocklist" } }) { Text("Always flag this domain") }
                        if (r.verdict != Verdict.CONFIRMED_MALICIOUS) TextButton(onClick = { scope.launch { graph.threats.addRule(host, "ALLOW", "THREAT"); info = "$host trusted" } }) { Text("I trust this domain") }
                    } }
                }
            }
        }
        item { Spacer(Modifier.height(12.dp)); Text("Recent scans", style = MaterialTheme.typography.titleMedium) }
        items(history, key = { it.id }) { h ->
            val v = runCatching { Verdict.valueOf(h.verdict) }.getOrDefault(Verdict.UNKNOWN)
            Row(Modifier.padding(vertical = 2.dp)) { Text(v.label(), color = v.color(), modifier = Modifier.weight(0.4f)); Dim(h.sanitizedUrl, Modifier.weight(0.6f)) }
        }
    }

    if (confirmOpen) AlertDialog(
        onDismissRequest = { confirmOpen = false },
        title = { Text("Open an unverified site?") },
        text = { Text("BANKVAULT has no information about this site. Never enter a PIN, OTP or card number on a site you reached from a message.") },
        confirmButton = { TextButton(onClick = { confirmOpen = false; open(ctx, report?.sanitized) }) { Text("Open") } },
        dismissButton = { TextButton(onClick = { confirmOpen = false }) { Text("Cancel") } },
    )
}

private fun open(ctx: android.content.Context, url: String?) {
    if (url == null) return
    runCatching { ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
}
