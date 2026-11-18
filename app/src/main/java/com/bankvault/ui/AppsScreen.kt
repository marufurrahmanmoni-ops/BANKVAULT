package com.bankvault.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.bankvault.AppGraph
import com.bankvault.core.audit.AuditEvent
import com.bankvault.core.audit.AuditType
import com.bankvault.core.auth.AuthPolicy
import com.bankvault.core.session.SessionConfig
import com.bankvault.data.NetworkMode
import com.bankvault.data.ProtectedAppEntity
import kotlinx.coroutines.launch

@Composable
fun AppsScreen(graph: AppGraph) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val apps by graph.db.apps().observe().collectAsStateWithLifecycle(emptyList())
    val settings by graph.settings.state.collectAsStateWithLifecycle()
    val sessions by graph.sessions.active.collectAsStateWithLifecycle()
    var picking by remember { mutableStateOf(false) }

    fun save(e: ProtectedAppEntity, what: String) = scope.launch {
        graph.db.apps().upsert(e)
        graph.audit.record(AuditEvent(AuditType.SETTINGS_CHANGED, graph.clock.nowMillis(), e.packageName, what))
        graph.sessions.updateConfigs(graph.db.apps().all())
        graph.network.reconcileFromStore()
    }

    LazyColumn(Modifier.fillMaxSize().padding(16.dp)) {
        item {
            Text("Protected apps", style = MaterialTheme.typography.headlineSmall)
            Dim("Each app is locked by default, its network is blocked while locked (if a network method is active), and temporary access ends automatically.")
            Spacer(Modifier.height(8.dp))
            Button(onClick = { picking = true }) { Text("Add apps") }
        }
        items(apps, key = { it.packageName }) { a ->
            SectionCard(a.label) {
                Dim(a.packageName)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Block Wi-Fi while locked", Modifier.weight(1f)); Switch(a.blockWifi, { save(a.copy(blockWifi = it), "blockWifi=$it") })
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Block Mobile Data while locked", Modifier.weight(1f)); Switch(a.blockMobile, { save(a.copy(blockMobile = it), "blockMobile=$it") })
                }
                if (graph.managed.canRestrict) Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Hide from launcher while locked", Modifier.weight(1f)); Switch(a.hideWhenLocked, { save(a.copy(hideWhenLocked = it), "hide=$it") })
                }
                Text("Session length", style = MaterialTheme.typography.labelLarge)
                Row(Modifier.horizontalScroll(rememberScrollState())) { SessionConfig.PRESETS.forEach { p ->
                    FilterChip(selected = a.sessionDurationMs == p, onClick = {
                        save(a.copy(sessionDurationMs = p, backgroundGraceMs = a.backgroundGraceMs.coerceAtMost(p)), "session=${p / 1000}s")
                    }, label = { Text(formatDuration(p)) }, modifier = Modifier.padding(end = 4.dp))
                } }
                CustomDuration(a) { ms -> save(a.copy(sessionDurationMs = ms, backgroundGraceMs = a.backgroundGraceMs.coerceAtMost(ms)), "session=${ms / 1000}s") }
                Text("App-switch grace (e.g. to copy an OTP): ${formatDuration(a.backgroundGraceMs)}", style = MaterialTheme.typography.labelLarge)
                Row(Modifier.horizontalScroll(rememberScrollState())) { listOf(15_000L, 30_000L, 45_000L, 90_000L).filter { it <= a.sessionDurationMs }.forEach { g ->
                    FilterChip(selected = a.backgroundGraceMs == g, onClick = { save(a.copy(backgroundGraceMs = g), "grace=${g / 1000}s") },
                        label = { Text(formatDuration(g)) }, modifier = Modifier.padding(end = 4.dp))
                } }
                Text("Authentication", style = MaterialTheme.typography.labelLarge)
                Row(Modifier.horizontalScroll(rememberScrollState())) { (listOf<AuthPolicy?>(null) + AuthPolicy.entries).forEach { p ->
                    FilterChip(selected = a.authPolicy == p?.name, onClick = { save(a.copy(authPolicy = p?.name), "auth=${p ?: "global"}") },
                        label = { Text(when (p) { null -> "Global"; AuthPolicy.PIN_ONLY -> "PIN"; AuthPolicy.BIOMETRIC_ONLY -> "Biometric"; AuthPolicy.PIN_AND_BIOMETRIC -> "PIN+Bio" }) },
                        modifier = Modifier.padding(end = 4.dp))
                } }
                if (settings.networkMode == NetworkMode.OEM_MANUAL) {
                    Spacer(Modifier.height(6.dp))
                    Dim(graph.oem.instructions())
                    Row {
                        OutlinedButton(onClick = { ctx.startActivity(graph.oem.appInfoIntent(a.packageName)) }) { Text("Open app info") }
                        TextButton(onClick = { graph.oem.markConfirmed(a.packageName, true); scope.launch { graph.network.reconcileFromStore() } }) { Text("I switched it off") }
                    }
                }
                Row {
                    if (a.packageName in sessions) OutlinedButton(onClick = { scope.launch { graph.sessions.endNow(a.packageName) } }) { Text("Lock now") }
                    TextButton(onClick = { scope.launch {
                        graph.sessions.endNow(a.packageName)
                        graph.managed.release(setOf(a.packageName))
                        graph.db.apps().delete(a.packageName)
                        graph.network.reconcileFromStore()
                        graph.audit.record(AuditEvent(AuditType.SETTINGS_CHANGED, graph.clock.nowMillis(), a.packageName, "removed from protection"))
                    } }) { Text("Remove protection", color = BvColors.Bad) }
                }
            }
        }
    }

    if (picking) AppPicker(graph, apps.map { it.packageName }.toSet(), onDismiss = { picking = false }) { chosen ->
        picking = false
        scope.launch {
            chosen.forEach { c ->
                graph.db.apps().upsert(ProtectedAppEntity(c.first, c.second, addedAt = graph.clock.nowMillis()))
                graph.audit.record(AuditEvent(AuditType.SETTINGS_CHANGED, graph.clock.nowMillis(), c.first, "added to protection"))
            }
            graph.managed.restrict(chosen.map { it.first }.toSet())
            graph.sessions.updateConfigs(graph.db.apps().all())
            graph.network.reconcileFromStore()
        }
    }
}

@Composable
private fun CustomDuration(a: ProtectedAppEntity, onSet: (Long) -> Unit) {
    var txt by remember(a.packageName) { mutableStateOf("") }
    Row(verticalAlignment = Alignment.CenterVertically) {
        OutlinedTextField(txt, { v -> txt = v.filter(Char::isDigit).take(4) }, label = { Text("Custom (seconds)") }, singleLine = true, modifier = Modifier.weight(1f))
        TextButton(onClick = {
            val ms = txt.toLongOrNull()?.times(1000) ?: return@TextButton
            if (ms in SessionConfig.MIN_DURATION..SessionConfig.MAX_DURATION) { onSet(ms); txt = "" }
        }) { Text("Set") }
    }
}

@Composable
private fun AppPicker(graph: AppGraph, already: Set<String>, onDismiss: () -> Unit, onPick: (List<Pair<String, String>>) -> Unit) {
    val all = remember { graph.installed.launchable().filter { it.packageName !in already } }
    val selected = remember { mutableStateOf(all.filter { it.suggested }.map { it.packageName }.toSet()) }
    var manual by remember { mutableStateOf("") }
    var manualError by remember { mutableStateOf<String?>(null) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Choose apps to protect") },
        text = {
            Column {
                Dim("Suggested financial apps are pre-selected. Only apps with a launcher icon are listed (no QUERY_ALL_PACKAGES).")
                LazyColumn(Modifier.height(320.dp)) {
                    items(all, key = { it.packageName }) { app ->
                        Row(Modifier.fillMaxWidth().clickable {
                            selected.value = if (app.packageName in selected.value) selected.value - app.packageName else selected.value + app.packageName
                        }, verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(app.packageName in selected.value, null)
                            Column { Text(app.label); Dim(app.packageName) }
                        }
                    }
                }
                OutlinedTextField(manual, { manual = it.trim(); manualError = null }, label = { Text("Or package name") }, singleLine = true)
                manualError?.let { Text(it, color = BvColors.Bad) }
            }
        },
        confirmButton = {
            Button(onClick = {
                val picks = all.filter { it.packageName in selected.value }.map { it.packageName to it.label }.toMutableList()
                if (manual.isNotBlank()) {
                    val m = graph.installed.resolveManually(manual)
                    if (m == null) { manualError = "Not installed or not visible to BANKVAULT"; return@Button }
                    picks += m.packageName to m.label
                }
                onPick(picks)
            }) { Text("Protect") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
