package com.bankvault.ui

import android.content.Intent
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.bankvault.AppGraph
import com.bankvault.core.audit.AuditType
import kotlinx.coroutines.launch
import java.text.DateFormat
import java.util.Date

private enum class LogFilter(val label: String, val types: Set<AuditType>?) {
    ALL("All", null),
    AUTH("Auth", setOf(AuditType.AUTH_SUCCESS, AuditType.AUTH_FAILURE, AuditType.AUTH_LOCKOUT, AuditType.APP_ACCESS_ATTEMPT)),
    SESSIONS("Sessions", setOf(AuditType.SESSION_STARTED, AuditType.SESSION_ENDED)),
    NETWORK("Network", setOf(AuditType.NETWORK_RESTRICTION_CHANGED, AuditType.NETWORK_PROTECTION_FAILURE)),
    THREATS("Threats", setOf(AuditType.THREAT_DETECTED, AuditType.MALICIOUS_DOMAIN_BLOCKED, AuditType.THREAT_DB_UPDATED)),
    SECURITY("Tamper", setOf(AuditType.PERMISSION_CHANGED, AuditType.TAMPER_DETECTED, AuditType.EMERGENCY_LOCK, AuditType.RECOVERY, AuditType.APP_VISIBILITY_CHANGED)),
}

@Composable
fun ActivityScreen(activity: FragmentActivity, graph: AppGraph) {
    val ctx = LocalContext.current
    val scope = rememberSafeScope()
    val events by graph.audit.observe().collectAsStateWithLifecycle(emptyList())
    var filter by remember { mutableStateOf(LogFilter.ALL) }
    var confirmClear by remember { mutableStateOf(false) }
    val fmt = remember { DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.MEDIUM) }

    Column(Modifier.fillMaxSize().padding(16.dp)) {
        Text("Security activity", style = MaterialTheme.typography.headlineSmall)
        Dim("Stored encrypted on this device. Never contains PINs, OTPs, passwords or banking data.")
        Row(Modifier.horizontalScroll(rememberScrollState())) {
            LogFilter.entries.forEach { f -> FilterChip(filter == f, { filter = f }, { Text(f.label) }, Modifier.padding(end = 4.dp)) }
        }
        Row {
            OutlinedButton(onClick = { scope.launch {
                val report = graph.audit.exportReport()
                ctx.startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).setType("text/plain")
                    .putExtra(Intent.EXTRA_SUBJECT, "BANKVAULT security report").putExtra(Intent.EXTRA_TEXT, report), "Export report"))
            } }) { Text("Export report") }
            TextButton(onClick = { confirmClear = true }) { Text("Clear history", color = BvColors.Bad) }
        }
        LazyColumn {
            items(events.filter { filter.types == null || it.type in filter.types!! }) { e ->
                Column(Modifier.padding(vertical = 6.dp)) {
                    Text("${e.type.name.replace('_', ' ').lowercase().replaceFirstChar { it.uppercase() }}  ·  ${fmt.format(Date(e.timestamp))}",
                        style = MaterialTheme.typography.labelLarge,
                        color = if (e.type.name.contains("FAIL") || e.type == AuditType.TAMPER_DETECTED || e.type == AuditType.MALICIOUS_DOMAIN_BLOCKED) BvColors.Warning else MaterialTheme.colorScheme.onSurface)
                    e.packageName?.let { Dim(it) }
                    if (e.detail.isNotBlank()) Dim(e.detail)
                }
            }
        }
    }
    if (confirmClear) ReAuthDialog(activity, graph, "Clear security history", onDismiss = { confirmClear = false }) {
        confirmClear = false
        scope.launch { graph.audit.clear(graph.clock.nowMillis()) }
    }
}
