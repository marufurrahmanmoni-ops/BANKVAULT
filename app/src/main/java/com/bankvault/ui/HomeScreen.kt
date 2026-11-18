package com.bankvault.ui

import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.bankvault.AppGraph
import com.bankvault.core.network.NetworkAccessState
import com.bankvault.core.status.ProtectionStatus
import com.bankvault.data.NetworkMode
import com.bankvault.dns.PrivateDnsInspector
import com.bankvault.emergency.triggerEmergency
import com.bankvault.lock.Biometric
import com.bankvault.tamper.TamperMonitor
import kotlinx.coroutines.delay

@Composable
fun HomeScreen(graph: AppGraph, onNavigate: (Tab) -> Unit) {
    val ctx = LocalContext.current
    val apps by graph.db.apps().observe().collectAsStateWithLifecycle(emptyList())
    val net by graph.network.status.collectAsStateWithLifecycle()
    val settings by graph.settings.state.collectAsStateWithLifecycle()
    val sessions by graph.sessions.active.collectAsStateWithLifecycle()
    val dbInfo by graph.threats.info.collectAsStateWithLifecycle()
    var checks by remember { mutableStateOf<List<TamperMonitor.Check>>(emptyList()) }
    var dns by remember { mutableStateOf(PrivateDnsInspector.status(ctx)) }
    var emergencyMsg by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) {
        while (true) {
            checks = graph.tamper.run()
            dns = PrivateDnsInspector.status(ctx)
            graph.network.verifyAll()
            delay(10_000)
        }
    }

    val cm = ctx.getSystemService(ConnectivityManager::class.java)
    val caps = cm.getNetworkCapabilities(cm.activeNetwork)
    val onWifi = caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
    val onCell = caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true

    // ---- derive component statuses (never green unless verified) ----
    val netStatuses = net.map { ProtectionStatus.fromNetwork(it.state) }
    val networkStatus = when {
        apps.isEmpty() -> ProtectionStatus.PENDING
        settings.networkMode == NetworkMode.NONE -> ProtectionStatus.DEGRADED
        else -> ProtectionStatus.overall(netStatuses.map { if (it == ProtectionStatus.ALLOWED) ProtectionStatus.PROTECTED else it })
    }
    fun transportStatus(blockedState: NetworkAccessState): ProtectionStatus = when {
        net.isEmpty() -> ProtectionStatus.PENDING
        net.all { it.state == NetworkAccessState.BLOCKED_ALL || it.state == blockedState || it.state == NetworkAccessState.TEMPORARILY_ALLOWED } -> ProtectionStatus.BLOCKED
        else -> ProtectionStatus.overall(netStatuses)
    }
    val appLockStatus = when {
        apps.isEmpty() -> ProtectionStatus.PENDING
        checks.any { it.id == "usage" && it.severity == TamperMonitor.Severity.CRITICAL } -> ProtectionStatus.DEGRADED
        graph.managed.canRestrict && apps.all { graph.managed.isSuspended(it.packageName) || it.packageName in sessions } -> ProtectionStatus.PROTECTED
        else -> ProtectionStatus.DEGRADED // launch detection is best-effort without suspension
    }
    val threatStatus = when {
        dbInfo.entries == 0 -> ProtectionStatus.UNSUPPORTED
        dbInfo.stale(graph.clock.nowMillis()) -> ProtectionStatus.DEGRADED
        else -> ProtectionStatus.PROTECTED
    }
    val dnsStatus = when {
        dns.active && dns.knownFilteringProvider != null -> ProtectionStatus.PROTECTED
        dns.active -> ProtectionStatus.VERIFICATION_UNAVAILABLE
        else -> ProtectionStatus.MANUAL_SETUP_REQUIRED
    }
    val stealthStatus = when {
        graph.managed.canRestrict -> if (apps.isNotEmpty() && apps.all { graph.managed.isHidden(it.packageName) || it.packageName in sessions || !it.hideWhenLocked }) ProtectionStatus.HIDDEN else ProtectionStatus.VISIBLE
        else -> ProtectionStatus.MANUAL_SETUP_REQUIRED
    }
    val bio = Biometric.availability(ctx)
    val authStatus = if (graph.pins.isSet()) ProtectionStatus.PROTECTED else ProtectionStatus.PENDING
    val monitorStatus = when {
        checks.any { it.severity == TamperMonitor.Severity.CRITICAL } -> ProtectionStatus.DEGRADED
        checks.any { it.severity == TamperMonitor.Severity.WARNING } -> ProtectionStatus.DEGRADED
        checks.isEmpty() -> ProtectionStatus.PENDING
        else -> ProtectionStatus.PROTECTED
    }
    val overall = ProtectionStatus.overall(listOf(appLockStatus, networkStatus, authStatus, monitorStatus))

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)) {
        SectionCard("Overall security", overall) {
            Dim(graph.tamper.deviceModelLine())
            Dim("Profile: ${settings.profile.title}. BANKVAULT never claims 100% protection; amber items explain what is missing.")
        }

        Button(
            onClick = { triggerEmergency(ctx, "in_app_button") { ok -> emergencyMsg = if (ok) "Emergency lock applied." else "Emergency lock applied – some steps are unavailable on this phone (see Activity)." } },
            colors = ButtonDefaults.buttonColors(containerColor = BvColors.Bad),
            modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
        ) { Icon(Icons.Filled.Lock, null); Spacer(Modifier.padding(4.dp)); Text("EMERGENCY LOCK") }
        emergencyMsg?.let { Dim(it) }

        SectionCard("Protected banking apps", appLockStatus) {
            if (apps.isEmpty()) Dim("No apps selected yet.") else apps.forEach { a ->
                val st = net.firstOrNull { it.app.packageName == a.packageName }
                Row(Modifier.fillMaxWidth().padding(vertical = 3.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(a.label)
                        Dim(if (a.packageName in sessions) "Unlocked – ${formatDuration(graph.sessions.manager.remainingMillis(a.packageName))} left" else "Locked")
                    }
                    StatusChip(st?.let { ProtectionStatus.fromNetwork(it.state) } ?: ProtectionStatus.PENDING)
                }
            }
            if (appLockStatus == ProtectionStatus.DEGRADED) Dim("Without Device Owner, BANKVAULT detects launches and shows its lock screen (best effort). The network block below is what actually stops a locked app from reaching its servers.")
            Button(onClick = { onNavigate(Tab.APPS) }) { Text("Manage apps") }
        }

        SectionCard("Network isolation", networkStatus) {
            Dim("Method: ${settings.networkMode.title}")
            when (settings.networkMode) {
                NetworkMode.NONE -> Dim("Not active. Choose a method under More > Network isolation.")
                NetworkMode.OEM_MANUAL -> Dim("Your phone's own switch cannot be read by apps, so this can only be 'Manual Setup Required' or 'Verification Unavailable'.")
                else -> net.filter { it.state != NetworkAccessState.BLOCKED_ALL && it.state != NetworkAccessState.TEMPORARILY_ALLOWED }
                    .forEach { Dim("${it.app.packageName}: ${it.state} – ${(it.enforcement as? com.bankvault.core.network.Enforcement.Failed)?.error ?: ""}") }
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            SectionCard("Wi-Fi", transportStatus(NetworkAccessState.BLOCKED_WIFI), Modifier.weight(1f)) { Dim(if (onWifi) "Connected" else "Not connected") }
            SectionCard("Mobile data", transportStatus(NetworkAccessState.BLOCKED_MOBILE_DATA), Modifier.weight(1f)) { Dim(if (onCell) "Connected" else "Not connected") }
        }

        SectionCard("Cyber threat protection", threatStatus) {
            Dim("Threat database v${dbInfo.version} (${dbInfo.source}), ${dbInfo.entries} entries.")
            if (dbInfo.stale(graph.clock.nowMillis())) Dim("Database is out of date – last valid copy is still used offline.")
        }
        SectionCard("Anti-phishing & link scanner", ProtectionStatus.PROTECTED) {
            Dim("Share links, paste URLs or scan QR codes. Works offline. Warnings only – it does not filter your browser.")
            Button(onClick = { onNavigate(Tab.SCAN) }) { Text("Scan a link") }
        }
        SectionCard("Malware & phishing domain blocking (device-wide)", dnsStatus) {
            Dim(if (dns.active) "Private DNS: ${dns.serverName}${dns.knownFilteringProvider?.let { " (${it.blocks})" } ?: " – filtering not verified"}"
                else "Set Private DNS to a filtering resolver: More > DNS protection.")
        }
        SectionCard("Privacy & tracker protection", if (dns.knownFilteringProvider?.blocks?.contains("trackers") == true) ProtectionStatus.PROTECTED else ProtectionStatus.MANUAL_SETUP_REQUIRED) {
            Dim("Tracker blocking without VPN works through a tracker-filtering Private DNS provider. BANKVAULT never inspects encrypted traffic.")
        }
        SectionCard("Stealth mode", stealthStatus) {
            Dim(if (graph.managed.canRestrict) "Locked apps are hidden from the launcher by Device Owner policy." else "Use your phone's Hide Apps feature (More > Stealth). BANKVAULT cannot hide other apps without Device Owner.")
        }
        SectionCard("Authentication", authStatus) {
            Dim("Separate PIN: set · Biometric: ${when (bio) { Biometric.Availability.USABLE -> "available (strong)"; Biometric.Availability.REENROLLED -> "re-enrolment detected – PIN required"; Biometric.Availability.NOT_ENROLLED -> "not enrolled"; else -> "not available" }} · Policy: ${settings.authPolicy}")
        }
        SectionCard("Security monitoring", monitorStatus) {
            checks.filter { it.severity != TamperMonitor.Severity.OK }.forEach { Dim("• ${it.title}: ${it.detail}") }
            Button(onClick = { onNavigate(Tab.LOG) }) { Text("View activity") }
        }
        Spacer(Modifier.height(24.dp))
    }
}
