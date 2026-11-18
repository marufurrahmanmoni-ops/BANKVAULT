package com.bankvault.ui

import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
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
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.bankvault.AppGraph
import com.bankvault.core.network.Enforcement
import com.bankvault.core.network.NetworkAccessState
import com.bankvault.core.status.ProtectionStatus
import com.bankvault.data.NetworkMode
import com.bankvault.dns.PrivateDnsInspector
import com.bankvault.emergency.triggerEmergency
import com.bankvault.lock.Biometric
import com.bankvault.tamper.TamperMonitor
import com.bankvault.vpn.VpnController
import kotlinx.coroutines.delay

@Composable
fun HomeScreen(activity: FragmentActivity, graph: AppGraph, fixer: Fixer, onNavigate: (Tab) -> Unit) {
    val ctx = activity
    val apps by graph.db.apps().observe().collectAsStateWithLifecycle(emptyList())
    val net by graph.network.status.collectAsStateWithLifecycle()
    val settings by graph.settings.state.collectAsStateWithLifecycle()
    val sessions by graph.sessions.active.collectAsStateWithLifecycle()
    val dbInfo by graph.threats.info.collectAsStateWithLifecycle()
    val vpnStatus by VpnController.statusFlow.collectAsStateWithLifecycle()
    val alwaysOn by VpnController.alwaysOn.collectAsStateWithLifecycle()
    var checks by remember { mutableStateOf<List<TamperMonitor.Check>>(emptyList()) }
    var dns by remember { mutableStateOf(PrivateDnsInspector.status(ctx)) }
    var emergencyMsg by remember { mutableStateOf<String?>(null) }
    var refresh by remember { mutableIntStateOf(0) }

    // Re-check immediately when the owner returns from a Settings screen opened by a Fix button.
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    DisposableEffect(lifecycle) {
        val obs = LifecycleEventObserver { _, e -> if (e == Lifecycle.Event.ON_RESUME) refresh++ }
        lifecycle.addObserver(obs); onDispose { lifecycle.removeObserver(obs) }
    }
    LaunchedEffect(refresh) {
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
    fun check(id: String) = checks.firstOrNull { it.id == id }
    val usageOk = check("usage")?.severity != TamperMonitor.Severity.CRITICAL
    val overlayOk = check("overlay")?.severity == TamperMonitor.Severity.OK || checks.isEmpty()
    val managed = graph.managed.canRestrict
    val label = apps.associate { it.packageName to it.label }

    // =============== Issues per section (reason + fix) ===============
    val appIssues = buildList {
        if (apps.isEmpty()) add(Issue("noapps", IssueLevel.PROBLEM, "No banking apps selected",
            "Choose which apps BANKVAULT should lock.", FixKind.ADD_APPS, "Add apps"))
        if (!usageOk) add(Issue("usage", IssueLevel.PROBLEM, "Usage access is off",
            "BANKVAULT can't see when a banking app opens, so it cannot show its lock screen.", FixKind.USAGE_ACCESS, "Turn on usage access"))
        if (!overlayOk) add(Issue("overlay", IssueLevel.PROBLEM, "\"Display over other apps\" is off",
            "Android blocks BANKVAULT from bringing its lock screen in front of the banking app.", FixKind.OVERLAY, "Allow"))
        if (!managed && apps.isNotEmpty()) add(Issue("bestEffort", IssueLevel.LIMITATION, "Lock screen works only while BANKVAULT runs",
            "On a normal phone no app can stop another app from starting. If someone force-stops BANKVAULT, the lock screen stops – " +
                "but the network block below keeps the banking app offline. To make banking apps unable to start at all, use Device Owner (advanced).",
            FixKind.DEVICE_OWNER_GUIDE, "How to set up (advanced)"))
    }
    val networkIssues = buildList {
        val vpnBroken = settings.networkMode == NetworkMode.LOCAL_VPN &&
            (VpnService.prepare(ctx) != null || vpnStatus is VpnController.Status.Revoked || vpnStatus is VpnController.Status.Error)
        when {
            apps.isEmpty() -> Unit
            settings.networkMode == NetworkMode.NONE -> add(Issue("netoff", IssueLevel.PROBLEM, "Network block is off",
                "Locked banking apps can still use Wi-Fi and Mobile Data. Turning this on starts a local VPN that drops only their traffic – no server, other apps unaffected.",
                FixKind.ENABLE_VPN, "Turn on network block"))
            vpnBroken -> add(Issue("vpn", IssueLevel.PROBLEM, "Network block stopped",
                (vpnStatus as? VpnController.Status.Error)?.message ?: "The VPN was turned off or another VPN app took over.",
                FixKind.ENABLE_VPN, "Restart network block"))
        }
        if (settings.networkMode != NetworkMode.NONE && !vpnBroken) for (s in net) {
            val name = label[s.app.packageName] ?: s.app.packageName
            when (s.state) {
                NetworkAccessState.PROTECTION_PENDING, NetworkAccessState.PROTECTION_INACTIVE -> add(Issue("net_${s.app.packageName}", IssueLevel.PROBLEM,
                    "$name: internet not blocked yet",
                    (s.enforcement as? Enforcement.Failed)?.error ?: "The block was requested but could not be confirmed.", FixKind.RETRY_NETWORK, "Retry"))
                NetworkAccessState.MANUAL_SETUP_REQUIRED -> add(Issue("oem_${s.app.packageName}", IssueLevel.PROBLEM,
                    "$name: switch off its network in phone settings", "You chose the phone's own setting; BANKVAULT can only show you where it is.",
                    FixKind.OEM_NETWORK_STEPS, "Show steps"))
                NetworkAccessState.VERIFICATION_UNAVAILABLE -> add(Issue("unv_${s.app.packageName}", IssueLevel.RECOMMENDED,
                    "$name: block can't be checked", "The phone's own network switch has no API, so BANKVAULT cannot confirm it. VPN mode is verified automatically.",
                    FixKind.ENABLE_VPN, "Switch to VPN mode"))
                else -> Unit
            }
        }
        if (settings.networkMode == NetworkMode.LOCAL_VPN && !vpnBroken && vpnStatus is VpnController.Status.Running && !alwaysOn) add(Issue("alwayson", IssueLevel.RECOMMENDED,
            "Turn on Always-on VPN", "If BANKVAULT is force-stopped the block stops; with Always-on, Android restarts it. In the next screen tap the gear next to BANKVAULT › Always-on VPN. Do NOT turn on \"Block connections without VPN\".",
            FixKind.VPN_SETTINGS, "Open VPN settings"))
    }
    val dnsIssues = buildList {
        if (!dns.active) add(Issue("dns", IssueLevel.RECOMMENDED, "Phone-wide malicious-site blocking is not set up",
            "Set Private DNS to a filtering service. It protects every app and browser, without a VPN.", FixKind.PRIVATE_DNS, "Set up (1 minute)"))
        else if (dns.knownFilteringProvider == null) add(Issue("dnsunknown", IssueLevel.RECOMMENDED, "Private DNS is on, but not a known filtering service",
            "${dns.serverName} may not block malicious sites. Pick one from the list to be sure.", FixKind.PRIVATE_DNS, "Choose a provider"))
    }
    val privacyIssues = if (dns.knownFilteringProvider?.blocks?.contains("trackers") == true) emptyList() else listOf(
        Issue("trackers", IssueLevel.RECOMMENDED, "Tracker blocking is off",
            "Choose AdGuard DNS (dns.adguard-dns.com) as Private DNS to block ads and trackers in all apps.", FixKind.PRIVATE_DNS, "Set up"))
    val stealthIssues = buildList {
        if (!managed) add(Issue("hide", IssueLevel.RECOMMENDED, "Hide banking app icons",
            "Use your phone's own Hide apps feature. BANKVAULT can't check it, so this card always says Manual Setup Required.", FixKind.HIDE_APPS_GUIDE, "Show how"))
        if (!settings.tileAdded) add(Issue("tile", IssueLevel.RECOMMENDED, "Add the Emergency Lock tile",
            "One tap from Quick Settings locks everything – even from the lock screen. Also needed before you can hide BANKVAULT's own icon.", FixKind.ADD_TILE, "Add tile"))
    }
    val bio = Biometric.availability(ctx)
    val needsBio = settings.authPolicy != com.bankvault.core.auth.AuthPolicy.PIN_ONLY || settings.settingsAuthPolicy != com.bankvault.core.auth.AuthPolicy.PIN_ONLY
    val authIssues = buildList {
        if (needsBio && bio == Biometric.Availability.NOT_ENROLLED) add(Issue("bio", IssueLevel.PROBLEM, "No fingerprint/face enrolled",
            "Your policy uses biometrics, so BANKVAULT is falling back to PIN only.", FixKind.BIOMETRIC_ENROLL, "Enrol fingerprint"))
        if (bio == Biometric.Availability.REENROLLED) add(Issue("reenrol", IssueLevel.PROBLEM, "New fingerprint/face detected",
            "For safety biometric unlock is paused. Unlock once with your BANKVAULT PIN to re-enable it."))
    }
    val monitorIssues = buildList {
        if (check("notif")?.severity == TamperMonitor.Severity.WARNING) add(Issue("notif", IssueLevel.PROBLEM, "Notifications are blocked",
            "You won't be alerted if protection stops.", FixKind.NOTIFICATIONS, "Allow notifications"))
        if (check("adb")?.severity == TamperMonitor.Severity.WARNING) add(Issue("adb", IssueLevel.PROBLEM, "USB debugging is on",
            "Anyone with a computer and cable can stop BANKVAULT. Turn it off unless you are developing.", FixKind.USB_DEBUGGING, "Turn off USB debugging"))
    }

    // =============== Statuses (derived from the same facts) ===============
    val netVerifiedAll = net.isNotEmpty() && net.all { it.state.name.startsWith("BLOCKED") || it.state == NetworkAccessState.TEMPORARILY_ALLOWED }
    val networkStatus = when {
        apps.isEmpty() -> ProtectionStatus.PENDING
        networkIssues.any { it.level == IssueLevel.PROBLEM } -> if (settings.networkMode == NetworkMode.OEM_MANUAL) ProtectionStatus.MANUAL_SETUP_REQUIRED else ProtectionStatus.DEGRADED
        settings.networkMode == NetworkMode.OEM_MANUAL -> ProtectionStatus.VERIFICATION_UNAVAILABLE
        netVerifiedAll -> ProtectionStatus.PROTECTED
        else -> ProtectionStatus.PENDING
    }
    val appLockStatus = when {
        apps.isEmpty() -> ProtectionStatus.PENDING
        appIssues.any { it.level == IssueLevel.PROBLEM } -> ProtectionStatus.DEGRADED
        managed && apps.all { graph.managed.isSuspended(it.packageName) || it.packageName in sessions } -> ProtectionStatus.PROTECTED
        // Unmanaged: lock screen active AND the real boundary (network) verified.
        !managed && netVerifiedAll -> ProtectionStatus.PROTECTED
        else -> ProtectionStatus.DEGRADED
    }
    val appLockReasonIfDegraded = if (appLockStatus == ProtectionStatus.DEGRADED && appIssues.none { it.level == IssueLevel.PROBLEM })
        listOf(Issue("needsnet", IssueLevel.PROBLEM, "Needs the network block to be fully protected",
            "The lock screen alone is best-effort. Turn on the network block so a locked banking app also cannot go online.", FixKind.ENABLE_VPN, "Turn on network block"))
    else emptyList()
    fun transportStatus(blockedState: NetworkAccessState): ProtectionStatus = when {
        net.isEmpty() || networkStatus != ProtectionStatus.PROTECTED -> networkStatus
        net.all { it.state == NetworkAccessState.BLOCKED_ALL || it.state == blockedState || it.state == NetworkAccessState.TEMPORARILY_ALLOWED } -> ProtectionStatus.BLOCKED
        else -> ProtectionStatus.ALLOWED
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
    val stealthStatus = if (managed) {
        if (apps.isNotEmpty() && apps.all { graph.managed.isHidden(it.packageName) || it.packageName in sessions || !it.hideWhenLocked }) ProtectionStatus.HIDDEN else ProtectionStatus.VISIBLE
    } else ProtectionStatus.MANUAL_SETUP_REQUIRED
    val authStatus = when {
        !graph.pins.isSet() -> ProtectionStatus.PENDING
        authIssues.isNotEmpty() -> ProtectionStatus.DEGRADED
        else -> ProtectionStatus.PROTECTED
    }
    val monitorStatus = when {
        checks.isEmpty() -> ProtectionStatus.PENDING
        monitorIssues.isNotEmpty() -> ProtectionStatus.DEGRADED
        else -> ProtectionStatus.PROTECTED
    }
    val overall = ProtectionStatus.overall(listOf(appLockStatus, networkStatus, authStatus, monitorStatus))
    val allProblems = (appIssues + appLockReasonIfDegraded + networkIssues + authIssues + monitorIssues).filter { it.level == IssueLevel.PROBLEM }.distinctBy { it.fix to it.title }

    var crashReport by remember { mutableStateOf(com.bankvault.CrashReporter.read(ctx)) }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)) {
        crashReport?.let { report ->
            SectionCard("Problem report available", ProtectionStatus.DEGRADED) {
                Dim(report.lineSequence().take(2).joinToString(" · "))
                Dim("BANKVAULT recorded an error. Please share this report with the developer – it contains no PINs, OTPs or banking data.")
                Row {
                    Button(onClick = {
                        graph.expectReturn()
                        ctx.startActivity(android.content.Intent.createChooser(android.content.Intent(android.content.Intent.ACTION_SEND)
                            .setType("text/plain").putExtra(android.content.Intent.EXTRA_SUBJECT, "BANKVAULT problem report")
                            .putExtra(android.content.Intent.EXTRA_TEXT, report), "Share report"))
                    }) { Text("Share report") }
                    androidx.compose.material3.TextButton(onClick = { com.bankvault.CrashReporter.clear(ctx); crashReport = null }) { Text("Dismiss") }
                }
            }
        }
        SectionCard("Overall security", overall) {
            Dim(graph.tamper.deviceModelLine())
            if (allProblems.isEmpty()) Dim("All required protections are on and verified. Optional extras are suggested below. BANKVAULT never claims 100% protection.")
            else {
                Text("${allProblems.size} thing(s) to fix – tap each button:")
                IssueList(allProblems, fixer)
            }
        }

        Button(
            onClick = { triggerEmergency(ctx, "in_app_button") { ok -> emergencyMsg = if (ok) "Emergency lock applied." else "Emergency lock applied. Steps your phone doesn't support were skipped (see Activity)." } },
            colors = ButtonDefaults.buttonColors(containerColor = BvColors.Bad),
            modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
        ) { Icon(Icons.Filled.Lock, null); Spacer(Modifier.padding(4.dp)); Text("EMERGENCY LOCK") }
        emergencyMsg?.let { Dim(it) }

        SectionCard("Protected banking apps", appLockStatus) {
            apps.forEach { a ->
                val st = net.firstOrNull { it.app.packageName == a.packageName }
                Row(Modifier.fillMaxWidth().padding(vertical = 3.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(a.label)
                        Dim(if (a.packageName in sessions) "Unlocked – ${formatDuration(graph.sessions.manager.remainingMillis(a.packageName))} left" else "Locked")
                    }
                    StatusChip(st?.let { ProtectionStatus.fromNetwork(it.state) } ?: if (settings.networkMode == NetworkMode.NONE) ProtectionStatus.DEGRADED else ProtectionStatus.PENDING)
                }
            }
            IssueList(appIssues + appLockReasonIfDegraded, fixer)
            if (apps.isNotEmpty()) Button(onClick = { onNavigate(Tab.APPS) }) { Text("Manage apps") }
        }

        SectionCard("Network block (Wi-Fi + Mobile Data)", networkStatus) {
            Dim("Method: ${settings.networkMode.title}")
            if (networkStatus == ProtectionStatus.PROTECTED) Dim("Verified: locked banking apps have no internet; all other apps work normally.")
            IssueList(networkIssues, fixer)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            SectionCard("Wi-Fi", transportStatus(NetworkAccessState.BLOCKED_WIFI), Modifier.weight(1f)) { Dim(if (onWifi) "Connected" else "Not connected") }
            SectionCard("Mobile data", transportStatus(NetworkAccessState.BLOCKED_MOBILE_DATA), Modifier.weight(1f)) { Dim(if (onCell) "Connected" else "Not connected") }
        }
        if (networkStatus != ProtectionStatus.PROTECTED && apps.isNotEmpty()) Dim("Wi-Fi / Mobile data show the same state as the network block above until it is verified.")

        SectionCard("Cyber threat database", threatStatus) {
            Dim("v${dbInfo.version} (${dbInfo.source}), ${dbInfo.entries} entries. Used by the link & QR scanner.")
            if (threatStatus == ProtectionStatus.DEGRADED) Dim("Out of date – the last valid copy still works offline. Updates: More › Threat intelligence updates.")
        }
        SectionCard("Anti-phishing & link scanner", ProtectionStatus.PROTECTED) {
            Dim("Share a link to BANKVAULT, paste it, or scan a QR code. Works offline. It warns – it doesn't filter your browser (that's what Private DNS below does).")
            Button(onClick = { onNavigate(Tab.SCAN) }) { Text("Scan a link") }
        }
        SectionCard("Malicious-site blocking (whole phone)", dnsStatus) {
            if (dns.active) Dim("Private DNS: ${dns.serverName}${dns.knownFilteringProvider?.let { " – ${it.blocks}" } ?: ""}")
            IssueList(dnsIssues, fixer)
        }
        SectionCard("Privacy & tracker protection", if (privacyIssues.isEmpty()) ProtectionStatus.PROTECTED else ProtectionStatus.MANUAL_SETUP_REQUIRED) {
            if (privacyIssues.isEmpty()) Dim("Trackers are filtered by your Private DNS provider. BANKVAULT never inspects encrypted traffic.")
            IssueList(privacyIssues, fixer)
        }
        SectionCard("Stealth mode", stealthStatus) {
            if (managed) Dim("Locked apps are hidden from the launcher automatically (Device Owner).")
            IssueList(stealthIssues, fixer)
        }
        SectionCard("Authentication", authStatus) {
            Dim("Separate BANKVAULT PIN: set · Biometric: ${when (bio) { Biometric.Availability.USABLE -> "available"; Biometric.Availability.REENROLLED -> "paused"; Biometric.Availability.NOT_ENROLLED -> "not enrolled"; else -> "not available" }} · Policy: ${settings.authPolicy}")
            IssueList(authIssues, fixer)
        }
        SectionCard("Security monitoring", monitorStatus) {
            if (monitorIssues.isEmpty()) Dim("Watching permissions, VPN and settings. You'll get an alert if anything weakens protection.")
            IssueList(monitorIssues, fixer)
            Button(onClick = { onNavigate(Tab.LOG) }) { Text("View activity") }
        }
        Spacer(Modifier.height(24.dp))
    }
}
