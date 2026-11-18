package com.bankvault.ui

import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
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
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.bankvault.AppGraph
import com.bankvault.core.audit.AuditEvent
import com.bankvault.core.audit.AuditType
import com.bankvault.core.auth.AuthPolicy
import com.bankvault.core.compat.CompatEntry
import com.bankvault.core.compat.Support
import com.bankvault.core.util.wipe
import com.bankvault.data.NetworkMode
import com.bankvault.data.SecurityProfile
import com.bankvault.dns.PrivateDnsInspector
import com.bankvault.emergency.triggerEmergency
import com.bankvault.lock.Biometric
import com.bankvault.root.RootShell
import com.bankvault.security.PinRepository
import com.bankvault.threat.ThreatFeedWorker
import com.bankvault.vpn.VpnController
import kotlinx.coroutines.launch

@Composable
fun MoreScreen(activity: FragmentActivity, graph: AppGraph, fixer: Fixer) {
    val scope = rememberSafeScope()
    val settings by graph.settings.state.collectAsStateWithLifecycle()
    var pendingAction by remember { mutableStateOf<Pair<String, () -> Unit>?>(null) }
    var note by remember { mutableStateOf<String?>(null) }
    fun guarded(what: String, block: () -> Unit) { pendingAction = what to block }
    var resumeTick by remember { mutableStateOf(0) }
    val lifecycle = androidx.lifecycle.compose.LocalLifecycleOwner.current.lifecycle
    androidx.compose.runtime.DisposableEffect(lifecycle) {
        val obs = androidx.lifecycle.LifecycleEventObserver { _, e -> if (e == androidx.lifecycle.Lifecycle.Event.ON_RESUME) resumeTick++ }
        lifecycle.addObserver(obs); onDispose { lifecycle.removeObserver(obs) }
    }
    fun audit(detail: String) = scope.launch { graph.audit.record(AuditEvent(AuditType.SETTINGS_CHANGED, graph.clock.nowMillis(), null, detail)) }

    val vpnConsent = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        scope.launch {
            if (VpnService.prepare(activity) == null) { graph.network.switchMode(NetworkMode.LOCAL_VPN); audit("network mode=LOCAL_VPN"); note = null }
            else note = "VPN permission was not granted – network isolation is not active."
        }
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)) {
        note?.let { Text(it, color = BvColors.Warning) }

        // ---------------- Profiles ----------------
        SectionCard("Security profile") {
            SecurityProfile.entries.forEach { p ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    RadioButton(settings.profile == p, { guarded("Switch to ${p.title}") { scope.launch { applyProfile(graph, p); audit("profile=$p") } } })
                    Column { Text(p.title); Dim(profileDescription(p)) }
                }
            }
        }

        // ---------------- Permissions ----------------
        SectionCard("Permissions") {
            androidx.compose.runtime.key(resumeTick) {
            PermissionRow("Usage access", graph.tamper.hasUsageAccess(),
                "Lets BANKVAULT see which app is in front, so it can show its lock screen over a protected app. Nothing else is read.") {
                fixer.run(FixKind.USAGE_ACCESS)
            }
            PermissionRow("Display over other apps", graph.tamper.canDrawOverlays(),
                "Android only allows the lock screen to come to the front from the background with this permission.") {
                fixer.run(FixKind.OVERLAY)
            }
            PermissionRow("Notifications", graph.tamper.notificationsAllowed(),
                "Needed for the always-on status notification and protection alerts. Banking app names are hidden on the lock screen.") {
                fixer.run(FixKind.NOTIFICATIONS)
            }
            }
        }

        // ---------------- Network ----------------
        SectionCard("Network isolation method") {
            Dim("Blocks Wi-Fi and Mobile Data for locked banking apps only. Other apps are never affected.")
            NetworkMode.entries.forEach { m ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    RadioButton(settings.networkMode == m, {
                        guarded("Change network isolation to ${m.title}") {
                            scope.launch {
                                when (m) {
                                    NetworkMode.LOCAL_VPN -> { fixer.run(FixKind.ENABLE_VPN); audit("network mode=$m") }
                                    NetworkMode.ROOT_FIREWALL -> if (RootShell.isRootGranted(forceCheck = true)) { graph.network.switchMode(m); audit("network mode=$m") }
                                        else note = "Root access was not granted. Root mode requires an authorised root manager (e.g. Magisk) on a device you own."
                                    else -> { graph.network.switchMode(m); audit("network mode=$m") }
                                }
                            }
                        }
                    })
                    Column { Text(m.title); Dim(networkModeDescription(m)) }
                }
            }
            if (settings.networkMode == NetworkMode.LOCAL_VPN) {
                val st by VpnController.statusFlow.collectAsStateWithLifecycle()
                val dropped by VpnController.droppedPackets.collectAsStateWithLifecycle()
                Dim("VPN: ${st::class.simpleName}. Blocked packets: $dropped. Android shows a key icon while it runs. For extra safety you may turn on Settings > Network > VPN > BANKVAULT > Always-on (do NOT enable 'Block connections without VPN' – it would cut every app).")
            }
        }

        // ---------------- DNS ----------------
        SectionCard("DNS protection (all apps, no VPN)") {
            val dns = remember { PrivateDnsInspector.status(activity) }
            Dim(if (dns.active) "Private DNS active: ${dns.serverName}" else "Private DNS is not set to a hostname.")
            Dim("Android does not let apps change Private DNS. Open Settings > Network & internet > Private DNS (Realme/ColorOS: Settings > Connection & sharing > Private DNS) and enter one of these hostnames:")
            PrivateDnsInspector.PROVIDERS.forEach { p -> Dim("• ${p.hostname} – ${p.name}: ${p.blocks}") }
            OutlinedButton(onClick = { fixer.run(FixKind.PRIVATE_DNS) }) { Text("Set up Private DNS") }
            Dim("DNS-over-HTTPS is available only inside browsers that support it (e.g. Chrome: Settings > Privacy > Use secure DNS).")
        }

        // ---------------- Authentication ----------------
        SectionCard("Authentication") {
            val bio = Biometric.availability(activity)
            Text("Banking apps (default)", style = MaterialTheme.typography.labelLarge)
            PolicyChips(settings.authPolicy) { p -> guarded("Change app-unlock policy") { graph.settings.update { it.copy(authPolicy = p) }; audit("authPolicy=$p") } }
            Text("BANKVAULT settings", style = MaterialTheme.typography.labelLarge)
            PolicyChips(settings.settingsAuthPolicy) { p -> guarded("Change settings-unlock policy") { graph.settings.update { it.copy(settingsAuthPolicy = p) }; audit("settingsAuthPolicy=$p") } }
            if (bio != Biometric.Availability.USABLE) Dim("Strong biometric not usable now ($bio) – biometric policies fall back to PIN and show 'Degraded'.")
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("End sessions when screen turns off", Modifier.weight(1f))
                Switch(settings.endOnScreenOff, { v -> guarded("Change screen-off rule") { graph.settings.update { it.copy(endOnScreenOff = v) }; audit("endOnScreenOff=$v") } })
            }
            ChangePin(graph, "Change BANKVAULT PIN", PinRepository.Kind.MAIN)
            ChangePin(graph, "Change recovery PIN", PinRepository.Kind.RECOVERY)
        }

        // ---------------- Stealth ----------------
        SectionCard("Stealth mode") {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("Hide BANKVAULT icon")
                    Dim(if (settings.tileAdded) "Re-open via: long-press the 'Emergency Lock' Quick Settings tile, or share any link to BANKVAULT."
                        else "Add the 'Emergency Lock' tile to Quick Settings first – it is your way back in.")
                    if (!settings.tileAdded) OutlinedButton(onClick = { fixer.run(FixKind.ADD_TILE) }) { Text("Add tile") }
                }
                Switch(graph.stealth.isLauncherHidden(), { v ->
                    guarded(if (v) "Hide BANKVAULT icon" else "Show BANKVAULT icon") {
                        val ok = graph.stealth.setLauncherHidden(v, settings.tileAdded)
                        if (ok) { graph.settings.update { it.copy(stealthLauncherHidden = v) }; scope.launch { graph.audit.record(AuditEvent(AuditType.APP_VISIBILITY_CHANGED, graph.clock.nowMillis(), activity.packageName, "launcher hidden=$v")) } }
                        else note = "Add the Quick Settings tile before hiding the icon."
                    }
                }, enabled = settings.tileAdded || graph.stealth.isLauncherHidden())
            }
            Spacer(Modifier.height(8.dp))
            Text("Hiding banking apps", style = MaterialTheme.typography.labelLarge)
            if (graph.managed.canRestrict) Dim("Device Owner active: locked apps are suspended and hidden automatically; they reappear only during an authenticated session.")
            else Dim("Without Device Owner no app can hide another app's icon. Use your phone's built-in feature:\n" +
                "• Realme UI 3.0+: Settings > Security & privacy (or Privacy) > Hide apps. You set an access code (#…#) and open hidden apps by dialling it. Hidden apps' notifications and recent tasks are hidden too.\n" +
                "• Realme UI 2.0: Settings > Privacy > Hide apps. Realme UI R/Go/S/T editions do not support Hide apps.\n" +
                "• ColorOS / OPPO: Settings > Privacy > Hide apps (menu names vary by version).\n" +
                "Menu names vary by version. BANKVAULT cannot verify this setting, so it shows 'Manual Setup Required'.")
        }

        // ---------------- Threat intelligence ----------------
        SectionCard("Threat intelligence updates") {
            var url by remember { mutableStateOf(settings.feedUrl) }
            Dim("Optional. Downloads a signed threat database over HTTPS (unmetered network only). Nothing about you or your scans is uploaded. Off by default.")
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Enable signed feed", Modifier.weight(1f))
                Switch(settings.externalIntelEnabled, { v -> graph.settings.update { it.copy(externalIntelEnabled = v) }; audit("externalIntel=$v") })
            }
            OutlinedTextField(url, { url = it.trim() }, label = { Text("Feed URL (https://…)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            Row {
                TextButton(onClick = { if (url.isEmpty() || url.startsWith("https://")) { graph.settings.update { it.copy(feedUrl = url) }; audit("feed url changed") } }) { Text("Save") }
                TextButton(onClick = { ThreatFeedWorker.schedule(activity) }) { Text("Check now") }
            }
            if (graph.threats.verifier == null) Dim("This build has no feed public key, so updates will be rejected. See docs/CYBER_THREAT_PROTECTION.md.")
        }

        // ---------------- Compatibility ----------------
        CompatibilitySection(activity, graph, fixer)

        // ---------------- Recovery ----------------
        RecoverySection(activity, graph)

        Button(onClick = { triggerEmergency(activity, "more_screen") }, modifier = Modifier.fillMaxWidth()) { Text("Emergency lock") }
        Spacer(Modifier.height(24.dp))
    }

    pendingAction?.let { (what, block) ->
        ReAuthDialog(activity, graph, what, onDismiss = { pendingAction = null }) { pendingAction = null; block() }
    }
}

private fun profileDescription(p: SecurityProfile) = when (p) {
    SecurityProfile.BANKING_LOCKDOWN -> "Banking apps locked, network blocked while locked, hidden where supported."
    SecurityProfile.SAFE_INTERNET -> "Normal internet; malicious & phishing link warnings; DNS filtering recommended."
    SecurityProfile.MAXIMUM_SECURITY -> "Banking lockdown + threat intel + PIN and biometric + 1-minute sessions."
    SecurityProfile.PRIVATE_MODE -> "Strict privacy: tracker-filtering DNS, no external feed downloads, local-only reports."
    SecurityProfile.EMERGENCY_LOCKDOWN -> "Ends all sessions and applies every available restriction now."
}

private fun networkModeDescription(m: NetworkMode) = when (m) {
    NetworkMode.NONE -> "No network isolation (not recommended)."
    NetworkMode.OEM_MANUAL -> "Use the phone's own per-app Wi-Fi/Mobile data switch. Cannot be verified or lifted automatically during a session."
    NetworkMode.LOCAL_VPN -> "Locked apps are routed into a local tunnel that drops their traffic. No server, no inspection. Verified automatically."
    NetworkMode.ROOT_FIREWALL -> "iptables/ip6tables rules per app UID. Requires authorised root. Verified by reading live rules."
}

private suspend fun applyProfile(graph: AppGraph, p: SecurityProfile) {
    val bioOk = Biometric.availability(graph.context) == Biometric.Availability.USABLE
    graph.settings.update { s ->
        when (p) {
            SecurityProfile.MAXIMUM_SECURITY -> s.copy(profile = p, authPolicy = if (bioOk) AuthPolicy.PIN_AND_BIOMETRIC else AuthPolicy.PIN_ONLY,
                settingsAuthPolicy = if (bioOk) AuthPolicy.PIN_AND_BIOMETRIC else AuthPolicy.PIN_ONLY, endOnScreenOff = true)
            SecurityProfile.PRIVATE_MODE -> s.copy(profile = p, externalIntelEnabled = false, trackerWarnings = true)
            SecurityProfile.SAFE_INTERNET -> s.copy(profile = p, trackerWarnings = false)
            else -> s.copy(profile = p)
        }
    }
    if (p == SecurityProfile.MAXIMUM_SECURITY) graph.db.apps().all().forEach {
        graph.db.apps().upsert(it.copy(sessionDurationMs = minOf(it.sessionDurationMs, 60_000L), backgroundGraceMs = minOf(it.backgroundGraceMs, 30_000L)))
    }
    if (p == SecurityProfile.EMERGENCY_LOCKDOWN) { graph.emergency().trigger("profile"); graph.network.verifyAll() }
    if (p == SecurityProfile.BANKING_LOCKDOWN || p == SecurityProfile.MAXIMUM_SECURITY) graph.network.reconcileFromStore()
}

@Composable
private fun PermissionRow(title: String, granted: Boolean, why: String, open: () -> Unit) {
    Row(Modifier.padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(title + if (granted) " – granted" else " – not granted", color = if (granted) MaterialTheme.colorScheme.onSurface else BvColors.Warning)
            Dim(why)
        }
        TextButton(onClick = open) { Text(if (granted) "Review" else "Grant") }
    }
}

@Composable
private fun PolicyChips(current: AuthPolicy, onPick: (AuthPolicy) -> Unit) {
    Row(Modifier.horizontalScroll(rememberScrollState())) { AuthPolicy.entries.forEach { p ->
        FilterChip(current == p, { onPick(p) }, { Text(when (p) { AuthPolicy.PIN_ONLY -> "PIN"; AuthPolicy.BIOMETRIC_ONLY -> "Biometric"; AuthPolicy.PIN_AND_BIOMETRIC -> "PIN + Bio" }) },
            Modifier.padding(end = 4.dp))
    } }
}

/** Change requires the current PIN of the same kind (verified with the brute-force limiter). */
@Composable
private fun ChangePin(graph: AppGraph, title: String, kind: PinRepository.Kind) {
    val scope = rememberSafeScope()
    var open by remember { mutableStateOf(false) }
    var stage by remember { mutableStateOf(0) }
    var newPin by remember { mutableStateOf<CharArray?>(null) }
    var msg by remember { mutableStateOf<String?>(null) }
    TextButton(onClick = { open = !open; stage = 0; msg = null }) { Text(title) }
    if (!open) return
    Text(when (stage) { 0 -> "Current ${if (kind == PinRepository.Kind.MAIN) "" else "recovery "}PIN"; 1 -> "New PIN"; else -> "Repeat new PIN" })
    msg?.let { Text(it, color = BvColors.Warning) }
    PinPad(submitLabel = "Next") { pin ->
        scope.launch {
            when (stage) {
                0 -> when (val r = graph.pins.verify(kind, pin)) {
                    PinRepository.VerifyResult.Ok -> { stage = 1; msg = null }
                    is PinRepository.VerifyResult.LockedOut -> msg = "Locked for ${formatDuration(r.remainingMillis)}"
                    else -> msg = "Wrong PIN"
                }
                1 -> when (val v = com.bankvault.core.auth.PinPolicy.validate(pin)) {
                    com.bankvault.core.auth.PinPolicy.Result.Ok -> { newPin = pin.copyOf(); stage = 2; msg = null }
                    is com.bankvault.core.auth.PinPolicy.Result.Rejected -> msg = v.reason
                }
                else -> {
                    val n = newPin
                    if (n != null && n.contentEquals(pin)) {
                        graph.pins.set(kind, pin); msg = "PIN changed"; open = false
                        graph.audit.record(AuditEvent(AuditType.SETTINGS_CHANGED, graph.clock.nowMillis(), null, "${kind.name} PIN changed"))
                    } else { msg = "PINs do not match"; stage = 1 }
                    n?.wipe(); newPin = null
                }
            }
            pin.wipe()
        }
    }
}

/** Fix for a feature that is supported but not active yet; null = nothing the owner can do on this phone. */
private fun fixFor(f: com.bankvault.core.compat.Feature, realme: Boolean): Pair<FixKind, String>? = when (f) {
    com.bankvault.core.compat.Feature.BIOMETRIC -> FixKind.BIOMETRIC_ENROLL to "Enrol fingerprint"
    com.bankvault.core.compat.Feature.APP_LAUNCH_DETECTION -> FixKind.USAGE_ACCESS to "Turn on usage access"
    com.bankvault.core.compat.Feature.APP_SUSPEND, com.bankvault.core.compat.Feature.UNINSTALL_PROTECTION -> FixKind.DEVICE_OWNER_GUIDE to "How to set up (advanced)"
    com.bankvault.core.compat.Feature.APP_HIDE_LAUNCHER -> if (realme) FixKind.HIDE_APPS_GUIDE to "Use phone's Hide apps" else FixKind.DEVICE_OWNER_GUIDE to "How to set up (advanced)"
    com.bankvault.core.compat.Feature.PER_APP_NETWORK_BLOCK, com.bankvault.core.compat.Feature.PER_APP_WIFI_ONLY,
    com.bankvault.core.compat.Feature.NETWORK_VERIFICATION -> FixKind.ENABLE_VPN to "Turn on network block"
    com.bankvault.core.compat.Feature.PRIVATE_DNS_FILTERING -> FixKind.PRIVATE_DNS to "Set up Private DNS"
    com.bankvault.core.compat.Feature.EMERGENCY_TILE -> FixKind.ADD_TILE to "Add tile"
    else -> null
}

@Composable
private fun CompatibilitySection(activity: FragmentActivity, graph: AppGraph, fixer: Fixer) {
    val scope = rememberSafeScope()
    val settings by graph.settings.state.collectAsStateWithLifecycle()
    var rows by remember { mutableStateOf<List<CompatEntry>>(emptyList()) }
    var header by remember { mutableStateOf("") }
    var realme by remember { mutableStateOf(false) }
    fun load(root: Boolean) = scope.launch {
        val (p, m) = graph.profiler.matrix(root)
        realme = p.isRealmeOrOppo
        header = "${p.manufacturer} ${p.model} · API ${p.sdkInt} · patch ${p.securityPatch} · ROM ${p.oemVersion ?: "?"} · " +
            "Device Owner: ${p.isDeviceOwner} · Profile Owner: ${p.isProfileOwner} · Root: ${if (root) p.rootGranted else "not checked"}"
        val dnsOk = PrivateDnsInspector.status(activity).let { it.active && it.knownFilteringProvider != null }
        rows = m.map { e -> when (e.feature) {
            com.bankvault.core.compat.Feature.PRIVATE_DNS_FILTERING -> e.copy(active = dnsOk)
            com.bankvault.core.compat.Feature.EMERGENCY_TILE -> e.copy(active = graph.settings.state.value.tileAdded)
            else -> e
        } }
    }
    // Reload whenever settings change (e.g. a Fix button turned something on) and when returning to the screen.
    androidx.compose.runtime.LaunchedEffect(settings) { load(false) }
    val lifecycle = androidx.lifecycle.compose.LocalLifecycleOwner.current.lifecycle
    androidx.compose.runtime.DisposableEffect(lifecycle) {
        val obs = androidx.lifecycle.LifecycleEventObserver { _, e -> if (e == androidx.lifecycle.Lifecycle.Event.ON_RESUME) load(false) }
        lifecycle.addObserver(obs); onDispose { lifecycle.removeObserver(obs) }
    }
    SectionCard("Compatibility matrix") {
        Dim(header)
        Dim("Green = working now. Amber = can be turned on – tap the button. Grey \"Not possible\" = Android does not allow it on this phone; nothing is broken.")
        rows.forEach { r ->
            val fix = if (!r.active && r.support != Support.UNSUPPORTED) fixFor(r.feature, realme) else null
            val possible = r.active || fix != null
            Column(Modifier.padding(vertical = 6.dp)) {
                Row {
                    Text(r.feature.title, Modifier.weight(1f))
                    Text(when { r.active -> "Active"; possible -> "Not active"; else -> "Not possible" },
                        color = when { r.active -> BvColors.Good; possible -> BvColors.Warning; else -> BvColors.TextDim })
                }
                Text(r.support.label, color = if (r.support == Support.UNSUPPORTED) BvColors.TextDim else BvColors.Neutral, style = MaterialTheme.typography.labelMedium)
                Dim(r.note)
                if (fix != null) OutlinedButton(onClick = { fixer.run(fix.first) }) { Text(fix.second) }
            }
        }
        TextButton(onClick = { load(true) }) { Text("Check root access (shows root prompt)") }
    }
}

@Composable
private fun RecoverySection(activity: FragmentActivity, graph: AppGraph) {
    val scope = rememberSafeScope()
    var verified by remember { mutableStateOf(false) }
    var msg by remember { mutableStateOf<String?>(null) }
    SectionCard("Recovery") {
        Dim("If BANKVAULT ever misbehaves you are never locked out of your banking apps:\n" +
            "1. Use your recovery PIN below to release everything.\n" +
            "2. Without BANKVAULT: Settings > Apps > BANKVAULT > Force stop, then Uninstall. VPN and launch locking stop immediately; root rules are removed by 'Release everything' or a reboot.\n" +
            "3. Device Owner mode: use 'Release everything' (it removes owner status). Otherwise a factory reset is the only way to remove a Device Owner – see docs/RECOVERY.md.")
        msg?.let { Text(it, color = BvColors.Warning) }
        if (!verified) {
            Text("Enter recovery PIN", style = MaterialTheme.typography.labelLarge)
            PinPad(submitLabel = "Verify") { pin -> scope.launch {
                when (val r = graph.pins.verify(PinRepository.Kind.RECOVERY, pin)) {
                    PinRepository.VerifyResult.Ok -> { verified = true; msg = null; graph.recordRecovery("Recovery PIN accepted") }
                    is PinRepository.VerifyResult.LockedOut -> msg = "Locked for ${formatDuration(r.remainingMillis)}"
                    PinRepository.VerifyResult.NotSet -> msg = "No recovery PIN set"
                    else -> msg = "Wrong recovery PIN"
                }
                pin.wipe()
            } }
        } else {
            Button(onClick = { scope.launch {
                val pkgs = graph.protectedPackages()
                graph.managed.release(pkgs)
                graph.network.backend()?.rollback()
                graph.network.switchMode(NetworkMode.NONE)
                graph.stealth.setLauncherHidden(false, true)
                graph.settings.update { it.copy(stealthLauncherHidden = false) }
                graph.recordRecovery("Released all apps, removed network rules, restored launcher icon")
                msg = "All apps released and visible; network rules removed. Protection is now OFF until you re-enable it."
            } }) { Text("Release everything") }
            if (graph.managed.canRestrict) OutlinedButton(onClick = { scope.launch {
                graph.managed.relinquish(graph.protectedPackages()); graph.recordRecovery("Device/Profile Owner relinquished")
                msg = "Owner status removed. BANKVAULT can now be uninstalled normally."
            } }) { Text("Remove Device Owner status") }
            TextButton(onClick = { graph.expectReturn(); activity.startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${activity.packageName}"))) }) { Text("Open BANKVAULT in Android Settings") }
        }
    }
}
