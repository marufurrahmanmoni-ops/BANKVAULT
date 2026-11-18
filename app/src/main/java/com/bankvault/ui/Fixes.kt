package com.bankvault.ui

import android.Manifest
import android.app.StatusBarManager
import android.content.ActivityNotFoundException
import android.content.ComponentName
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.drawable.Icon
import android.net.Uri
import android.net.VpnService
import android.provider.Settings
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.bankvault.AppGraph
import com.bankvault.ClipboardGuard
import com.bankvault.R
import com.bankvault.data.NetworkMode
import com.bankvault.dns.PrivateDnsInspector
import com.bankvault.emergency.EmergencyTileService
import com.bankvault.root.RootShell
import kotlinx.coroutines.launch

/** PROBLEM = something is off and can be fixed now. RECOMMENDED = optional extra protection. LIMITATION = Android does not allow it; nothing is broken. */
enum class IssueLevel { PROBLEM, RECOMMENDED, LIMITATION }

enum class FixKind {
    USAGE_ACCESS, OVERLAY, NOTIFICATIONS, ENABLE_VPN, VPN_SETTINGS, RETRY_NETWORK, PRIVATE_DNS,
    USB_DEBUGGING, BIOMETRIC_ENROLL, ADD_TILE, DEVICE_OWNER_GUIDE, HIDE_APPS_GUIDE, ADD_APPS, ROOT_MODE, OEM_NETWORK_STEPS,
}

data class Issue(
    val id: String,
    val level: IssueLevel,
    val title: String,
    val why: String,
    val fix: FixKind? = null,
    val fixLabel: String = "Fix",
)

fun interface Fixer { fun run(kind: FixKind) }

/**
 * Hosts everything the Fix buttons need: Activity-result launchers (VPN consent, notification
 * permission), step-by-step dialogs for things Android only lets the owner do, and the logic that
 * actually applies a fix. [onChanged] is called after anything that may have changed a status.
 */
@Composable
fun FixHost(activity: FragmentActivity, graph: AppGraph, onNavigate: (Tab) -> Unit, content: @Composable (Fixer) -> Unit) {
    val scope = rememberCoroutineScope()
    var dialog by remember { mutableStateOf<FixKind?>(null) }
    fun toast(msg: String) = Toast.makeText(activity, msg, Toast.LENGTH_LONG).show()

    fun open(vararg intents: Intent) {
        graph.expectReturn()
        for (i in intents) {
            try { activity.startActivity(i); return } catch (_: ActivityNotFoundException) { } catch (_: SecurityException) { }
        }
        activity.startActivity(Intent(Settings.ACTION_SETTINGS))
    }
    val pkgUri = Uri.parse("package:${activity.packageName}")

    val vpnLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (VpnService.prepare(activity) == null) scope.launch {
            graph.network.switchMode(NetworkMode.LOCAL_VPN)
            toast("Network isolation turned on")
        } else toast("VPN permission was not given, so banking apps' internet is NOT blocked.")
    }
    val notifLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (!granted) open(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, activity.packageName))
    }

    val fixer = Fixer { kind ->
        when (kind) {
            FixKind.USAGE_ACCESS -> open(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS, pkgUri), Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS))
            FixKind.OVERLAY -> open(Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, pkgUri))
            FixKind.NOTIFICATIONS ->
                if (ContextCompat.checkSelfPermission(activity, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED)
                    notifLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                else open(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, activity.packageName))
            FixKind.ENABLE_VPN -> {
                val consent = VpnService.prepare(activity)
                if (consent != null) { graph.expectReturn(); vpnLauncher.launch(consent) }
                else scope.launch { graph.network.switchMode(NetworkMode.LOCAL_VPN); toast("Network isolation turned on") }
            }
            FixKind.VPN_SETTINGS -> open(Intent(Settings.ACTION_VPN_SETTINGS))
            FixKind.RETRY_NETWORK -> scope.launch { graph.network.reconcileFromStore(); toast("Restrictions re-applied") }
            FixKind.USB_DEBUGGING -> open(Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS))
            FixKind.BIOMETRIC_ENROLL -> open(
                Intent(Settings.ACTION_BIOMETRIC_ENROLL).putExtra(Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED, BiometricManager.Authenticators.BIOMETRIC_STRONG),
                Intent(Settings.ACTION_SECURITY_SETTINGS))
            FixKind.ADD_TILE -> {
                // Android 13+: system dialog that adds our Quick Settings tile in one tap.
                val sbm = activity.getSystemService(StatusBarManager::class.java)
                sbm.requestAddTileService(
                    ComponentName(activity, EmergencyTileService::class.java),
                    activity.getString(R.string.tile_label),
                    Icon.createWithResource(activity, R.drawable.ic_lock),
                    ContextCompat.getMainExecutor(activity),
                ) { result ->
                    if (result == StatusBarManager.TILE_ADD_REQUEST_RESULT_TILE_ADDED || result == StatusBarManager.TILE_ADD_REQUEST_RESULT_TILE_ALREADY_ADDED) {
                        graph.settings.update { it.copy(tileAdded = true) }
                        toast("Emergency Lock tile added to Quick Settings")
                    }
                }
            }
            FixKind.ADD_APPS, FixKind.OEM_NETWORK_STEPS -> onNavigate(Tab.APPS)
            FixKind.ROOT_MODE -> scope.launch {
                if (RootShell.isRootGranted(forceCheck = true)) { graph.network.switchMode(NetworkMode.ROOT_FIREWALL); toast("Root firewall turned on") }
                else toast("Root access not granted. Use VPN mode instead.")
            }
            FixKind.PRIVATE_DNS, FixKind.DEVICE_OWNER_GUIDE, FixKind.HIDE_APPS_GUIDE -> dialog = kind
        }
    }

    content(fixer)

    when (dialog) {
        FixKind.PRIVATE_DNS -> GuideDialog("Block malicious sites on the whole phone", onDismiss = { dialog = null },
            primary = "Open Settings" to { open(PrivateDnsInspector.settingsIntent()); dialog = null }) {
            Text("Android does not let any app change this setting, so do it once yourself:")
            Step(1, "Tap a hostname below to copy it.")
            Step(2, "Open Settings › Connection & sharing › Private DNS (Realme/ColorOS) or Network & internet › Private DNS.")
            Step(3, "Choose \"Private DNS provider hostname\", paste, Save.")
            Step(4, "Come back – BANKVAULT checks it automatically.")
            Spacer(Modifier.height(8.dp))
            PrivateDnsInspector.PROVIDERS.forEach { p ->
                OutlinedButton(onClick = { ClipboardGuard.copy(activity, p.hostname); toast("Copied ${p.hostname}") }, modifier = Modifier.fillMaxWidth()) {
                    Column { Text(p.hostname, fontFamily = FontFamily.Monospace); Text("${p.name} · ${p.blocks}", style = MaterialTheme.typography.bodySmall) }
                }
            }
        }
        FixKind.HIDE_APPS_GUIDE -> GuideDialog("Hide banking app icons", onDismiss = { dialog = null },
            primary = "Open Settings" to { open(Intent(Settings.ACTION_SETTINGS)); dialog = null }) {
            Text("Without Device Owner no app can hide another app's icon, but your phone can:")
            Step(1, "Settings › Security & privacy (or Privacy) › Hide apps.")
            Step(2, "Set a privacy password and an access code like #1234#.")
            Step(3, "Turn on your banking apps. Their icons, notifications and recent-task cards disappear.")
            Step(4, "To open them, dial the access code in the Phone app.")
            Dim("Realme UI R/Go/S/T editions do not have Hide apps. BANKVAULT cannot check this setting, so it stays 'Manual Setup Required' – that is expected.")
        }
        FixKind.DEVICE_OWNER_GUIDE -> GuideDialog("Hard-block banking apps (advanced)", onDismiss = { dialog = null }, primary = null) {
            Text("This makes locked banking apps unable to start at all, and hides them. It needs a computer and usually a factory reset.")
            Step(1, "Back up the phone. Remove all accounts (or factory reset).")
            Step(2, "Enable USB debugging and connect to a computer with adb.")
            Step(3, "Run this command:")
            val cmd = "adb shell dpm set-device-owner ${activity.packageName}/com.bankvault.managed.BankVaultAdminReceiver"
            OutlinedButton(onClick = { ClipboardGuard.copy(activity, cmd); toast("Command copied") }, modifier = Modifier.fillMaxWidth()) {
                Text(cmd, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
            }
            Step(4, "Re-add accounts, then turn USB debugging off.")
            Dim("Optional. Without it, BANKVAULT's lock screen + network block still protect you. Full guide: docs/DEVICE_OWNER_SETUP.md.")
        }
        else -> Unit
    }
}

@Composable
private fun Step(n: Int, text: String) = Row(Modifier.padding(vertical = 2.dp)) {
    Text("$n.", fontWeight = FontWeight.Bold, modifier = Modifier.width(22.dp)); Text(text)
}

@Composable
private fun GuideDialog(title: String, onDismiss: () -> Unit, primary: Pair<String, () -> Unit>?, body: @Composable () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = { Column(Modifier.verticalScroll(rememberScrollState())) { body() } },
        confirmButton = { if (primary != null) Button(onClick = primary.second) { Text(primary.first) } else TextButton(onClick = onDismiss) { Text("OK") } },
        dismissButton = { if (primary != null) TextButton(onClick = onDismiss) { Text("Close") } },
    )
}

/** Renders issues with their reason and a button that performs the fix. */
@Composable
fun IssueList(issues: List<Issue>, fixer: Fixer) {
    for (i in issues) {
        val color = when (i.level) { IssueLevel.PROBLEM -> BvColors.Warning; IssueLevel.RECOMMENDED -> BvColors.Neutral; IssueLevel.LIMITATION -> BvColors.TextDim }
        val tag = when (i.level) { IssueLevel.PROBLEM -> "Needs action"; IssueLevel.RECOMMENDED -> "Recommended"; IssueLevel.LIMITATION -> "Android limit – nothing is broken" }
        Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
            Text(tag, color = color, style = MaterialTheme.typography.labelSmall)
            Text(i.title, color = color, fontWeight = FontWeight.SemiBold)
            Dim(i.why)
            if (i.fix != null) Row(verticalAlignment = Alignment.CenterVertically) {
                if (i.level == IssueLevel.PROBLEM) Button(onClick = { fixer.run(i.fix) }) { Text(i.fixLabel) }
                else OutlinedButton(onClick = { fixer.run(i.fix) }) { Text(i.fixLabel) }
            }
        }
    }
}
