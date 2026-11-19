package com.bankvault.ui

import android.Manifest
import android.app.AppOpsManager
import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Process
import android.provider.Settings
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.core.graphics.drawable.toBitmap
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.bankvault.BuildConfig
import com.bankvault.CrashReporter
import com.bankvault.R
import com.bankvault.data.Locker
import com.bankvault.data.Pin
import com.bankvault.data.Relock
import com.bankvault.data.Store
import com.bankvault.data.Unlocks
import com.bankvault.hide.Hider
import com.bankvault.lock.LockActivity
import com.bankvault.net.NetBlock
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private data class AppItem(val pkg: String, val label: String, val icon: ImageBitmap?)

class MainActivity : FragmentActivity() {
    /** BANKVAULT itself is locked again whenever you leave it, except while a Settings page we opened is showing. */
    private var unlocked by mutableStateOf(false)
    private var openingSettings = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= 33) setRecentsScreenshotEnabled(false)
        Store.init(this)
        setContent { Theme { Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
            // Android 15+ draws apps edge-to-edge: keep content clear of the status and navigation bars.
            Box(Modifier.fillMaxSize().safeDrawingPadding()) { Root() }
        } } }
    }

    override fun onStart() { super.onStart(); openingSettings = false }
    override fun onStop() {
        super.onStop()
        if (!isChangingConfigurations && !openingSettings) unlocked = false
    }

    fun openSettings(vararg intents: Intent) {
        openingSettings = true
        for (i in intents) try { startActivity(i); return } catch (_: ActivityNotFoundException) { } catch (_: SecurityException) { }
        runCatching { startActivity(Intent(Settings.ACTION_SETTINGS)) }
    }

    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_LONG).show()

    // ---------------------------------------------------------------- root
    @Composable
    private fun Root() {
        var pinSet by remember { mutableStateOf(Store.pinSet()) }
        var report by remember { mutableStateOf(CrashReporter.read(this)) }
        report?.let { r ->
            AlertDialog(
                onDismissRequest = {},
                title = { Text("BANKVAULT had a problem") },
                text = { Text(r.lineSequence().take(4).joinToString("\n") + "\n\nPlease share this report with the developer. It contains no PINs or personal data.") },
                confirmButton = { Button(onClick = {
                    openingSettings = true
                    runCatching { startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, r), "Share report")) }
                    CrashReporter.clear(this); report = null
                }) { Text("Share report") } },
                dismissButton = { TextButton(onClick = { CrashReporter.clear(this); report = null }) { Text("Dismiss") } },
            )
        }
        when {
            !pinSet -> SetPin(first = true) { pinSet = true; unlocked = true }
            !unlocked -> UnlockSelf()
            else -> Home()
        }
    }

    // ---------------------------------------------------------------- set / change PIN
    @Composable
    private fun SetPin(first: Boolean, onDone: () -> Unit) {
        val scope = rememberSafeScope()
        var firstPin by remember { mutableStateOf<CharArray?>(null) }
        var msg by remember { mutableStateOf<String?>(null) }
        var busy by remember { mutableStateOf(false) }
        Column(Modifier.fillMaxSize().padding(20.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            if (first) { Text("BANKVAULT", style = MaterialTheme.typography.headlineMedium); Dim("App lock · Network access off · App hide") }
            Spacer(Modifier.height(12.dp))
            Text(if (firstPin == null) "Choose a 6–8 digit PIN" else "Enter the same PIN again", style = MaterialTheme.typography.titleMedium)
            Dim("Use a PIN different from your phone's screen lock.")
            msg?.let { Text(it, color = C.Warn) }
            PinPad(enabled = !busy, submitLabel = "Next") { pin ->
                val f = firstPin
                if (f == null) {
                    val err = Pin.validate(pin)
                    if (err != null) { msg = err; pin.fill('\u0000') } else { firstPin = pin; msg = null }
                } else if (!f.contentEquals(pin)) {
                    msg = "PINs did not match – start again"; f.fill('\u0000'); pin.fill('\u0000'); firstPin = null
                } else {
                    busy = true
                    scope.launch {
                        withContext(Dispatchers.Default) { Pin.set(pin) }
                        f.fill('\u0000'); pin.fill('\u0000'); firstPin = null; busy = false
                        toast(if (first) "PIN saved" else "PIN changed")
                        onDone()
                    }
                }
            }
        }
    }

    // ---------------------------------------------------------------- unlock BANKVAULT
    @Composable
    private fun UnlockSelf() {
        val scope = rememberSafeScope()
        var msg by remember { mutableStateOf<String?>(null) }
        var busy by remember { mutableStateOf(false) }
        var forgot by remember { mutableStateOf(false) }
        val fp = Store.fingerprint && Fingerprint.available(this)
        LaunchedEffect(Unit) { if (fp) Fingerprint.ask(this@MainActivity, "Unlock BANKVAULT") { unlocked = true } }
        Column(Modifier.fillMaxSize().padding(20.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            Spacer(Modifier.height(24.dp))
            Text("BANKVAULT", style = MaterialTheme.typography.headlineMedium)
            Dim("Enter your PIN")
            msg?.let { Text(it, color = C.Warn) }
            PinPad(enabled = !busy, submitLabel = "Unlock") { pin ->
                busy = true
                scope.launch {
                    val r = withContext(Dispatchers.Default) { Pin.check(pin).also { pin.fill('\u0000') } }
                    busy = false
                    when (r) {
                        Pin.Result.Ok -> unlocked = true
                        is Pin.Result.Wrong -> msg = "Wrong PIN"
                        is Pin.Result.Wait -> msg = "Too many wrong tries. Wait ${mmss(r.millis)}."
                    }
                }
            }
            if (fp) OutlinedButton(onClick = { Fingerprint.ask(this@MainActivity, "Unlock BANKVAULT") { unlocked = true } }) { Text("Use fingerprint") }
            TextButton(onClick = { forgot = true }) { Text("Forgot PIN?") }
        }
        if (forgot) AlertDialog(
            onDismissRequest = { forgot = false },
            title = { Text("Forgot PIN") },
            text = { Text("There is no secret master PIN. To start over: Settings › Apps › BANKVAULT › Storage › Clear data. " +
                "This only resets BANKVAULT – your other apps and their data are not touched, and all locks are removed.") },
            confirmButton = { TextButton(onClick = { forgot = false; openSettings(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$packageName"))) }) { Text("Open app settings") } },
            dismissButton = { TextButton(onClick = { forgot = false }) { Text("Close") } },
        )
    }

    // ---------------------------------------------------------------- home
    private fun hasUsageAccess(): Boolean = runCatching {
        getSystemService(AppOpsManager::class.java).unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), packageName) == AppOpsManager.MODE_ALLOWED
    }.getOrDefault(false)

    private fun notificationsOk() = Build.VERSION.SDK_INT < 33 ||
        ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED

    private fun loadApps(): List<AppItem> {
        val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        @Suppress("DEPRECATION")
        val visible = packageManager.queryIntentActivities(intent, 0).map { it.activityInfo.applicationInfo }
        // Apps currently hidden by BANKVAULT have no launcher entry; add them back to the list.
        val hidden = Store.hidden.value.mapNotNull { runCatching { packageManager.getApplicationInfo(it, PackageManager.MATCH_UNINSTALLED_PACKAGES) }.getOrNull() }
        return (visible + hidden).distinctBy { it.packageName }.filter { it.packageName != packageName }.map { ai ->
            AppItem(ai.packageName, packageManager.getApplicationLabel(ai).toString(),
                runCatching { packageManager.getApplicationIcon(ai).toBitmap(96, 96).asImageBitmap() }.getOrNull())
        }.sortedBy { it.label.lowercase() }
    }

    @Composable
    private fun Home() {
        val scope = rememberSafeScope()
        val locked by Store.locked.collectAsStateWithLifecycle()
        val hidden by Store.hidden.collectAsStateWithLifecycle()
        val netOn by Store.netBlock.collectAsStateWithLifecycle()
        val netStatus by NetBlock.statusFlow.collectAsStateWithLifecycle()
        val unlockedApps by Unlocks.unlocked.collectAsStateWithLifecycle()
        var apps by remember { mutableStateOf<List<AppItem>>(emptyList()) }
        var query by remember { mutableStateOf("") }
        var tick by remember { mutableIntStateOf(0) }
        var hideHelp by remember { mutableStateOf(false) }
        var changePin by remember { mutableStateOf(false) }
        var relock by remember { mutableStateOf(Store.relock) }
        var fingerprint by remember { mutableStateOf(Store.fingerprint) }
        val ownerMode = remember(tick) { Hider.available(this) }

        // Refresh permission state whenever we come back from Settings.
        val lifecycle = LocalLifecycleOwner.current.lifecycle
        DisposableEffect(lifecycle) {
            val o = LifecycleEventObserver { _, e -> if (e == Lifecycle.Event.ON_RESUME) tick++ }
            lifecycle.addObserver(o); onDispose { lifecycle.removeObserver(o) }
        }
        LaunchedEffect(Unit) { apps = withContext(Dispatchers.Default) { loadApps() }; Locker.refresh(applicationContext) }

        val notifLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { tick++ }
        val vpnLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            if (VpnService.prepare(this) == null) { Store.setNetBlock(true); NetBlock.update(applicationContext) }
            else toast("Network access off needs the VPN permission.")
        }
        fun turnOnNetBlock() {
            val consent = runCatching { VpnService.prepare(this) }.getOrNull()
            if (consent == null) { Store.setNetBlock(true); NetBlock.update(applicationContext) }
            else try { vpnLauncher.launch(consent) } catch (e: Exception) { CrashReporter.recordHandled(this, "vpn consent", e); toast("Could not ask for VPN permission") }
        }

        if (changePin) { SetPin(first = false) { changePin = false }; return }

        val usage = remember(tick) { hasUsageAccess() }
        val overlay = remember(tick) { Settings.canDrawOverlays(this) }
        val notif = remember(tick) { notificationsOk() }
        val ready = usage && overlay

        LazyColumn(Modifier.fillMaxSize().padding(horizontal = 16.dp)) {
            item {
                Spacer(Modifier.height(12.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("BANKVAULT", style = MaterialTheme.typography.headlineSmall, modifier = Modifier.weight(1f))
                    TextButton(onClick = { Locker.lockNow(applicationContext); toast("All apps locked") }) { Text("Lock all now") }
                }
            }
            // ---- status / permissions
            item {
                Section(if (ready) "✅ App lock is working" else "⚠️ App lock needs 2 permissions") {
                    PermissionRow("Usage access", usage, "Lets BANKVAULT see when a locked app is opened.") {
                        openSettings(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS, Uri.parse("package:$packageName")), Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS))
                    }
                    PermissionRow("Display over other apps", overlay, "Lets the lock screen appear on top of the locked app.") {
                        openSettings(Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, Uri.parse("package:$packageName")))
                    }
                    PermissionRow("Notifications (optional)", notif, "Shows that app lock is running.") {
                        if (Build.VERSION.SDK_INT >= 33) try { notifLauncher.launch(Manifest.permission.POST_NOTIFICATIONS) } catch (e: Exception) {
                            openSettings(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, packageName))
                        }
                    }
                }
            }
            // ---- network access off
            item {
                Section("Network access off") {
                    Row(Modifier.clickable { if (!netOn) turnOnNetBlock() else { Store.setNetBlock(false); NetBlock.update(applicationContext) } },
                        verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text("Block internet for locked apps")
                            Dim("Locked apps get no Wi-Fi or mobile data until you unlock them. Uses a local VPN on this phone – no server, nothing is read or sent. Other apps keep working.")
                        }
                        Switch(netOn, { on -> if (on) turnOnNetBlock() else { Store.setNetBlock(false); NetBlock.update(applicationContext) } })
                    }
                    Text(when (val s = netStatus) {
                        NetBlock.Status.Off -> "Off"
                        NetBlock.Status.NeedsPermission -> "VPN permission needed – turn the switch on again."
                        NetBlock.Status.NothingToBlock -> "On – no locked app needs blocking right now."
                        is NetBlock.Status.Blocking -> "On – internet blocked for ${s.apps} locked app(s)."
                        is NetBlock.Status.Problem -> s.message
                    }, color = when (netStatus) { is NetBlock.Status.Blocking -> C.Accent; is NetBlock.Status.Problem, NetBlock.Status.NeedsPermission -> C.Warn; else -> C.Dim },
                        style = MaterialTheme.typography.bodySmall)
                    if (netStatus is NetBlock.Status.Problem || (netOn && netStatus is NetBlock.Status.NeedsPermission))
                        TextButton(onClick = { turnOnNetBlock() }) { Text("Turn on again") }
                }
            }
            // ---- apps
            item {
                Section("Apps") {
                    Dim("Switch on the apps to lock. ${if (ownerMode) "Hidden apps disappear from the home screen while locked – open them here." else "Tap “Hide” to hide an app's icon."}")
                    OutlinedTextField(query, { query = it }, label = { Text("Search") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                    if (apps.isEmpty()) Dim("Loading apps…")
                }
            }
            items(apps.filter { query.isBlank() || it.label.contains(query, true) }.sortedByDescending { it.pkg in locked }, key = { it.pkg }) { app ->
                val isLocked = app.pkg in locked
                fun setLock(on: Boolean) {
                    Store.setLocked(app.pkg, on)
                    if (!on) { Unlocks.relock(app.pkg); Hider.unhide(applicationContext, app.pkg); Store.setHidden(app.pkg, false) }
                    Locker.refresh(applicationContext)
                }
                Column(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
                    Row(Modifier.fillMaxWidth().clickable { setLock(!isLocked) }.padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                        if (app.icon != null) Image(app.icon, null, Modifier.size(36.dp)) else Spacer(Modifier.size(36.dp))
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(app.label)
                            if (isLocked) Dim(if (app.pkg in unlockedApps) "Unlocked for now" else "Locked" +
                                (if (netOn) " · no internet" else "") + (if (app.pkg in hidden && ownerMode) " · hidden" else ""))
                        }
                        Switch(isLocked, { on -> setLock(on) })
                    }
                    if (isLocked) Row(Modifier.padding(start = 48.dp)) {
                        TextButton(onClick = {
                            if (ownerMode) { Store.setHidden(app.pkg, app.pkg !in hidden); Locker.refresh(applicationContext) } else hideHelp = true
                        }) { Text(if (app.pkg in hidden && ownerMode) "Unhide" else "Hide") }
                        TextButton(onClick = {
                            startActivity(Intent(this@MainActivity, LockActivity::class.java)
                                .putExtra(LockActivity.EXTRA_PKG, app.pkg).putExtra(LockActivity.EXTRA_OPEN, true))
                        }) { Text("Open") }
                    }
                }
            }
            // ---- settings
            item {
                Section("Settings") {
                    Text("Lock again", style = MaterialTheme.typography.labelLarge)
                    Relock.entries.forEach { r ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            RadioButton(relock == r, { relock = r; Store.relock = r }); Text(r.label)
                        }
                    }
                    Dim("Locked apps also lock again when the screen turns off.")
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("Unlock with fingerprint", Modifier.weight(1f))
                        Switch(fingerprint, { fingerprint = it; Store.fingerprint = it })
                    }
                    if (fingerprint && !Fingerprint.available(this@MainActivity)) Dim("No fingerprint is set up on this phone – PIN will be used.")
                    TextButton(onClick = { changePin = true }) { Text("Change PIN") }
                }
            }
            item { About() }
            item { Spacer(Modifier.height(24.dp)) }
        }

        if (hideHelp) AlertDialog(
            onDismissRequest = { hideHelp = false },
            title = { Text("Hide app icons") },
            text = {
                Column {
                    Text("Android only lets a “Device Owner” app hide other apps. Two options:")
                    Spacer(Modifier.height(8.dp))
                    Text("1. Use your phone's Hide apps (easy)", fontWeight = FontWeight.Bold)
                    Text("Realme: Settings › Security & privacy (or Privacy) › Hide apps. Set an access code like #1234#, pick the app. Open it later by dialling the code in the Phone app.")
                    Spacer(Modifier.height(8.dp))
                    Text("2. Make BANKVAULT Device Owner (advanced)", fontWeight = FontWeight.Bold)
                    Text("Needs a computer and removing all accounts (often a factory reset). Then run:")
                    Text(Hider.ADB_COMMAND, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                }
            },
            confirmButton = { TextButton(onClick = { hideHelp = false; openSettings(Intent(Settings.ACTION_SETTINGS)) }) { Text("Open Settings") } },
            dismissButton = { TextButton(onClick = {
                getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText("adb", Hider.ADB_COMMAND))
                toast("Command copied"); hideHelp = false
            }) { Text("Copy command") } },
        )
    }

    @Composable
    private fun PermissionRow(title: String, ok: Boolean, why: String, fix: () -> Unit) {
        Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text((if (ok) "✓ " else "✗ ") + title, color = if (ok) C.Accent else C.Warn)
                Dim(why)
            }
            if (!ok) Button(onClick = fix) { Text("Allow") }
        }
    }

    @Composable
    private fun About() {
        Section("About") {
            Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
                Image(painterResource(R.drawable.developer_photo), "Photo of Md. Marufur Rahman Moni", contentScale = ContentScale.Crop,
                    modifier = Modifier.size(110.dp).clip(CircleShape).border(3.dp, C.Accent, CircleShape))
                Spacer(Modifier.height(10.dp))
                Text("Md. Marufur Rahman Moni", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                Dim("Developer")
                Spacer(Modifier.height(8.dp))
                Text("BANKVAULT ${BuildConfig.VERSION_NAME}", color = C.Accent)
                Dim("Simple app lock. Your PIN never leaves this phone.")
            }
        }
    }
}
