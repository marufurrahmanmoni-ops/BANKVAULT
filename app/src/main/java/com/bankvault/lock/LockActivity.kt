package com.bankvault.lock

import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.OnBackPressedCallback
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.bankvault.data.Locker
import com.bankvault.data.Pin
import com.bankvault.data.Store
import com.bankvault.ui.C
import com.bankvault.ui.Dim
import com.bankvault.ui.Fingerprint
import com.bankvault.ui.PinPad
import com.bankvault.ui.Theme
import com.bankvault.ui.mmss
import com.bankvault.ui.rememberSafeScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Lock screen shown over a locked app (or when opening a hidden app from BANKVAULT). */
class LockActivity : FragmentActivity() {
    companion object {
        const val EXTRA_PKG = "pkg"
        const val EXTRA_OPEN = "open"   // launch the app after unlocking (used by the "Open" button)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= 33) setRecentsScreenshotEnabled(false)
        Store.init(this)
        val pkg = intent.getStringExtra(EXTRA_PKG) ?: return finish()
        val open = intent.getBooleanExtra(EXTRA_OPEN, false)
        val label = runCatching { packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg, PackageManager.MATCH_UNINSTALLED_PACKAGES)).toString() }.getOrDefault(pkg)
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) { override fun handleOnBackPressed() = goHome() })
        setContent { Theme { Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) { Screen(pkg, label, open) } } }
    }

    @Composable
    private fun Screen(pkg: String, label: String, open: Boolean) {
        val scope = rememberSafeScope()
        var msg by remember { mutableStateOf<String?>(null) }
        var wait by remember { mutableLongStateOf(Pin.waitMillis()) }
        var busy by remember { mutableStateOf(false) }
        val fp = Store.fingerprint && Fingerprint.available(this)

        fun success() {
            Locker.unlocked(applicationContext, pkg)
            if (open) runCatching {
                packageManager.getLaunchIntentForPackage(pkg)?.let { startActivity(it.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
            }
            finish()
        }

        LaunchedEffect(Unit) { if (fp && wait == 0L) Fingerprint.ask(this@LockActivity, "Unlock $label") { success() } }
        LaunchedEffect(wait) { if (wait > 0) { delay(1_000); wait = Pin.waitMillis() } }

        Box(Modifier.fillMaxSize().padding(16.dp), contentAlignment = Alignment.Center) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text("$label is locked", style = MaterialTheme.typography.headlineSmall, textAlign = TextAlign.Center)
                Dim("Enter your BANKVAULT PIN")
                if (wait > 0) Text("Too many wrong tries. Wait ${mmss(wait)}.", color = C.Bad)
                msg?.let { Text(it, color = C.Warn) }
                PinPad(enabled = wait == 0L && !busy, submitLabel = "Unlock") { pin ->
                    busy = true
                    scope.launch {
                        val r = withContext(Dispatchers.Default) { Pin.check(pin).also { pin.fill('\u0000') } }
                        busy = false
                        when (r) {
                            Pin.Result.Ok -> success()
                            is Pin.Result.Wrong -> msg = "Wrong PIN"
                            is Pin.Result.Wait -> wait = r.millis
                        }
                    }
                }
                if (fp) OutlinedButton(onClick = { Fingerprint.ask(this@LockActivity, "Unlock $label") { success() } }) { Text("Use fingerprint") }
                Spacer(Modifier.height(4.dp))
                TextButton(onClick = { goHome() }) { Text("Cancel") }
            }
        }
    }

    private fun goHome() {
        runCatching { startActivity(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
        finish()
    }

    override fun onStop() {
        super.onStop()
        if (!isChangingConfigurations && !isFinishing) finishAndRemoveTask()
    }
}
