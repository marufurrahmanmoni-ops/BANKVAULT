package com.bankvault.lock

import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.OnBackPressedCallback
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.TextButton
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import com.bankvault.BankVaultApp
import com.bankvault.core.auth.AuthPolicy
import com.bankvault.ui.BankVaultTheme
import kotlinx.coroutines.launch

/**
 * Shown in front of a protected app that was opened while locked.
 * Cancel/back always goes to the HOME screen, never back into the banking app.
 * FLAG_SECURE prevents screenshots/screen recording of this screen (only this screen –
 * Android gives no way to protect another app's windows).
 */
class LockActivity : FragmentActivity() {
    companion object { const val EXTRA_PACKAGE = "pkg" }

    private val graph get() = (application as BankVaultApp).graph

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        setRecentsScreenshotEnabled(false)
        val pkg = intent.getStringExtra(EXTRA_PACKAGE) ?: return finish()
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) { override fun handleOnBackPressed() = goHome() })

        lifecycleScope.launch {
            val entity = graph.db.apps().get(pkg) ?: return@launch finish() // no longer protected
            val label = entity.label
            val policy = entity.authPolicy?.let { runCatching { AuthPolicy.valueOf(it) }.getOrNull() } ?: graph.settings.state.value.authPolicy
            setContent {
                BankVaultTheme {
                    Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                        var granting by remember { mutableStateOf(false) }
                        Box(Modifier.fillMaxSize().padding(16.dp), contentAlignment = Alignment.Center) {
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                if (!granting) AuthPanel(this@LockActivity, graph, policy,
                                    title = "$label is protected",
                                    subtitle = "Enter your BANKVAULT PIN (not your phone's screen-lock PIN)",
                                    packageName = pkg) {
                                    granting = true
                                    lifecycleScope.launch {
                                        try {
                                            graph.sessions.grant(pkg)
                                        } catch (e: Exception) {
                                            com.bankvault.CrashReporter.recordHandled(this@LockActivity, "unlock $pkg", e)
                                        }
                                        graph.installed.launchIntent(pkg)?.let { runCatching { startActivity(it.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) } }
                                        finish()
                                    }
                                } else Text("Opening $label…")
                                TextButton(onClick = { goHome() }) { Text("Cancel") }
                            }
                        }
                    }
                }
            }
        }
    }

    private fun goHome() {
        startActivity(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        finish()
    }

    /** If the user leaves the lock screen without authenticating, do not linger in recents. */
    override fun onStop() {
        super.onStop()
        if (!isChangingConfigurations) finishAndRemoveTask()
    }
}
