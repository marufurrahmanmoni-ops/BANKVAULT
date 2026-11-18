package com.bankvault.ui

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.MoreHoriz
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.bankvault.AppGraph
import com.bankvault.BankVaultApp
import com.bankvault.lock.AuthPanel

enum class Tab(val label: String, val icon: ImageVector) {
    HOME("Security", Icons.Filled.Shield),
    APPS("Apps", Icons.Filled.Apps),
    SCAN("Scan", Icons.Filled.QrCodeScanner),
    LOG("Activity", Icons.Filled.History),
    MORE("More", Icons.Filled.MoreHoriz),
}

class MainActivity : FragmentActivity() {
    private val graph get() = (application as BankVaultApp).graph

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Protect BANKVAULT's own screens from screenshots, screen recording and the Recents thumbnail.
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        setRecentsScreenshotEnabled(false)
        setContent { BankVaultTheme { Root() } }
    }

    private var stoppedAt = 0L

    override fun onStop() {
        super.onStop()
        if (isChangingConfigurations) return
        // Leaving the app locks the dashboard – unless the owner just tapped a Fix button that opens Settings.
        if (graph.clock.elapsedMillis() < graph.returnGraceUntil) stoppedAt = graph.clock.elapsedMillis()
        else graph.dashboardUnlocked.value = false
    }

    override fun onStart() {
        super.onStart()
        if (stoppedAt > 0 && graph.clock.elapsedMillis() - stoppedAt > AppGraph.RETURN_GRACE_MS) graph.dashboardUnlocked.value = false
        stoppedAt = 0; graph.returnGraceUntil = 0
    }

    @Composable
    private fun Root() {
        var pinSet by rememberSaveable { mutableStateOf(graph.pins.isSet()) }
        var recovering by rememberSaveable { mutableStateOf(false) }
        val unlocked by graph.dashboardUnlocked.collectAsStateWithLifecycle()
        val settings by graph.settings.state.collectAsStateWithLifecycle()
        when {
            !pinSet -> OnboardingScreen(this@MainActivity, graph) {
                pinSet = true; graph.dashboardUnlocked.value = true
                com.bankvault.monitor.AppMonitorService.startIfPossible(this@MainActivity)
            }
            recovering -> ForgotPinScreen(graph) { recovering = false }
            !unlocked -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                androidx.compose.foundation.layout.Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    AuthPanel(this@MainActivity, graph, settings.settingsAuthPolicy, "BANKVAULT", "Unlock the security dashboard") {
                        graph.dashboardUnlocked.value = true
                    }
                    androidx.compose.material3.TextButton(onClick = { recovering = true }) { Text("Forgot PIN? Use recovery PIN") }
                }
            }
            else -> Dashboard()
        }
    }

    @Composable
    private fun Dashboard() {
        var tab by rememberSaveable { mutableStateOf(Tab.HOME) }
        Scaffold(
            containerColor = MaterialTheme.colorScheme.background,
            bottomBar = {
                NavigationBar(containerColor = MaterialTheme.colorScheme.surface) {
                    Tab.entries.forEach { t ->
                        NavigationBarItem(selected = tab == t, onClick = { tab = t }, icon = { Icon(t.icon, t.label) }, label = { Text(t.label) })
                    }
                }
            },
        ) { pad ->
            Box(Modifier.padding(pad)) { FixHost(this@MainActivity, graph, onNavigate = { tab = it }) { fixer ->
                when (tab) {
                    Tab.HOME -> HomeScreen(this@MainActivity, graph, fixer, onNavigate = { tab = it })
                    Tab.APPS -> AppsScreen(graph)
                    Tab.SCAN -> ScanScreen(graph, initialText = null)
                    Tab.LOG -> ActivityScreen(this@MainActivity, graph)
                    Tab.MORE -> MoreScreen(this@MainActivity, graph, fixer)
                }
            } }
        }
    }
}
