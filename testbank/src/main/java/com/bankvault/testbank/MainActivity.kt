package com.bankvault.testbank

import android.app.Activity
import android.app.Service
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Bundle
import android.os.IBinder
import android.util.Log
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL

/**
 * Probes used by docs/TEST_REPORT.md:
 *   IPv4  https://1.1.1.1/cdn-cgi/trace           (IP literal: no DNS involved)
 *   IPv6  https://[2606:4700:4700::1111]/cdn-cgi/trace
 *   DNS   InetAddress lookup of example.com
 *   HTTPS https://example.com/
 * Each probe prints OK/BLOCKED plus the active transport. Results are also logged with tag
 * "TestBank" so they can be collected with `adb logcat -s TestBank`.
 */
object Probes {
    suspend fun runAll(cm: ConnectivityManager): String = withContext(Dispatchers.IO) {
        val caps = cm.getNetworkCapabilities(cm.activeNetwork)
        val transport = when {
            caps == null -> "none"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "VPN"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "WIFI"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "CELLULAR"
            else -> "other"
        }
        val lines = mutableListOf("transport(as seen by TestBank)=$transport")
        lines += probe("IPv4") { http("https://1.1.1.1/cdn-cgi/trace") }
        lines += probe("IPv6") { http("https://[2606:4700:4700::1111]/cdn-cgi/trace") }
        lines += probe("DNS") { InetAddress.getAllByName("example.com").joinToString { it.hostAddress ?: "?" } }
        lines += probe("HTTPS") { http("https://example.com/") }
        lines.joinToString("\n").also { Log.i("TestBank", it.replace('\n', ' | ')) }
    }

    private inline fun probe(name: String, block: () -> String) =
        try { "$name: OK (${block().take(40).replace('\n', ' ')})" } catch (e: Exception) { "$name: BLOCKED (${e.javaClass.simpleName})" }

    private fun http(u: String): String {
        val c = URL(u).openConnection() as HttpURLConnection
        c.connectTimeout = 5_000; c.readTimeout = 5_000
        try { return "HTTP ${c.responseCode}" } finally { c.disconnect() }
    }
}

class MainActivity : Activity() {
    private val scope = MainScope()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val out = TextView(this).apply { textSize = 15f; setPadding(32, 32, 32, 32) }
        val run = Button(this).apply { text = "Run network probes" }
        val bg = Button(this).apply { text = "Start background pinger (test 6)" }
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; addView(run); addView(bg); addView(out) }
        setContentView(ScrollView(this).apply { addView(root) })
        val cm = getSystemService(ConnectivityManager::class.java)
        run.setOnClickListener { out.text = "Running…"; scope.launch { out.text = Probes.runAll(cm) } }
        bg.setOnClickListener { startService(Intent(this, BackgroundPinger::class.java)); out.text = "Background pinger started – see logcat -s TestBank" }
        scope.launch { out.text = Probes.runAll(cm) }
    }

    override fun onDestroy() { scope.cancel(); super.onDestroy() }
}

/** Keeps probing every 10 s while TestBank is in the background (acceptance test: background traffic). */
class BackgroundPinger : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    override fun onBind(intent: Intent?): IBinder? = null
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val cm = getSystemService(ConnectivityManager::class.java)
        scope.launch { repeat(60) { if (!isActive) return@launch; Probes.runAll(cm); delay(10_000) }; stopSelf() }
        return START_NOT_STICKY
    }
    override fun onDestroy() { scope.cancel(); super.onDestroy() }
}
