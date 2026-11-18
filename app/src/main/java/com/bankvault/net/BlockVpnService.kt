package com.bankvault.net

import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.ParcelFileDescriptor
import com.bankvault.CrashReporter
import com.bankvault.core.vpn.PacketResponder
import java.io.FileInputStream
import java.io.FileOutputStream

/**
 * Only the locked apps are put inside this VPN (addAllowedApplication). Their packets are dropped;
 * TCP connects and DNS get an immediate refusal so the app shows "no internet" at once.
 * If no app needs blocking the VPN is stopped (an empty allow-list would capture EVERY app).
 */
class BlockVpnService : VpnService() {
    companion object { const val ACTION_STOP = "stop" }

    private var tun: ParcelFileDescriptor? = null
    private var reader: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        try {
            if (intent?.action == ACTION_STOP) { close(); stopSelf(); return START_NOT_STICKY }
            apply()
        } catch (e: Exception) {
            CrashReporter.recordHandled(this, "VPN", e)
            NetBlock.status.value = NetBlock.Status.Problem(e.message ?: e.javaClass.simpleName)
        }
        return START_STICKY
    }

    @Synchronized
    private fun apply() {
        val apps = NetBlock.blockedNow()
        if (apps.isEmpty()) {
            close(); NetBlock.status.value = if (com.bankvault.data.Store.netBlock.value) NetBlock.Status.NothingToBlock else NetBlock.Status.Off
            return
        }
        val b = Builder()
            .setSession("BANKVAULT network block")
            .addAddress("10.215.173.1", 32)
            .addAddress("fd00:b4b:7a17::1", 128)
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)
            .addDnsServer("10.215.173.53")
            .addDnsServer("fd00:b4b:7a17::53")
            .setMtu(1500)
            .setBlocking(true)
        val added = apps.filter { runCatching { b.addAllowedApplication(it) }.isSuccess }
        if (added.isEmpty()) { close(); NetBlock.status.value = NetBlock.Status.NothingToBlock; return }
        b.setUnderlyingNetworks(arrayOf())
        val newTun = b.establish()
        if (newTun == null) { NetBlock.status.value = NetBlock.Status.NeedsPermission; return }
        val old = tun; tun = newTun
        startReader(newTun)
        runCatching { old?.close() } // only after the new one is up: no gap
        NetBlock.status.value = NetBlock.Status.Blocking(added.size)
    }

    private fun startReader(fd: ParcelFileDescriptor) {
        reader?.interrupt()
        reader = Thread({
            val buf = ByteArray(32 * 1024)
            try {
                val out = FileOutputStream(fd.fileDescriptor)
                FileInputStream(fd.fileDescriptor).use { input ->
                    while (!Thread.currentThread().isInterrupted) {
                        val n = input.read(buf)
                        if (n < 0) break
                        if (n > 0) PacketResponder.respond(buf, n)?.let { runCatching { out.write(it) } }
                    }
                }
            } catch (_: Exception) { }
        }, "bv-vpn").apply { isDaemon = true; start() }
    }

    private fun close() {
        reader?.interrupt(); reader = null
        runCatching { tun?.close() }; tun = null
    }

    override fun onRevoke() {
        close()
        NetBlock.status.value = NetBlock.Status.Problem("The VPN was turned off (by you or another VPN app). Tap to turn it on again.")
        super.onRevoke()
    }

    override fun onDestroy() { close(); super.onDestroy() }
}
