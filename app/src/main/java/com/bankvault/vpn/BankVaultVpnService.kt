package com.bankvault.vpn

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import com.bankvault.BankVaultApp
import com.bankvault.core.audit.AuditEvent
import com.bankvault.core.audit.AuditType
import com.bankvault.core.network.Transport
import com.bankvault.core.vpn.VpnPlan
import com.bankvault.core.vpn.VpnPlanner
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.io.FileInputStream

/**
 * Mode D – local blackhole VPN.
 *
 * Only the locked banking apps are placed inside the tunnel (addAllowedApplication). Their packets
 * are read from the TUN fd and discarded without inspection. All other apps, and BANKVAULT itself,
 * are outside the VPN and keep normal Wi-Fi / Mobile Data access.
 *
 * Leak handling:
 *  - IPv4 and IPv6 default routes are both installed; DNS servers point inside the tunnel.
 *  - On re-plan the new interface is established BEFORE the old fd is closed, so a blocked app is
 *    never outside the tunnel during a policy change.
 *  - If the network type is unknown/switching, apps with any transport restriction are blocked.
 *  - The owner can additionally enable Android's Always-on VPN + "Block connections without VPN"
 *    (Settings > Network > VPN); note that lockdown applies to every app, not only banking apps.
 */
class BankVaultVpnService : VpnService() {

    companion object {
        const val ACTION_APPLY = "com.bankvault.vpn.APPLY"
        const val ACTION_STOP = "com.bankvault.vpn.STOP"
        private const val TAG = "BV-VPN"

        fun apply(ctx: Context) = ctx.startService(Intent(ctx, BankVaultVpnService::class.java).setAction(ACTION_APPLY))
        fun stop(ctx: Context) = ctx.startService(Intent(ctx, BankVaultVpnService::class.java).setAction(ACTION_STOP))
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var tun: ParcelFileDescriptor? = null
    private var drainThread: Thread? = null
    @Volatile private var transport: Transport? = null
    private lateinit var cm: ConnectivityManager

    private val netCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            val t = when {
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> Transport.WIFI
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> Transport.CELLULAR
                else -> null
            }
            if (t != transport) { transport = t; VpnController.transport = t; replan() }
        }
        override fun onLost(network: Network) { transport = null; VpnController.transport = null; replan() }
    }

    override fun onCreate() {
        super.onCreate()
        cm = getSystemService(ConnectivityManager::class.java)
        cm.registerDefaultNetworkCallback(netCallback)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> { teardown(); stopSelf(); return START_NOT_STICKY }
            // Started by the system for Always-on VPN (action android.net.VpnService) or by us.
            else -> scope.launch {
                if (VpnController.desired.isEmpty()) {
                    // Always-on start after boot: rebuild policy from the database (everything locked).
                    runCatching { (application as BankVaultApp).graph.network.reconcileFromStore() }
                }
                replan()
            }
        }
        return START_STICKY
    }

    @Synchronized
    private fun replan() {
        val plan = VpnPlanner.plan(VpnController.desired, transport, packageName)
        when (plan) {
            VpnPlan.Stop -> { teardown(); VpnController.status.value = VpnController.Status.Stopped }
            is VpnPlan.Establish -> establish(plan)
        }
    }

    private fun establish(plan: VpnPlan.Establish) {
        val b = Builder()
            .setSession("BANKVAULT banking isolation")
            .addAddress(plan.ipv4Address, plan.ipv4Prefix)
            .addAddress(plan.ipv6Address, plan.ipv6Prefix)
            .setMtu(plan.mtu)
            .setBlocking(true)
            .setMetered(false)
        plan.routes.forEach { (addr, prefix) -> b.addRoute(addr, prefix) }
        plan.dnsServers.forEach { b.addDnsServer(it) }
        val added = plan.blackholePackages.filter { pkg ->
            try { b.addAllowedApplication(pkg); true } catch (_: PackageManager.NameNotFoundException) { false }
        }
        if (added.isEmpty()) {
            // Never establish without an allowed-app list: that would capture every app.
            teardown(); VpnController.status.value = VpnController.Status.Error("No protected app could be added to the VPN"); return
        }
        // No underlying network: blocked apps see "no internet" instead of hanging.
        b.setUnderlyingNetworks(arrayOf())
        val newTun = try { b.establish() } catch (e: Exception) { null }
        if (newTun == null) {
            VpnController.status.value = VpnController.Status.Error("VPN permission missing or revoked")
            return
        }
        val old = tun
        tun = newTun
        startDrain(newTun)
        old?.close() // close only after the new interface is up
        VpnController.alwaysOn.value = isAlwaysOn
        VpnController.status.value = VpnController.Status.Running(plan.copy(blackholePackages = added.toSet()), transport, System.currentTimeMillis())
    }

    private fun startDrain(fd: ParcelFileDescriptor) {
        drainThread?.interrupt()
        drainThread = Thread({
            val buf = ByteArray(32 * 1024)
            try {
                FileInputStream(fd.fileDescriptor).use { input ->
                    while (!Thread.currentThread().isInterrupted) {
                        val n = input.read(buf)
                        if (n < 0) break
                        if (n > 0) VpnController.droppedPackets.value += 1 // drop; contents never parsed
                    }
                }
            } catch (_: Exception) { /* fd closed on re-plan/teardown */ }
        }, "bv-vpn-drain").apply { isDaemon = true; start() }
    }

    private fun teardown() {
        drainThread?.interrupt(); drainThread = null
        runCatching { tun?.close() }; tun = null
    }

    override fun onRevoke() {
        // Another VPN was started or the owner revoked consent: protection is OFF. Report it.
        Log.w(TAG, "VPN revoked")
        teardown()
        VpnController.status.value = VpnController.Status.Revoked
        scope.launch {
            (application as BankVaultApp).graph.audit.record(AuditEvent(AuditType.NETWORK_PROTECTION_FAILURE, System.currentTimeMillis(), null,
                "Local VPN was revoked by the system or another VPN app; banking network isolation is inactive"))
            (application as BankVaultApp).graph.alerts.protectionLost("Banking network isolation stopped: VPN was turned off.")
        }
        super.onRevoke()
    }

    override fun onDestroy() {
        runCatching { cm.unregisterNetworkCallback(netCallback) }
        teardown()
        if (VpnController.status.value is VpnController.Status.Running) VpnController.status.value = VpnController.Status.Stopped
        scope.cancel()
        super.onDestroy()
    }
}
