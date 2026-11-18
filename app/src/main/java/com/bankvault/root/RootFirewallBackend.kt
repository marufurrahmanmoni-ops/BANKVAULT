package com.bankvault.root

import android.content.Context
import com.bankvault.core.network.AppRef
import com.bankvault.core.network.BackendKind
import com.bankvault.core.network.DesiredAccess
import com.bankvault.core.network.Enforcement
import com.bankvault.core.network.IsolationBackend
import com.bankvault.core.root.IptablesPlan
import java.io.File

/**
 * Mode C – UID firewall with iptables + ip6tables on rooted devices.
 * Rules are not persistent in the kernel across reboot; [com.bankvault.monitor.BootReceiver]
 * re-applies them at BOOT_COMPLETED (there is a short window during boot before that runs –
 * documented in docs/NETWORK_SECURITY.md).
 */
class RootFirewallBackend(private val context: Context) : IsolationBackend {
    override val kind = BackendKind.ROOT_FIREWALL
    private val backupDir: File get() = File(context.filesDir, "fw").apply { mkdirs() }

    override suspend fun isAvailable() = RootShell.isRootGranted()

    override suspend fun apply(policies: Map<AppRef, DesiredAccess>): Map<AppRef, Enforcement> {
        if (!File(backupDir, "iptables.v4.bak").exists()) {
            val b = RootShell.run(IptablesPlan.backupCommands(backupDir.absolutePath))
            if (!b.ok) return policies.mapValues { Enforcement.Failed("Backup failed, no rules changed: ${b.stderr.take(120)}") }
        }
        val r = RootShell.run(IptablesPlan.applyCommands(policies), timeoutSec = 30)
        if (!r.ok) {
            // Partial state is worse than a known state: fall back to removing our chain entirely.
            RootShell.run(IptablesPlan.rollbackCommands())
            return policies.mapValues { Enforcement.Failed("iptables error: ${r.stderr.take(160)}") }
        }
        return policies.mapValues { (app, want) -> verify(app, want) }
    }

    override suspend fun verify(app: AppRef, expected: DesiredAccess): Enforcement {
        val v4 = RootShell.run(listOf("iptables -w -S ${IptablesPlan.CHAIN}"))
        val v6 = RootShell.run(listOf("ip6tables -w -S ${IptablesPlan.CHAIN}"))
        val j4 = RootShell.run(listOf("iptables -w -C OUTPUT -j ${IptablesPlan.CHAIN}")).ok
        val j6 = RootShell.run(listOf("ip6tables -w -C OUTPUT -j ${IptablesPlan.CHAIN}")).ok
        if (!v4.ok && !v6.ok && expected != DesiredAccess.ALLOW_ALL) return Enforcement.Failed("Firewall chain missing")
        return Enforcement.Verified(IptablesPlan.parseEnforced(v4.stdout, v6.stdout, app.uid, j4 && j6))
    }

    override suspend fun rollback(): Boolean = RootShell.run(IptablesPlan.rollbackCommands()).ok
}
