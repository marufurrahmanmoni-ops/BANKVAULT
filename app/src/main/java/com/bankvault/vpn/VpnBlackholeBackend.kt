package com.bankvault.vpn

import android.content.Context
import android.net.VpnService
import com.bankvault.core.network.AppRef
import com.bankvault.core.network.BackendKind
import com.bankvault.core.network.DesiredAccess
import com.bankvault.core.network.Enforcement
import com.bankvault.core.network.IsolationBackend
import com.bankvault.core.vpn.VpnPlan
import com.bankvault.core.vpn.VpnPlanner
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeoutOrNull

class VpnBlackholeBackend(private val context: Context) : IsolationBackend {
    override val kind = BackendKind.LOCAL_VPN

    /** VpnService.prepare() returns null only when the owner already approved BANKVAULT's VPN. */
    override suspend fun isAvailable() = VpnService.prepare(context) == null

    override suspend fun apply(policies: Map<AppRef, DesiredAccess>): Map<AppRef, Enforcement> {
        VpnController.desired = policies
        BankVaultVpnService.apply(context)
        // Wait for the service to reflect the new desired set (or report an error).
        withTimeoutOrNull(4_000) {
            while (true) {
                if (consistent(policies) || VpnController.status.value is VpnController.Status.Error) break
                delay(100)
            }
        }
        return policies.mapValues { (app, want) -> verify(app, want) }
    }

    override suspend fun verify(app: AppRef, expected: DesiredAccess): Enforcement {
        val st = VpnController.status.value
        if (st is VpnController.Status.Error) return Enforcement.Failed(st.message)
        if (st is VpnController.Status.Revoked) return Enforcement.Failed("VPN revoked")
        val transport = VpnController.transport
        val shouldBeInTunnel = VpnPlanner.plan(mapOf(app to expected), transport, context.packageName) is VpnPlan.Establish
        val isInTunnel = st is VpnController.Status.Running && app.packageName in st.plan.blackholePackages
        return if (shouldBeInTunnel == isInTunnel) Enforcement.Verified(expected)
        else Enforcement.Verified(if (isInTunnel) DesiredAccess(false, false) else DesiredAccess.ALLOW_ALL) // mismatch -> PENDING in UI
    }

    private fun consistent(p: Map<AppRef, DesiredAccess>): Boolean {
        val st = VpnController.status.value
        val transport = VpnController.transport
        val plan = VpnPlanner.plan(p, transport, context.packageName)
        return when (plan) {
            VpnPlan.Stop -> st is VpnController.Status.Stopped
            is VpnPlan.Establish -> st is VpnController.Status.Running && st.plan.blackholePackages == plan.blackholePackages
        }
    }

    override suspend fun rollback(): Boolean {
        VpnController.desired = emptyMap(); BankVaultVpnService.stop(context); return true
    }
}
