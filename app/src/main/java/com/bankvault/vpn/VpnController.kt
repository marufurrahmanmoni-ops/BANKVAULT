package com.bankvault.vpn

import com.bankvault.core.network.AppRef
import com.bankvault.core.network.DesiredAccess
import com.bankvault.core.network.Transport
import com.bankvault.core.vpn.VpnPlan
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** Shared state between [VpnBlackholeBackend] (requests) and [BankVaultVpnService] (reality). */
object VpnController {
    sealed class Status {
        data object Stopped : Status()
        data class Running(val plan: VpnPlan.Establish, val transport: Transport?, val since: Long) : Status()
        data object Revoked : Status()
        data class Error(val message: String) : Status()
    }

    /** Current default transport as seen by the VPN service (null = unknown/switching). */
    @Volatile var transport: Transport? = null
    @Volatile var desired: Map<AppRef, DesiredAccess> = emptyMap()
    val status = MutableStateFlow<Status>(Status.Stopped)
    /** Count of dropped packets from blocked apps (count only – contents are never read). */
    val droppedPackets = MutableStateFlow(0L)

    val statusFlow: StateFlow<Status> get() = status
}
