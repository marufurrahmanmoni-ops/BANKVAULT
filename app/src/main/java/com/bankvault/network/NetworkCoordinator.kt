package com.bankvault.network

import com.bankvault.apps.InstalledApps
import com.bankvault.core.audit.AuditEvent
import com.bankvault.core.audit.AuditSink
import com.bankvault.core.audit.AuditType
import com.bankvault.core.network.AppRef
import com.bankvault.core.network.IsolationBackend
import com.bankvault.core.network.LockedNetworkRule
import com.bankvault.core.network.NetworkAccessState
import com.bankvault.core.network.NetworkIsolationEngine
import com.bankvault.data.NetworkMode
import com.bankvault.data.ProtectedAppDao
import com.bankvault.data.SettingsStore
import com.bankvault.root.RootFirewallBackend
import com.bankvault.vpn.VpnBlackholeBackend
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** App-level wrapper: selects the backend from Settings and keeps the engine in sync with the DB. */
class NetworkCoordinator(
    private val settings: SettingsStore,
    private val apps: ProtectedAppDao,
    private val installed: InstalledApps,
    private val root: RootFirewallBackend,
    private val vpn: VpnBlackholeBackend,
    val oem: OemManualBackend,
    private val audit: AuditSink,
    private val now: () -> Long,
) {
    private val mutex = Mutex()
    private val engine = NetworkIsolationEngine { backend() }
    private val _status = MutableStateFlow<List<NetworkIsolationEngine.AppNetworkStatus>>(emptyList())
    val status: StateFlow<List<NetworkIsolationEngine.AppNetworkStatus>> = _status
    private var lastStates = emptyMap<String, NetworkAccessState>()

    fun backend(): IsolationBackend? = when (settings.state.value.networkMode) {
        NetworkMode.NONE -> null
        NetworkMode.OEM_MANUAL -> oem
        NetworkMode.LOCAL_VPN -> vpn
        NetworkMode.ROOT_FIREWALL -> root
    }

    /** Load protected apps from DB (all locked) and push to the backend. Used at boot and on changes. */
    suspend fun reconcileFromStore() = mutex.withLock {
        val stored = apps.all()
        val refs = stored.mapNotNull { e -> installed.uidOf(e.packageName)?.let { AppRef(e.packageName, it) to e } }
        val known = engine.status().map { it.app }.toSet()
        (known - refs.map { it.first }.toSet()).forEach(engine::removeProtected)
        refs.forEach { (ref, e) -> if (ref !in known) engine.setProtected(ref, LockedNetworkRule(e.blockWifi, e.blockMobile)) }
        // Rules may have changed for known apps.
        refs.forEach { (ref, e) -> engine.setProtected(ref, LockedNetworkRule(e.blockWifi, e.blockMobile)) }
        publish(engine.reconcile())
    }

    suspend fun allow(pkg: String) = mutex.withLock { ref(pkg)?.let { publish(listOf(engine.allow(it)) + engine.status()) } }
    suspend fun block(pkg: String) = mutex.withLock { ref(pkg)?.let { publish(listOf(engine.block(it)) + engine.status()) } }
    suspend fun blockAll() = mutex.withLock { publish(engine.blockAll()); engine.status() }
    suspend fun verifyAll() = mutex.withLock { publish(engine.verifyAll()) }
    fun engineForEmergency(): NetworkIsolationEngine = engine

    suspend fun switchMode(mode: NetworkMode) {
        val old = backend()
        settings.update { it.copy(networkMode = mode) }
        if (old != null && old != backend()) runCatching { old.rollback() }
        reconcileFromStore()
    }

    private fun ref(pkg: String) = engine.status().firstOrNull { it.app.packageName == pkg }?.app

    private suspend fun publish(list: List<NetworkIsolationEngine.AppNetworkStatus>) {
        val current = engine.status()
        _status.value = current
        val newStates = current.associate { it.app.packageName to it.state }
        for ((pkg, st) in newStates) if (lastStates[pkg] != st) {
            val failure = st == NetworkAccessState.PROTECTION_INACTIVE || st == NetworkAccessState.PROTECTION_PENDING
            audit.record(AuditEvent(if (failure) AuditType.NETWORK_PROTECTION_FAILURE else AuditType.NETWORK_RESTRICTION_CHANGED,
                now(), pkg, "${lastStates[pkg] ?: "NEW"} -> $st via ${backend()?.kind ?: "none"}"))
        }
        lastStates = newStates
    }
}
