package com.bankvault.session

import com.bankvault.core.audit.AuditEvent
import com.bankvault.core.audit.AuditSink
import com.bankvault.core.audit.AuditType
import com.bankvault.core.session.SessionConfig
import com.bankvault.core.session.SessionEffect
import com.bankvault.core.session.SessionManager
import com.bankvault.core.util.Clock
import com.bankvault.data.ProtectedAppEntity
import com.bankvault.managed.ManagedDeviceController
import com.bankvault.network.NetworkCoordinator
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.util.concurrent.ConcurrentHashMap

/**
 * Turns SessionManager effects into real platform actions:
 *   Grant  -> unsuspend/unhide (managed) + network allow (VPN/root)
 *   Revoke -> network block + suspend/hide (managed)
 * Each action's real outcome is audited; nothing is assumed to have worked.
 */
class SessionCoordinator(
    private val clock: Clock,
    private val network: NetworkCoordinator,
    private val managed: ManagedDeviceController,
    private val audit: AuditSink,
    private val endOnScreenOff: () -> Boolean,
) {
    private val configs = ConcurrentHashMap<String, SessionConfig>()
    val manager = SessionManager(clock) { configs[it] ?: SessionConfig(endOnScreenOff = endOnScreenOff()) }

    private val _active = MutableStateFlow<Set<String>>(emptySet())
    val active: StateFlow<Set<String>> = _active

    fun updateConfigs(apps: List<ProtectedAppEntity>) {
        configs.clear()
        apps.forEach {
            configs[it.packageName] = runCatching {
                SessionConfig(it.sessionDurationMs, it.backgroundGraceMs.coerceAtMost(it.sessionDurationMs), endOnScreenOff())
            }.getOrDefault(SessionConfig(endOnScreenOff = endOnScreenOff()))
        }
    }

    fun syncActive() { _active.value = manager.activePackages() }

    fun isUnlocked(pkg: String) = pkg in manager.activePackages()

    suspend fun grant(pkg: String) = handle(listOf(manager.onAuthenticated(pkg)))
    suspend fun onForeground(pkg: String?) = handle(manager.onForegroundChanged(pkg))
    suspend fun tick() = handle(manager.tick())
    suspend fun screenOff() = handle(manager.onScreenOff())
    suspend fun reboot() = handle(manager.onReboot())
    suspend fun policyInvalid() = handle(manager.onPolicyInvalid())
    suspend fun endNow(pkg: String) = handle(manager.end(pkg))

    private suspend fun handle(effects: List<SessionEffect>) {
        for (e in effects) when (e) {
            is SessionEffect.Grant -> {
                val released = managed.release(setOf(e.packageName))
                network.allow(e.packageName)
                audit.record(AuditEvent(AuditType.SESSION_STARTED, clock.nowMillis(), e.packageName,
                    "duration=${(e.expiresAtElapsed - clock.elapsedMillis()) / 1000}s; unsuspended=${e.packageName in released}"))
            }
            is SessionEffect.Revoke -> {
                network.block(e.packageName)
                val restricted = managed.restrict(setOf(e.packageName))
                audit.record(AuditEvent(AuditType.SESSION_ENDED, clock.nowMillis(), e.packageName,
                    "reason=${e.reason}; suspended=${e.packageName in restricted}"))
            }
        }
        _active.value = manager.activePackages()
    }
}
