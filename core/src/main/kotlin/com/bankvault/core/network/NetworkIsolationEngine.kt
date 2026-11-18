package com.bankvault.core.network

/**
 * Coordinates protected apps, sessions and the active backend.
 * Holds "requested" separately from "enforced" for every app so the UI can never confuse them.
 */
class NetworkIsolationEngine(private val backendProvider: suspend () -> IsolationBackend?) {

    data class AppNetworkStatus(
        val app: AppRef,
        val requested: DesiredAccess,
        val enforcement: Enforcement,
        val state: NetworkAccessState,
    )

    private val rules = linkedMapOf<AppRef, LockedNetworkRule>()
    private val unlocked = mutableSetOf<AppRef>()
    private val lastEnforcement = mutableMapOf<AppRef, Enforcement>()

    fun setProtected(app: AppRef, rule: LockedNetworkRule) { rules[app] = rule; lastEnforcement[app] = Enforcement.Pending }
    fun removeProtected(app: AppRef) { rules.remove(app); unlocked.remove(app); lastEnforcement.remove(app) }

    fun requested(app: AppRef): DesiredAccess {
        val rule = rules[app] ?: return DesiredAccess.ALLOW_ALL
        return if (app in unlocked) DesiredAccess.ALLOW_ALL else DesiredAccess.forLocked(rule)
    }

    suspend fun allow(app: AppRef): AppNetworkStatus { unlocked += app; return reconcile().first { it.app == app } }
    suspend fun block(app: AppRef): AppNetworkStatus { unlocked -= app; return reconcile().first { it.app == app } }
    suspend fun blockAll(): List<AppNetworkStatus> { unlocked.clear(); return reconcile() }

    /** Push the full policy set to the backend and read back the result. */
    suspend fun reconcile(): List<AppNetworkStatus> {
        val backend = backendProvider()
        val desired = rules.keys.associateWith { requested(it) }
        val results: Map<AppRef, Enforcement> = when {
            backend == null -> desired.mapValues { Enforcement.NoBackend }
            !backend.isAvailable() -> desired.mapValues { Enforcement.Failed("${backend.kind} unavailable") }
            else -> try {
                backend.apply(desired)
            } catch (e: Exception) {
                desired.mapValues { Enforcement.Failed(e.message ?: e.javaClass.simpleName) }
            }
        }
        lastEnforcement.putAll(results)
        return status()
    }

    /** Re-verify without changing anything (anti-tamper / dashboard refresh). */
    suspend fun verifyAll(): List<AppNetworkStatus> {
        val backend = backendProvider()
        for (app in rules.keys) {
            lastEnforcement[app] = when {
                backend == null -> Enforcement.NoBackend
                !backend.isAvailable() -> Enforcement.Failed("${backend.kind} unavailable")
                else -> try { backend.verify(app, requested(app)) } catch (e: Exception) { Enforcement.Failed(e.message ?: "verify failed") }
            }
        }
        return status()
    }

    fun status(): List<AppNetworkStatus> = rules.keys.map { app ->
        val req = requested(app)
        val enf = lastEnforcement[app] ?: Enforcement.Pending
        AppNetworkStatus(app, req, enf, NetworkStateResolver.resolve(req, app in unlocked, enf))
    }
}
