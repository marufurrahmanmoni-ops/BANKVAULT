package com.bankvault.core.emergency

import com.bankvault.core.audit.AuditEvent
import com.bankvault.core.audit.AuditSink
import com.bankvault.core.audit.AuditType
import com.bankvault.core.network.NetworkIsolationEngine
import com.bankvault.core.session.SessionManager
import com.bankvault.core.util.Clock

/** Suspends/hides protected apps where the platform allows it (Device Owner / Profile Owner). */
interface AppAccessController {
    /** @return packages for which the operation actually succeeded. */
    suspend fun restrict(packages: Set<String>): Set<String>
    suspend fun release(packages: Set<String>): Set<String>
    val canRestrict: Boolean
}

interface SensitiveStateWiper {
    suspend fun wipeTransientState()
    suspend fun lockDashboard()
}

/**
 * Executes the Emergency Lock sequence. Every step runs even if an earlier one fails, and the
 * result reports precisely what succeeded so the UI never claims more than was done.
 * It never touches calling, SIM, or system settings.
 */
class EmergencyLock(
    private val clock: Clock,
    private val sessions: SessionManager,
    private val network: NetworkIsolationEngine,
    private val access: AppAccessController,
    private val wiper: SensitiveStateWiper,
    private val audit: AuditSink,
    private val protectedPackages: () -> Set<String>,
) {
    data class Step(val name: String, val ok: Boolean, val detail: String)
    data class Result(val steps: List<Step>) { val fullySucceeded get() = steps.all { it.ok } }

    suspend fun trigger(source: String): Result {
        val steps = mutableListOf<Step>()
        suspend fun step(name: String, block: suspend () -> Pair<Boolean, String>) {
            steps += try { block().let { Step(name, it.first, it.second) } } catch (e: Exception) { Step(name, false, e.message ?: "error") }
        }
        step("End banking sessions") { val r = sessions.onEmergencyLock(); true to "${r.size} session(s) ended" }
        step("Re-apply network restrictions") {
            val st = network.blockAll()
            val ok = st.all { it.state.name.startsWith("BLOCKED") }
            ok to st.joinToString { "${it.app.packageName}=${it.state}" }.ifEmpty { "no protected apps" }
        }
        step("Suspend / hide protected apps") {
            if (!access.canRestrict) false to "Not available without Device Owner/Profile Owner"
            else {
                val want = protectedPackages(); val done = access.restrict(want)
                (done == want) to "${done.size}/${want.size} restricted"
            }
        }
        step("Clear sensitive temporary state") { wiper.wipeTransientState(); true to "cleared" }
        step("Lock dashboard") { wiper.lockDashboard(); true to "locked" }
        val result = Result(steps)
        audit.record(AuditEvent(AuditType.EMERGENCY_LOCK, clock.nowMillis(), null,
            "source=$source; " + steps.joinToString("; ") { "${it.name}:${if (it.ok) "ok" else "FAILED"}" }))
        return result
    }
}
