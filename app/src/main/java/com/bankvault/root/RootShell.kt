package com.bankvault.root

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.TimeUnit

/**
 * Minimal `su` runner. Scripts are generated only by [com.bankvault.core.root.IptablesPlan],
 * which never interpolates user-controlled strings. No destructive commands are ever issued.
 */
object RootShell {
    data class Result(val exitCode: Int, val stdout: String, val stderr: String) { val ok get() = exitCode == 0 }

    @Volatile private var cachedRoot: Boolean? = null

    suspend fun isRootGranted(forceCheck: Boolean = false): Boolean {
        if (!forceCheck) cachedRoot?.let { return it }
        val r = run(listOf("id -u"), timeoutSec = 20) // first call triggers the root manager's consent prompt
        return (r.ok && r.stdout.trim() == "0").also { cachedRoot = it }
    }

    suspend fun run(commands: List<String>, timeoutSec: Long = 15): Result = withContext(Dispatchers.IO) {
        try {
            val p = ProcessBuilder("su").redirectErrorStream(false).start()
            p.outputStream.bufferedWriter().use { w ->
                for (c in commands) { w.write(c); w.write("\n") }
                w.write("exit\n")
            }
            if (!p.waitFor(timeoutSec, TimeUnit.SECONDS)) { p.destroyForcibly(); return@withContext Result(-2, "", "timeout") }
            Result(p.exitValue(), p.inputStream.bufferedReader().readText(), p.errorStream.bufferedReader().readText())
        } catch (e: Exception) {
            Result(-1, "", e.message ?: "su not available")
        }
    }
}
