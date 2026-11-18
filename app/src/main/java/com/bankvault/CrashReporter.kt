package com.bankvault

import android.content.Context
import android.os.Build
import android.util.Log
import java.io.File

/**
 * Saves the stack trace of any crash (or any error caught by a background safety net) so the
 * owner can share it from the dashboard. Stack traces contain class/method names only – never
 * PINs, OTPs or banking data.
 */
object CrashReporter {
    private const val FILE = "last_crash.txt"
    private fun file(ctx: Context) = File(ctx.filesDir, FILE)

    fun install(ctx: Context) {
        val app = ctx.applicationContext
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { t, e ->
            runCatching { write(app, "CRASH in thread ${t.name}", e) }
            previous?.uncaughtException(t, e)
        }
    }

    /** For errors that were caught (so the app keeps running) but must still be visible. */
    fun recordHandled(ctx: Context, where: String, e: Throwable) {
        Log.e("BANKVAULT", "Handled error in $where", e)
        runCatching { write(ctx.applicationContext, "Handled error in $where (app kept running)", e) }
    }

    private fun write(ctx: Context, title: String, e: Throwable) {
        val text = buildString {
            appendLine(title)
            appendLine("Time: ${java.time.Instant.now()}")
            appendLine("App: ${BuildConfig.APPLICATION_ID} ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})")
            appendLine("Device: ${Build.MANUFACTURER} ${Build.MODEL} · Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT}) · ${Build.DISPLAY}")
            appendLine()
            append(Log.getStackTraceString(e))
        }
        file(ctx).writeText(text.take(20_000))
    }

    fun read(ctx: Context): String? = file(ctx).takeIf { it.exists() }?.readText()
    fun clear(ctx: Context) { file(ctx).delete() }
}
