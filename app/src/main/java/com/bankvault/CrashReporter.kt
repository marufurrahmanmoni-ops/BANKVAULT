package com.bankvault

import android.content.Context
import android.os.Build
import android.util.Log
import java.io.File

/** Saves the last crash (class/method names only – never PINs) so it can be shared from the app. */
object CrashReporter {
    private fun file(ctx: Context) = File(ctx.filesDir, "last_crash.txt")

    fun install(ctx: Context) {
        val app = ctx.applicationContext
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { t, e ->
            runCatching { write(app, "CRASH in thread ${t.name}", e) }
            previous?.uncaughtException(t, e)
        }
    }

    fun recordHandled(ctx: Context, where: String, e: Throwable) {
        Log.e("BANKVAULT", "Handled error in $where", e)
        runCatching { write(ctx.applicationContext, "Handled error in $where (app kept running)", e) }
    }

    private fun write(ctx: Context, title: String, e: Throwable) {
        file(ctx).writeText(buildString {
            appendLine(title)
            appendLine("Time: ${java.util.Date()}")
            appendLine("App: ${BuildConfig.APPLICATION_ID} ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})")
            appendLine("Device: ${Build.MANUFACTURER} ${Build.MODEL} · Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT}) · ${Build.DISPLAY}")
            appendLine()
            append(Log.getStackTraceString(e))
        }.take(20_000))
    }

    fun read(ctx: Context): String? = runCatching { file(ctx).takeIf { it.exists() }?.readText() }.getOrNull()
    fun clear(ctx: Context) { runCatching { file(ctx).delete() } }
}
