package com.bankvault.ui

import android.widget.Toast
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalContext
import com.bankvault.CrashReporter
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob

/**
 * Like rememberCoroutineScope(), but a failure inside a button action shows a message and is
 * saved to the crash report instead of closing the app. Still cancelled when the screen leaves.
 */
@Composable
fun rememberSafeScope(): CoroutineScope {
    val ctx = LocalContext.current.applicationContext
    val base = rememberCoroutineScope()
    return remember(base) {
        val handler = CoroutineExceptionHandler { _, e ->
            CrashReporter.recordHandled(ctx, "screen action", e)
            Toast.makeText(ctx, "Could not complete: ${e.message ?: e.javaClass.simpleName}", Toast.LENGTH_LONG).show()
        }
        CoroutineScope(base.coroutineContext + SupervisorJob(base.coroutineContext[Job]) + handler)
    }
}
