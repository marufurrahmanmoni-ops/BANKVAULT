package com.bankvault.ui

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.TextButton
import androidx.compose.material3.Text
import androidx.compose.foundation.layout.Column
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.bankvault.AppGraph
import com.bankvault.lock.AuthPanel

/** Fresh authentication for sensitive settings ("separate authentication for security settings"). */
@Composable
fun ReAuthDialog(activity: FragmentActivity, graph: AppGraph, action: String, onDismiss: () -> Unit, onSuccess: () -> Unit) {
    val settings by graph.settings.state.collectAsStateWithLifecycle()
    Dialog(onDismissRequest = onDismiss, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
            Column {
                AuthPanel(activity, graph, settings.settingsAuthPolicy, "Confirm it's you", action, onSuccess = onSuccess)
                TextButton(onClick = onDismiss) { Text("Cancel") }
            }
        }
    }
}
