package com.bankvault.ui

import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.TextButton
import androidx.compose.material3.Text
import androidx.compose.ui.Modifier
import androidx.fragment.app.FragmentActivity
import com.bankvault.BankVaultApp

/**
 * Share-sheet target ("Scan link with BANKVAULT"). Scanning does not require unlocking – it only
 * analyses the shared text. It is also a documented recovery path when the launcher icon is hidden.
 */
class ShareReceiverActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        val graph = (application as BankVaultApp).graph
        val text = intent?.takeIf { it.action == Intent.ACTION_SEND }?.getStringExtra(Intent.EXTRA_TEXT)
        setContent {
            BankVaultTheme {
                Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    Column {
                        TextButton(onClick = { startActivity(Intent(this@ShareReceiverActivity, MainActivity::class.java)); finish() }) { Text("Open BANKVAULT") }
                        ScanScreen(graph, initialText = text, source = "share_sheet")
                    }
                }
            }
        }
    }
}
