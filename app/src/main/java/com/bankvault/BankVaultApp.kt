package com.bankvault

import android.app.Application
import androidx.work.Configuration
import com.bankvault.monitor.AppMonitorService
import com.bankvault.threat.ThreatFeedWorker
import kotlinx.coroutines.launch

class BankVaultApp : Application(), Configuration.Provider {
    lateinit var graph: AppGraph
        private set

    override val workManagerConfiguration: Configuration
        get() = Configuration.Builder().setMinimumLoggingLevel(android.util.Log.WARN).build()

    override fun onCreate() {
        super.onCreate()
        CrashReporter.install(this)
        graph = AppGraph(this)
        graph.alerts.ensureChannels()
        graph.threats.load()
        ThreatFeedWorker.schedule(this)
        graph.scope.launch {
            graph.sessions.updateConfigs(graph.db.apps().all())
            graph.network.reconcileFromStore()
        }
        if (graph.pins.isSet()) AppMonitorService.startIfPossible(this)
    }
}
