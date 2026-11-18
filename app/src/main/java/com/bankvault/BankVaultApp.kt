package com.bankvault

import android.app.Application
import com.bankvault.data.Store
import com.bankvault.monitor.MonitorService

class BankVaultApp : Application() {
    override fun onCreate() {
        super.onCreate()
        CrashReporter.install(this)
        Store.init(this)
        if (Store.pinSet() && Store.lockedApps().isNotEmpty()) MonitorService.start(this)
    }
}
