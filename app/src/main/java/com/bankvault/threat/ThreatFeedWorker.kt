package com.bankvault.threat

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.bankvault.BankVaultApp
import java.net.URL
import java.util.concurrent.TimeUnit
import javax.net.ssl.HttpsURLConnection

/**
 * Downloads `<feedUrl>` and `<feedUrl>.sig` over HTTPS (system CAs only, see
 * network_security_config.xml). Sends no device identifiers, no browsing data and no URLs the
 * owner scanned – it is a plain anonymous GET of a public file.
 */
class ThreatFeedWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {

    override suspend fun doWork(): Result {
        val graph = (applicationContext as BankVaultApp).graph
        val s = graph.settings.state.value
        if (!s.externalIntelEnabled || s.feedUrl.isBlank()) return Result.success()
        if (!s.feedUrl.startsWith("https://")) return Result.failure()
        return try {
            val body = fetch(s.feedUrl, MAX_BODY)
            val sig = String(fetch(s.feedUrl + ".sig", 4096))
            val err = graph.threats.acceptUpdate(body, sig)
            if (err == null) graph.settings.update { it.copy(threatDbVersion = graph.threats.info.value.version) }
            Result.success()
        } catch (_: Exception) {
            Result.retry()
        }
    }

    private fun fetch(url: String, limit: Int): ByteArray {
        val c = URL(url).openConnection() as HttpsURLConnection
        c.connectTimeout = 15_000; c.readTimeout = 30_000; c.instanceFollowRedirects = false
        c.setRequestProperty("User-Agent", "BANKVAULT")
        try {
            require(c.responseCode == 200) { "HTTP ${c.responseCode}" }
            c.inputStream.use { input ->
                val out = java.io.ByteArrayOutputStream(); val buf = ByteArray(8192); var total = 0
                while (true) { val n = input.read(buf); if (n < 0) break; total += n; require(total <= limit) { "Feed too large" }; out.write(buf, 0, n) }
                return out.toByteArray()
            }
        } finally { c.disconnect() }
    }

    companion object {
        private const val MAX_BODY = 8 * 1024 * 1024
        fun schedule(ctx: Context) {
            val req = PeriodicWorkRequestBuilder<ThreatFeedWorker>(12, TimeUnit.HOURS)
                .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.UNMETERED).build())
                .build()
            WorkManager.getInstance(ctx).enqueueUniquePeriodicWork("threat-feed", ExistingPeriodicWorkPolicy.UPDATE, req)
        }
    }
}
