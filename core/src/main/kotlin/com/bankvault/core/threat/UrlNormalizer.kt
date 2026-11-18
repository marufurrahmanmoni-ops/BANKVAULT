package com.bankvault.core.threat

import java.net.IDN
import java.net.URI

data class ParsedUrl(
    val scheme: String,
    val host: String,          // ASCII / punycode, lower case, no trailing dot
    val unicodeHost: String,
    val port: Int,
    val path: String,
    val hasUserInfo: Boolean,
    val queryKeys: List<String>,
    val isIpLiteral: Boolean,
) {
    /** Query values and fragments are dropped: they may carry tokens, OTPs or account numbers. */
    fun sanitized(): String = buildString {
        append(scheme).append("://").append(host)
        if (port != -1) append(':').append(port)
        append(path.ifEmpty { "/" })
    }
}

object UrlNormalizer {
    private val URL_IN_TEXT = Regex("""(?i)\b((?:https?://|www\.)[^\s<>"']+)""")
    private val IPV4 = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")

    /** Pull the first URL-looking token out of shared text (SMS, chat message, QR payload). */
    fun extract(text: String): String? = URL_IN_TEXT.find(text)?.value?.trimEnd('.', ',', ')', ']', '!', '?')

    fun parse(raw: String): ParsedUrl? {
        var s = raw.trim()
        if (s.isEmpty() || s.length > 4096) return null
        if (!Regex("^[a-zA-Z][a-zA-Z0-9+.-]*://").containsMatchIn(s)) s = "http://$s"
        val uri = try { URI(s.replace(" ", "%20")) } catch (_: Exception) { return null }
        val scheme = uri.scheme?.lowercase() ?: return null
        if (scheme != "http" && scheme != "https") return null
        // URI.host is null for IDN hosts; fall back to raw authority parsing.
        val authority = uri.rawAuthority ?: return null
        val hasUserInfo = authority.contains('@')
        var hostPort = authority.substringAfterLast('@')
        val isV6 = hostPort.startsWith("[")
        val hostRaw: String
        var port = -1
        if (isV6) {
            hostRaw = hostPort.substringAfter('[').substringBefore(']')
            hostPort.substringAfter("]:", "").toIntOrNull()?.let { port = it }
        } else {
            val idx = hostPort.lastIndexOf(':')
            if (idx > 0 && hostPort.substring(idx + 1).all(Char::isDigit) && idx < hostPort.length - 1) {
                port = hostPort.substring(idx + 1).toInt(); hostPort = hostPort.substring(0, idx)
            }
            hostRaw = hostPort
        }
        val decoded = try { java.net.URLDecoder.decode(hostRaw, "UTF-8") } catch (_: Exception) { hostRaw }
        val cleaned = decoded.trimEnd('.').lowercase()
        if (cleaned.isEmpty()) return null
        val ascii = if (isV6) cleaned else try { IDN.toASCII(cleaned, IDN.ALLOW_UNASSIGNED) } catch (_: Exception) { return null }
        val unicode = if (isV6) cleaned else try { IDN.toUnicode(ascii, IDN.ALLOW_UNASSIGNED) } catch (_: Exception) { cleaned }
        if (!isV6 && !Regex("^[a-z0-9.-]+$").matches(ascii.lowercase())) return null
        val keys = uri.rawQuery?.split('&')?.map { it.substringBefore('=') }?.filter { it.isNotEmpty() } ?: emptyList()
        return ParsedUrl(
            scheme = scheme,
            host = ascii.lowercase(),
            unicodeHost = unicode.lowercase(),
            port = if ((scheme == "http" && port == 80) || (scheme == "https" && port == 443)) -1 else port,
            path = uri.rawPath ?: "",
            hasUserInfo = hasUserInfo,
            queryKeys = keys,
            isIpLiteral = isV6 || IPV4.matches(ascii),
        )
    }
}
