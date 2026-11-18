package com.bankvault.core.threat

/**
 * Registrable-domain approximation. A full Public Suffix List is shipped via the signed threat
 * feed in production; this embedded subset covers the suffixes that matter most for Bangladesh
 * and common global ones so the analyzer still works offline.
 */
object DomainUtils {
    private val MULTI_LABEL_SUFFIXES = setOf(
        "com.bd", "net.bd", "org.bd", "gov.bd", "edu.bd", "ac.bd", "mil.bd", "info.bd", "co.bd",
        "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.in", "net.in", "org.in", "gov.in",
        "com.pk", "com.my", "com.sg", "co.jp", "com.br", "co.za", "com.cn", "com.hk",
    )

    fun registrable(host: String): String {
        val labels = host.trimEnd('.').lowercase().split('.').filter { it.isNotEmpty() }
        if (labels.size <= 2) return labels.joinToString(".")
        val last2 = labels.takeLast(2).joinToString(".")
        return if (last2 in MULTI_LABEL_SUFFIXES) labels.takeLast(3).joinToString(".") else last2
    }

    /** The label users "read" as the site name, e.g. "bkash" for www.bkash.com, "nagad" for nagad.com.bd. */
    fun siteLabel(host: String): String = registrable(host).substringBefore('.')

    fun tld(host: String): String = host.trimEnd('.').substringAfterLast('.')

    /** host itself and every parent domain, most specific first. */
    fun suffixChain(host: String): List<String> {
        val labels = host.trimEnd('.').lowercase().split('.')
        return (0 until labels.size - 1).map { labels.drop(it).joinToString(".") }.ifEmpty { listOf(host) }
    }

    fun isSameOrSubdomain(host: String, domain: String): Boolean =
        host == domain || host.endsWith(".$domain")
}
