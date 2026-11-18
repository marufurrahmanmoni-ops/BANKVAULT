package com.bankvault.core.threat

/**
 * Offline URL risk analysis for the Link Scanner, Share-sheet and QR flows.
 *
 * Verdict rules (deliberately conservative to avoid false alarms):
 *  - CONFIRMED_MALICIOUS only when a trusted threat source lists the domain.
 *  - SAFE only for verified official brand domains, feed allowlist entries or user allowlist.
 *  - SUSPICIOUS when heuristic score >= [suspiciousThreshold].
 *  - Everything else is UNKNOWN – which the UI presents as "not verified", never as safe.
 */
class UrlAnalyzer(
    private val db: () -> ThreatDatabase,
    private val brands: List<Brand> = BrandRegistry.SEED,
    private val userAllow: () -> Set<String> = { emptySet() },
    private val userBlock: () -> Set<String> = { emptySet() },
    private val suspiciousThreshold: Int = 40,
) {
    companion object {
        val SHORTENERS = setOf(
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly", "shorturl.at",
            "s.id", "tiny.cc", "buff.ly", "rebrand.ly", "t.ly", "v.gd", "shorte.st", "bitly.com",
        )
        /** TLDs disproportionately used for abuse. Only adds weight; never decisive alone. */
        val RISKY_TLDS = setOf("zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf", "ga", "work", "rest", "cam", "icu", "sbs", "cfd")
        val CREDENTIAL_WORDS = listOf("login", "signin", "verify", "verification", "account", "secure", "update", "wallet", "otp", "pin", "kyc", "reward", "bonus", "offer", "unlock", "suspend")
        val SENSITIVE_PARAMS = setOf("pin", "otp", "password", "pass", "pwd", "token", "access_token", "session", "sid", "auth", "code", "card", "cvv", "account")
    }

    fun analyze(input: String): UrlReport {
        val raw = UrlNormalizer.extract(input) ?: input.trim()
        val p = UrlNormalizer.parse(raw)
            ?: return UrlReport(input, null, null, null, null, Verdict.UNKNOWN, emptySet(),
                listOf(Finding("UNPARSEABLE", Severity.INFO, "This is not a valid web address, so it could not be checked.")), 0)

        val findings = mutableListOf<Finding>()
        var score = 0
        fun add(code: String, sev: Severity, pts: Int, msg: String) { findings += Finding(code, sev, msg); score += pts }

        val host = p.host
        val reg = if (p.isIpLiteral) host else DomainUtils.registrable(host)
        val database = db()

        // ---- 1. User lists and threat intelligence (authoritative) ----
        if (userBlock().any { DomainUtils.isSameOrSubdomain(host, it) }) {
            return report(input, p, reg, Verdict.CONFIRMED_MALICIOUS, setOf(ThreatCategory.SCAM),
                listOf(Finding("USER_BLOCKLIST", Severity.CRITICAL, "You added this domain to your blocklist.")), 100)
        }
        val cats = database.lookup(host)
        if (cats.isNotEmpty()) {
            return report(input, p, reg, Verdict.CONFIRMED_MALICIOUS, cats,
                listOf(Finding("THREAT_INTEL", Severity.CRITICAL,
                    "Listed by threat intelligence as: ${cats.joinToString { it.name.lowercase().replace('_', ' ') }}.")), 100)
        }
        val official = brands.firstOrNull { b -> b.officialDomains.any { DomainUtils.isSameOrSubdomain(host, it) } }
        val allowlisted = official != null || database.isAllowlisted(host) || userAllow().any { DomainUtils.isSameOrSubdomain(host, it) }

        // ---- 2. Structural heuristics ----
        if (p.hasUserInfo) add("USERINFO", Severity.HIGH, 45, "The address contains an '@' before the host – a classic trick to hide the real destination.")
        if (p.isIpLiteral) add("IP_HOST", Severity.MEDIUM, 25, "The link points to a raw IP address instead of a named website.")
        if (p.scheme == "http") {
            val credentialish = CREDENTIAL_WORDS.any { p.path.lowercase().contains(it) || host.contains(it) }
            if (credentialish) add("NO_TLS_LOGIN", Severity.HIGH, 30, "The page asks for login/verification but is not encrypted (http).")
            else add("NO_TLS", Severity.LOW, 5, "The connection is not encrypted (http).")
        }
        if (p.port != -1) add("ODD_PORT", Severity.LOW, 10, "The link uses an unusual port (${p.port}).")
        if (!p.isIpLiteral) {
            val tld = DomainUtils.tld(host)
            if (tld in RISKY_TLDS) add("RISKY_TLD", Severity.LOW, 10, "The '.$tld' domain ending is frequently used by scam sites.")
            val depth = host.count { it == '.' }
            if (depth >= 4) add("DEEP_SUBDOMAIN", Severity.LOW, 10, "Unusually many sub-domains, often used to disguise the real site.")
            if (reg in SHORTENERS) add("SHORTENER", Severity.MEDIUM, 20, "This is a shortened link; its real destination is hidden. Expand it before opening.")
            if (host.split('.').any { it.startsWith("xn--") }) {
                add("PUNYCODE", Severity.MEDIUM, 15, "The address uses international characters (shown as ${p.unicodeHost}).")
            }
            for (label in p.unicodeHost.split('.')) {
                if (Homograph.hasMixedScripts(label)) { add("MIXED_SCRIPT", Severity.HIGH, 45, "'$label' mixes alphabets (e.g. Latin and Cyrillic) to imitate another site."); break }
                if (Homograph.isWholeScriptLatinLookalike(label) && label.length >= 4) { add("WHOLE_SCRIPT_SPOOF", Severity.HIGH, 40, "'$label' is written in look-alike letters from another alphabet."); break }
            }
        }
        val sensitive = p.queryKeys.filter { it.lowercase() in SENSITIVE_PARAMS }
        if (sensitive.isNotEmpty()) add("SENSITIVE_PARAMS", Severity.MEDIUM, 15, "The link carries sensitive-looking parameters (${sensitive.joinToString()}). Never send PINs or OTPs in a link.")

        // ---- 3. Brand impersonation ----
        if (official == null && !p.isIpLiteral) brandChecks(p, reg).forEach { (sev, pts, msg) -> add("BRAND_LOOKALIKE", sev, pts, msg) }

        // ---- 4. Verdict ----
        val verdict = when {
            allowlisted && score < suspiciousThreshold -> Verdict.SAFE
            score >= suspiciousThreshold -> Verdict.SUSPICIOUS
            else -> Verdict.UNKNOWN
        }
        if (verdict == Verdict.SAFE && official != null) findings += Finding("OFFICIAL", Severity.INFO, "Official ${official.name} domain.")
        if (verdict == Verdict.UNKNOWN) findings += Finding("NOT_VERIFIED", Severity.INFO,
            "No known threat, but this site is not verified. Do not enter PINs, OTPs or card details unless you are sure.")
        return report(input, p, reg, verdict, emptySet(), findings, score.coerceAtMost(100))
    }

    private fun brandChecks(p: ParsedUrl, reg: String): List<Triple<Severity, Int, String>> {
        val out = mutableListOf<Triple<Severity, Int, String>>()
        val siteLabelSk = Homograph.skeleton(DomainUtils.siteLabel(p.unicodeHost).replace("-", ""))
        val siteLabelRaw = DomainUtils.siteLabel(p.unicodeHost)
        val subLabels = p.unicodeHost.removeSuffix(DomainUtils.registrable(p.unicodeHost)).split('.', '-').filter { it.isNotEmpty() }
        for (b in brands) for (kw in (b.keywords + b.officialDomains.map { DomainUtils.siteLabel(it) }).distinct()) {
            val official = b.officialDomains.joinToString(" / ")
            // 5-letter brands (bkash, nagad) need an exact skeleton match: "nagar" is a real word.
            val distLimit = when { kw.length >= 9 -> 2; kw.length >= 6 -> 1; else -> 0 }
            when {
                siteLabelSk == kw ->
                    out += Triple(Severity.HIGH, 50, "Looks like ${b.name}, but the real ${b.name} site is $official.")
                distLimit > 0 && EditDistance.damerau(siteLabelSk, kw) <= distLimit ->
                    out += Triple(Severity.HIGH, 45, "'$siteLabelRaw' is a misspelling of ${b.name} (official: $official).")
                kw.length >= 5 && siteLabelSk.contains(kw) ->
                    out += Triple(Severity.MEDIUM, 30, "Uses the ${b.name} name in an unrelated domain ($reg). Official: $official.")
                subLabels.any { Homograph.skeleton(it) == kw } ->
                    out += Triple(Severity.HIGH, 45, "'${b.name}' appears only as a sub-domain of $reg – the real site is $official.")
                else -> continue
            }
        }
        // Report only the strongest brand signal so one site is not penalised several times.
        return out.maxByOrNull { it.second }?.let { listOf(it) } ?: emptyList()
    }

    private fun report(input: String, p: ParsedUrl, reg: String, v: Verdict, cats: Set<ThreatCategory>, f: List<Finding>, score: Int) =
        UrlReport(input, p.sanitized(), p.host, p.unicodeHost, reg, v, cats, f, score)
}
