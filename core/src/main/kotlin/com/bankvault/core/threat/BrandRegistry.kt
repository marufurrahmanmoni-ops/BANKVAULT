package com.bankvault.core.threat

/**
 * Brands that phishing in Bangladesh most often imitates, with their official registrable domains.
 *
 * This is a SEED list. Official domains must be re-verified before release and are updated
 * through the signed threat feed (section "brand" lines). A domain listed here is the only
 * thing BANKVAULT will ever call SAFE without a positive reputation result.
 *
 * Keywords shorter than 5 characters (e.g. "ebl", "dbbl") are matched only as a whole label or
 * by skeleton equality, never by substring, to avoid false positives on unrelated sites.
 * Generic words (e.g. "rocket") are deliberately not keywords.
 */
data class Brand(val name: String, val keywords: Set<String>, val officialDomains: Set<String>)

object BrandRegistry {
    val SEED: List<Brand> = listOf(
        Brand("bKash", setOf("bkash"), setOf("bkash.com")),
        Brand("Nagad", setOf("nagad"), setOf("nagad.com.bd")),
        Brand("Rocket (Dutch-Bangla Bank)", setOf("dutchbangla", "dbbl"), setOf("dutchbanglabank.com")),
        Brand("Upay", setOf("upay"), setOf("upaybd.com")),
        Brand("BRAC Bank", setOf("bracbank"), setOf("bracbank.com")),
        Brand("Islami Bank Bangladesh", setOf("islamibank", "ibbl"), setOf("islamibankbd.com")),
        Brand("Eastern Bank", setOf("ebl", "easternbank"), setOf("ebl.com.bd")),
        Brand("City Bank", setOf("citybank"), setOf("thecitybank.com")),
        Brand("Sonali Bank", setOf("sonalibank"), setOf("sonalibank.com.bd")),
        Brand("Bangladesh Bank", setOf("bangladeshbank"), setOf("bb.org.bd")),
        Brand("PayPal", setOf("paypal"), setOf("paypal.com")),
    )
}
