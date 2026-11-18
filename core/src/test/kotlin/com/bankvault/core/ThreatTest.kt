package com.bankvault.core

import com.bankvault.core.threat.*
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

class ThreatTest {
    private val now = 1_763_400_000_000L
    private fun body(version: Long, extra: String = "") = """
        BANKVAULT-THREATDB 1
        version $version
        issued ${now - 1000}
        expires ${now + 30L * 86_400_000}
        phishing bkash-reward-claim.example
        malware evil-dropper.test
        command_and_control c2.badnet.test
        ransomware locker.example
        unknownfuturecategory something.test
        allow example.org
        $extra
    """.trimIndent()

    private val db = ThreatDatabase.parse(body(7))
    private val analyzer = UrlAnalyzer({ db })
    private fun v(url: String) = analyzer.analyze(url).verdict

    @Test fun officialBrandDomainsAreSafe() {
        assertEquals(Verdict.SAFE, v("https://www.bkash.com/"))
        assertEquals(Verdict.SAFE, v("https://nagad.com.bd/offers"))
        assertEquals(Verdict.SAFE, v("https://www.dutchbanglabank.com/rocket/rocket.html"))
    }

    @Test fun threatIntelHitsAreConfirmedIncludingSubdomains() {
        val r = analyzer.analyze("https://login.bkash-reward-claim.example/verify?pin=12345")
        assertEquals(Verdict.CONFIRMED_MALICIOUS, r.verdict)
        assertTrue(ThreatCategory.PHISHING in r.categories)
        assertEquals(Verdict.CONFIRMED_MALICIOUS, v("http://evil-dropper.test/app.apk"))
        assertTrue(ThreatCategory.COMMAND_AND_CONTROL in analyzer.analyze("c2.badnet.test").categories)
    }

    @Test fun lookalikesAreSuspicious() {
        assertEquals(Verdict.SUSPICIOUS, v("https://bkash.com.account-verify.xyz/login"))  // brand as subdomain
        assertEquals(Verdict.SUSPICIOUS, v("https://bkаsh.com/"))                          // Cyrillic 'а'
        assertEquals(Verdict.SUSPICIOUS, v("https://" + java.net.IDN.toASCII("bkаsh.com") + "/"))                   // same, punycode form
        assertEquals(Verdict.SUSPICIOUS, v("https://bkash.net/"))                          // right name, wrong domain
        assertEquals(Verdict.SUSPICIOUS, v("http://paypa1.com/signin"))                    // digit swap
        assertEquals(Verdict.SUSPICIOUS, v("https://dutchbanglabnak.com/"))                // transposition
        assertEquals(Verdict.SUSPICIOUS, v("http://user@192.168.4.20/nagad/login"))        // userinfo + IP
    }

    @Test fun brandInUnrelatedDomainIsFlagged() {
        val r = analyzer.analyze("http://nagad-bonus-offer.top/claim")
        assertEquals(Verdict.SUSPICIOUS, r.verdict)
        assertTrue(r.findings.any { it.code == "BRAND_LOOKALIKE" })
    }

    @Test fun unfamiliarSitesAreUnknownNotSafeNotMalicious() {
        assertEquals(Verdict.UNKNOWN, v("https://github.com/"))
        assertEquals(Verdict.UNKNOWN, v("https://www.prothomalo.com/"))
        assertEquals(Verdict.UNKNOWN, v("https://nagar.com.bd/"))   // real word close to "nagad"
        assertEquals(Verdict.UNKNOWN, v("https://rocketchat.com/"))  // generic word, not a brand keyword
        assertEquals(Verdict.SAFE, v("https://example.org/"))       // feed allowlist
    }

    @Test fun shortenerIsNotSafe() {
        val r = analyzer.analyze("https://bit.ly/3xYz")
        assertFalse(r.verdict == Verdict.SAFE)
        assertTrue(r.findings.any { it.code == "SHORTENER" })
    }

    @Test fun sanitizedUrlDropsQueryAndFragment() {
        val r = analyzer.analyze("https://www.bkash.com/pay?otp=482915&token=abc#frag")
        assertEquals("https://www.bkash.com/pay", r.sanitized)
        assertFalse(r.sanitized!!.contains("482915"))
    }

    @Test fun extractsUrlFromSmsText() {
        val sms = "Apnar bKash account bondho hobe. Ekhoni verify korun: http://bkash-reward-claim.example/kyc. Dhonnobad"
        assertEquals("http://bkash-reward-claim.example/kyc", UrlNormalizer.extract(sms))
        assertEquals(Verdict.CONFIRMED_MALICIOUS, analyzer.analyze(sms).verdict)
    }

    @Test fun userListsOverride() {
        val a = UrlAnalyzer({ db }, userAllow = { setOf("mybank.test") }, userBlock = { setOf("scam.test") })
        assertEquals(Verdict.SAFE, a.analyze("https://mybank.test/").verdict)
        assertEquals(Verdict.CONFIRMED_MALICIOUS, a.analyze("https://pay.scam.test/").verdict)
    }

    @Test fun garbageInputIsUnknown() {
        assertEquals(Verdict.UNKNOWN, v("not a url at all ::::"))
        assertEquals(Verdict.UNKNOWN, v("javascript:alert(1)"))
    }

    // ---------- signed feed ----------

    private val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private fun sign(b: ByteArray) = Base64.getEncoder().encodeToString(
        Signature.getInstance("SHA256withECDSA").apply { initSign(kp.private); update(b) }.sign())
    private val verifier = SignedFeedVerifier(mapOf("k1" to SignedFeedVerifier.publicKeyFromBase64(Base64.getEncoder().encodeToString(kp.public.encoded))))

    @Test fun signedFeedAccepted() {
        val b = body(8).toByteArray()
        val r = verifier.verify(b, sign(b), "k1", currentVersion = 7, now = now)
        assertTrue(r is SignedFeedVerifier.Result.Accepted)
        assertEquals(4, (r as SignedFeedVerifier.Result.Accepted).db.size)
    }

    @Test fun tamperedRollbackExpiredUnknownKeyRejected() {
        val b = body(8).toByteArray(); val s = sign(b)
        val tampered = body(8, "allow bkash-reward-claim.example").toByteArray()
        assertTrue(verifier.verify(tampered, s, "k1", 7, now) is SignedFeedVerifier.Result.Rejected)
        assertTrue(verifier.verify(b, s, "k1", 8, now) is SignedFeedVerifier.Result.Rejected)          // replay
        assertTrue(verifier.verify(b, s, "k1", 7, now + 60L * 86_400_000) is SignedFeedVerifier.Result.Rejected) // expired
        assertTrue(verifier.verify(b, s, "other", 7, now) is SignedFeedVerifier.Result.Rejected)
        assertNotNull(db)
    }
}
