# Cyber threat protection

BANKVAULT's threat module is *inspired by* enterprise DNS-security products; it does not use their branding or proprietary technology.

## Layers
1. **Device-wide DNS filtering (VPN-free):** Android Private DNS (DNS-over-TLS) set to a filtering resolver. BANKVAULT recommends providers,
   opens Settings and verifies the active hostname. Covers all apps and browsers. It is not a per-app firewall.
2. **Link / QR / Share scanner (offline):** `core/threat/UrlAnalyzer`.
3. **Signed local threat database:** bundled seed + optional signed updates.

## Verdicts
| Verdict | When |
|---|---|
| Confirmed malicious | Domain (or a parent) is in the threat DB or the owner's blocklist |
| Suspicious | Heuristic score ≥ 40 (look-alike brand, mixed scripts, '@' trick, IP host, http login page, …) |
| Safe | Only verified official brand domains, feed allowlist, or owner allowlist |
| Unknown | Everything else. Shown in grey and **never** as safe |

Heuristics: IDN normalisation (UTS-46 via `java.net.IDN`), mixed-script and whole-script homograph detection with a confusables
skeleton, Damerau-Levenshtein typosquat detection against brand labels (5-letter brands like *bkash*/*nagad* require an exact
skeleton match to avoid false positives such as *nagar*), brand-as-subdomain, brand-in-unrelated-domain, shorteners, risky TLDs,
sensitive query parameters. Shortened links are expanded only on request and only by asking known shortener hosts.

## Privacy
* Only `scheme://host/path` is stored – query strings and fragments (tokens, OTPs) are dropped before storage.
* Scans are never uploaded. The feed download is an anonymous HTTPS GET.
* No TLS interception, no user CA, `network_security_config` trusts system CAs only.

## Feed publishing
1. `tools/feed-signer/feed-signer.sh keygen ./keys` – keep the private key offline.
2. Put the printed public key into `FEED_PUBLIC_KEY_X509_B64` in `app/build.gradle.kts`.
3. Build a database (format: see `app/src/main/assets/threatdb/seed.txt`), raise `version`, set `expires`.
4. `feed-signer.sh sign keys/feed-private.pem threatdb.txt` → publish `threatdb.txt` and `threatdb.txt.sig` over HTTPS.
5. In the app: More → Threat intelligence updates → URL + enable.

## Sources (verify licence and rate limits before use)
* Google Safe Browsing / Web Risk: require API keys and have commercial-use terms. Do **not** call them from the APK with an
  embedded key; run a small server that queries them and publishes a signed BANKVAULT feed.
* Community feeds (e.g. abuse.ch URLhaus, PhishTank, OpenPhish community) have their own licences/attribution rules – check each.
* The bundled seed contains only reserved test domains (`.example`, `.test`) so tests are reproducible and no real site is accused.

## What it is not
BANKVAULT is not an antivirus: it does not scan installed APKs or files.
