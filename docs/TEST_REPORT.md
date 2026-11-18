# Test report

**Date:** 2026-11-19 · **Build environments:** (1) authoring sandbox without Android SDK – core tests via bundled Kotlin compiler; (2) GitHub Actions `ubuntu-latest` – full Gradle build.

## Summary – read this first

| Layer | Status |
|---|---|
| `:core` security logic (43 unit tests) | **Compiled and run: 43/43 PASS** – raw output in [`test-results/core-unit-tests.txt`](test-results/core-unit-tests.txt) |
| Threat-feed signing tool ↔ app verifier | **Run: PASS** (openssl-signed feed accepted, tampered copy rejected) |
| `:core` tests under real Gradle + JUnit 4 (GitHub Actions) | **PASS** (`.github/workflows/android.yml`, run 44369865777) |
| `:app` and `:testbank` Android modules | **COMPILED** on GitHub Actions (AGP 8.10.1, Kotlin 2.1.20, compileSdk 36) – 1 deprecation warning, 0 errors |
| Debug APKs | **BUILT** – downloadable as workflow artifacts `bankvault-debug-apk`, `testbank-debug-apk` |
| Emulator end-to-end smoke test (Android 14 & 15, `tools/ci/smoke.py`) | **20/20 PASS on both** – run 44403555031 |
| Real Realme phone | **NOT RUN by CI** – owner testing |
| On-device acceptance tests 1–15 | **NOT RUN** – need a physical phone. Procedures below |

No result in this file is marked PASS unless it was actually executed. The 15 acceptance tests are therefore **NOT RUN**,
with the unit tests that already prove the underlying logic listed next to each.

## Emulator end-to-end results (executed in CI, every push)

Google API emulators, API 34 and API 35, BANKVAULT + TestBank installed, permissions granted via adb (as the Fix buttons would).

| Step | API 34 | API 35 |
|---|---|---|
| Launch, onboarding (PIN + recovery PIN) | PASS | PASS |
| App picker lists TestBank; protect it | PASS | PASS |
| "Turn on network block" Fix button → VPN verified, dashboard *Blocked* | PASS | PASS |
| Opening TestBank while locked shows BANKVAULT lock screen | PASS | PASS |
| Locked: IPv4, IPv6, DNS, HTTPS all refused (fail fast, `ConnectException`) | PASS | PASS |
| Other apps keep internet | PASS | PASS |
| Wrong PIN rejected; correct PIN opens TestBank with internet | PASS | PASS |
| Emergency Lock → lock screen + network blocked again | PASS | PASS |
| Scanner: test phishing domain = Confirmed malicious; share-sheet look-alike = Suspicious | PASS | PASS |
| About shows developer | PASS | PASS |
| Force-stop + restart; 1 500 random monkey events | PASS, no crash | PASS, no crash |

Bugs found by this test and fixed: TestBank missing permission (crash); intermittent Keystore "busy" error crashing a UI action
(now serialised + retried, UI actions crash-safe, crash reports shown on the dashboard); blocked apps hanging on DNS timeouts and
staying offline briefly after unlock on Android 14 (VPN now answers TCP SYN with RST and DNS with REFUSED); emergency lock reporting
"FAILED" for steps the phone simply doesn't support.

## Unit tests (executed)

| Area | Tests | What is proven |
|---|---|---|
| Auth | 9 | PIN policy; hash/verify; no plaintext in record; per-device pepper binding; rehash; progressive lockout; lockout survives reboot and clock rollback; biometric→PIN fallback; two-factor challenge |
| Sessions | 7 | Locked by default; expiry; OTP-copy grace; inactivity end; screen-off/emergency/reboot end; wall-clock change cannot extend; config limits |
| Network | 11 | Requested ≠ applied; Wi-Fi/Mobile states independent; lock-unlock-relock; backend failure/unverified/manual/tampered reporting; VPN never established with empty app list; IPv4+IPv6+DNS routes; per-transport + fail-closed; iptables touches only own chain, v4+v6; refuses system UIDs and unsafe paths; verification from live rules (missing IPv6 ⇒ not blocked); rollback |
| Threat | 12 | Official domains safe; threat-DB hits incl. subdomains; look-alikes (Cyrillic, punycode, wrong TLD, digit swap, transposition, userinfo+IP); brand in unrelated domain; unfamiliar ⇒ UNKNOWN (incl. "nagar", "rocketchat"); shortener not safe; query/fragment stripped; URL extracted from SMS text; user lists; garbage input; signed feed accept; tamper/replay/expiry/unknown-key reject |
| Packet responder | 4 | IPv4/IPv6 TCP SYN → valid RST (checksums verified), DNS → REFUSED with same id, everything else silently dropped, no reply to RST |
| Misc | 4 | Audit redaction of OTP/PIN/account/token/email/URL query; green only for verified; compatibility matrix honesty; emergency lock reports failed steps |

## Acceptance tests (spec §23)

Setup for every device test: Realme/Android 14–16 phone you own · BANKVAULT debug APK · **TestBank** (`:testbank`) added as the
protected app (never a real bank) · Network method = Local VPN unless stated · `adb logcat -s TestBank BV-VPN` running.
TestBank probes: IPv4 literal `1.1.1.1`, IPv6 literal `2606:4700:4700::1111`, DNS lookup, HTTPS to `example.com`.

| # | Scenario | Expected | Actual | Status | Technical explanation / unit evidence |
|---|---|---|---|---|---|
| 1 | Unlock phone with normal screen PIN | Phone unlocks; BANKVAULT unaffected | – | NOT RUN | BANKVAULT PIN is independent (`PinRepository`) |
| 2 | Second person opens TestBank | BANKVAULT lock screen appears within ~0.5 s | – | NOT RUN | UsageStats ACTIVITY_RESUMED + SAW background-launch exemption. Best-effort |
| 3 | Wrong PIN / cancel | Access denied; cancel goes to Home; lockout after 3 wrong | – | NOT RUN | `AuthTest.progressiveLockout`, `correctPinVerifiesWrongPinFails` ✔ |
| 4 | TestBank probes while locked | All 4 probes BLOCKED; dashboard `BLOCKED_ALL` | – | NOT RUN | `NetworkTest.lockUnlockRelockCycle`, `vpnRoutesIpv4AndIpv6AndDns` ✔ |
| 5 | Wi-Fi only, then Mobile only (set rule Block Wi-Fi only, then Mobile only) | Blocked only on the chosen transport | – | NOT RUN | `vpnPerTransportAndFailClosed`, `wifiAndMobileStatesIndependent` ✔ |
| 6 | Chrome/YouTube while TestBank locked | Work normally | – | NOT RUN | VPN contains only locked apps; `vpnNeverEstablishedWithEmptyAppList` ✔ |
| 7 | Correct PIN | TestBank opens; probes OK; `TEMPORARILY_ALLOWED` | – | NOT RUN | `SessionCoordinator.grant` → VPN re-plan |
| 8 | Wait for session expiry / screen off | Probes BLOCKED again; audit SESSION_ENDED | – | NOT RUN | `SessionTest.*` ✔ |
| 9 | Hiding | DO: icon disappears while locked. Unmanaged: dashboard shows *Manual Setup Required* | – | NOT RUN | `ManagedDeviceController`; `compatibilityMatrixIsHonest` ✔ |
| 10 | Scan `https://bankvault-phishing-test.example/` | *Confirmed malicious* | – | NOT RUN | `threatIntelHitsAreConfirmedIncludingSubdomains` ✔ (seed contains this domain) |
| 11 | Share `http://bkash.com.account-verify.xyz/login`, `https://bkаsh.com` | *Suspicious* with explanation | – | NOT RUN | `lookalikesAreSuspicious` ✔ |
| 12 | Revoke Usage access; start another VPN app | Alert + *Degraded*; audit PERMISSION_CHANGED / NETWORK_PROTECTION_FAILURE | – | NOT RUN | `TamperMonitor`, `VpnService.onRevoke`; `backendFailuresAreReportedHonestly` ✔ |
| 13 | Reboot; then Recovery → Release everything | After boot TestBank blocked again; release restores access | – | NOT RUN | `BootReceiver`; `screenOffEmergencyRebootEndSessions` ✔ |
| 14 | Inspect DB + logs after tests 3–8 | No PIN/OTP/URL query in DB or export | – | NOT RUN | `auditRedactsCredentialsAndOtps`, `sanitizedUrlDropsQueryAndFragment` ✔ |
| 15 | Open Compatibility matrix on unmanaged, unrooted phone | Suspend/Hide = *Requires Device Owner*, Force-stop prevention = *Unsupported* | – | NOT RUN | `compatibilityMatrixIsHonest` ✔ |

### Network test matrix (spec §5F) – procedure
Run TestBank probes for each case and record results. Root mode: additionally `adb shell su -c 'iptables -S bankvault_out; ip6tables -S bankvault_out'`.

| Case | How |
|---|---|
| Locked + Wi-Fi / + Mobile / + both | Toggle radios, run probes |
| Authenticated / session expired | Unlock, probe; wait, probe |
| Background traffic | TestBank → "Start background pinger", leave app, watch logcat |
| Reboot | `adb reboot`, probe before and after opening BANKVAULT |
| Network switching | Start pinger, toggle Wi-Fi off/on repeatedly |
| IPv4 / IPv6 / DNS | Separate probe lines |
| Firewall interruption | Start another VPN app (VPN mode) or `iptables -D OUTPUT -j bankvault_out` (root) → dashboard must leave *Blocked* within 60 s |

## How to reproduce the unit tests
`./gradlew :core:test` (standard JUnit 4). In this sandbox they were compiled with the Kotlin 2.0.21 compiler bundled in Gradle and
executed by a small JUnit-compatible runner because Maven Central was unreachable.
