# BANKVAULT

Banking-app protection for Android 14–16 (Realme UI / ColorOS focus): a separate PIN/biometric lock, per-app network isolation for
locked banking apps, phishing/QR/link scanning, tamper monitoring, emergency lock and safe recovery.

**Honesty rule:** a protection is shown as *Protected/Blocked/Hidden* (green) only after it has been applied **and read back**.
Anything Android does not allow a normal app to do is shown as *Manual Setup Required*, *Requires Device Owner*, *Requires Root*,
*Verification Unavailable* or *Unsupported* – never simulated. BANKVAULT never claims 100 % protection.

## What actually stops a locked banking app

| Your phone | Can the locked app run? | Can it reach its servers? |
|---|---|---|
| Normal phone | Yes, but BANKVAULT's lock screen covers it (best effort) | **No** – local blackhole VPN (while running; enable Always-on VPN) |
| Rooted | Yes, lock screen covers it | **No** – iptables + ip6tables UID rules (survive BANKVAULT being killed) |
| Device Owner provisioned | **No** – package suspended & hidden | No – VPN or root as above |
| Phone's own *Network access* switch only | Yes | Probably not – but BANKVAULT cannot verify it |

## Status of this delivery

* `:core` – all platform-free security logic. **43/43 unit tests executed and passing** ([output](docs/test-results/core-unit-tests.txt)).
* `:app` – complete Android source (Compose UI, Room, Keystore, BiometricPrompt, UsageStats monitor, VpnService, root firewall,
  DevicePolicyManager, Quick Settings tile, widget, WorkManager). **Builds on GitHub Actions**: every push produces
  `bankvault-debug-apk` and `testbank-debug-apk` under *Actions → Build APK → latest run → Artifacts*.
* `:testbank` – dummy bank app for the acceptance tests.
* On-device acceptance tests: **not run yet** – procedures in [TEST_REPORT](docs/TEST_REPORT.md).

## Documentation
* [Feasibility matrix](docs/FEASIBILITY.md) – what is possible on which device, and why
* [Architecture](docs/ARCHITECTURE.md) – modules, flows, DB schema
* [Install & build](docs/INSTALL.md) · [Permissions](docs/PERMISSIONS.md)
* [Network security](docs/NETWORK_SECURITY.md) · [Cyber threat protection](docs/CYBER_THREAT_PROTECTION.md)
* [Device Owner setup](docs/DEVICE_OWNER_SETUP.md) · [Root setup](docs/ROOT_SETUP.md)
* [Recovery](docs/RECOVERY.md) · [Test report](docs/TEST_REPORT.md)

## Known limitations
* Without Device Owner, launch interception is best-effort (UsageStats polling): the app may be visible for a moment, and
  nothing intercepts launches if BANKVAULT is force-stopped. Network isolation is the real boundary.
* Only one VPN can run on Android; another VPN app disables BANKVAULT's network isolation (detected and alerted).
* Realme/ColorOS *Network access* and *Hide apps* have no public API – guided manual setup only, unverifiable.
* Root rules are re-applied at BOOT_COMPLETED; there is a short window early in boot.
* Wi-Fi-only / Mobile-only rules in VPN mode have a brief transition window during a network switch (default rule blocks both).
* Device-wide malicious-domain blocking relies on Android Private DNS with a filtering provider; the link scanner itself only warns.
* Not an antivirus; does not inspect encrypted traffic; collects no credentials, OTPs or banking screens.
* Library versions in `gradle/libs.versions.toml` were chosen offline; Android Studio may suggest updates.
