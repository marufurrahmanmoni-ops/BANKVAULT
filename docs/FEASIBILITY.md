# BANKVAULT – Technical Feasibility Matrix

Phase 2 deliverable. Every requested feature is classified **before** implementation. Nothing marked
"No" or "Unsupported" is simulated in the app; the dashboard shows the same classification at runtime
(`core/compat/Compatibility.kt`, More → Compatibility matrix).

Legend: **APK** = possible for a normal Play-installable app · **Perm** = needs a user-granted permission ·
**DO** = needs Device Owner / Profile Owner · **OEM** = needs OEM/system signature · **Root** · **VPN** = needs the optional local VPN ·
**Verify** = can BANKVAULT confirm automatically that it is in effect?

## 1. Authentication

| Feature | APK | Perm | DO | OEM | Root | VPN | Verify | Implementation |
|---|---|---|---|---|---|---|---|---|
| Separate 6–8 digit PIN | Yes | – | – | – | – | – | Yes | Argon2id (BouncyCastle, 64 MiB/3 passes) over a Keystore HMAC pepper; salted; constant-time compare |
| Rate limiting / progressive delay | Yes | – | – | – | – | – | Yes | 3→30 s, 5→1 min, 7→5 min, 10→15 min, 12→1 h; persisted; reboot & clock-rollback safe |
| Strong biometric | Yes | USE_BIOMETRIC | – | – | – | – | Yes | BiometricPrompt `BIOMETRIC_STRONG` + CryptoObject on a Keystore key |
| Biometric re-enrolment detection | Yes | – | – | – | – | – | Yes | `setInvalidatedByBiometricEnrollment(true)` → `KeyPermanentlyInvalidatedException` |
| PIN-only / Bio-only / PIN+Bio, per app, separate settings auth | Yes | – | – | – | – | – | Yes | `AuthRequirements` + `AuthChallenge` (core) |
| No backdoor / universal PIN | Yes | – | – | – | – | – | n/a | None exists. Recovery PIN is owner-set and rate-limited |

## 2. Banking app protection

| Feature | APK | Perm | DO | OEM | Root | VPN | Verify | Notes |
|---|---|---|---|---|---|---|---|---|
| Select installed apps | Yes | – | – | – | – | – | Yes | `<queries>` MAIN/LAUNCHER – **no QUERY_ALL_PACKAGES**; manual package entry |
| Detect launch of protected app | Best-effort | Usage access | – | – | – | – | Partly | `UsageStatsManager` events polled every 350 ms. App may be visible briefly. Not a security boundary |
| Show lock screen over it | Best-effort | Display over other apps | – | – | – | – | No | SAW is still a documented exemption for background activity launches |
| **Prevent the app from running at all** | No | – | **Yes** | – | – | – | Yes | `setPackagesSuspended` – the real boundary; survives BANKVAULT being force-stopped |
| Intercept *every* launch (shortcuts, notifications, deep links) | **No** | – | via suspension | – | – | – | – | Without DO, no third-party app can intercept all launch paths |
| Recent-tasks protection of other apps | No | – | suspension | – | – | – | – | Suspended apps cannot be resumed from Recents |
| Notification access protection | No | – | suspension hides notifications | Realme Hide-apps hides them | – | – | – | |
| Temporary sessions, auto-relock, grace period | Yes | – | – | – | – | – | Yes | `SessionManager` (monotonic clock) |
| Accessibility-based blocking | Rejected | – | – | – | – | – | – | Deliberately not used (Play policy risk, privacy) |

## 3. Network isolation (Section 5)

| Feature | APK | Perm | DO | OEM | Root | VPN | Verify | Notes |
|---|---|---|---|---|---|---|---|---|
| Per-app block Wi-Fi + Mobile, others unaffected | **No** (without VPN/root) | – | **No** | OEM only | Yes | **Yes** | Root: yes · VPN: yes | DO does **not** provide a per-app firewall |
| Realme/ColorOS "Network access" switch | Manual only | – | – | **API: none public** | – | – | **No** | Exists in Settings (see §5A). BANKVAULT opens app info + instructions; state = MANUAL_SETUP_REQUIRED / VERIFICATION_UNAVAILABLE |
| `NetworkPolicyManager` per-UID policy | No | MANAGE_NETWORK_POLICY is signature/privileged | – | Yes | – | – | – | Hidden/system API – not used |
| "Background data" restriction | Owner can set | – | – | – | – | – | No | Not a full block – never presented as one |
| Separate Wi-Fi / Mobile rules | – | – | – | OEM switch | Yes (interface match) | Yes (re-plans on network change) | Yes | VPN has a short transition window – default rule is BLOCKED_ALL |
| IPv4 + IPv6 | – | – | – | – | iptables + ip6tables | routes 0.0.0.0/0 + ::/0 | Yes | Unit-tested: missing IPv6 rule ⇒ not reported as blocked |
| DNS leak prevention | – | – | – | – | UID match covers DNS | DNS servers inside tunnel | Yes | |
| Persist across reboot | – | – | – | – | Re-applied at BOOT_COMPLETED | Always-on VPN (owner enables) | Yes | Short window during boot before BOOT_COMPLETED (root) |
| Rollback | – | – | – | – | Only own chain removed | VPN stopped | Yes | Backup `iptables-save` taken before first change |

### 5A. Realme UI / ColorOS findings (researched November 2026)

* **Per-app network access exists** – Realme UI 3.0+: *Settings > Mobile Network > Data usage > Network access*;
  Realme UI 1.0/2.0: *SIM card & mobile data > Data usage > Network permissions*; ColorOS 12 manual documents the same
  path with options Wi-Fi / mobile data / both / none. Source: realme.com support doc 2083861, ColorOS 12 user manual.
* **No public, authorised API** lets a third-party app read or change it. BANKVAULT therefore does not touch it
  programmatically and never shows it as "Blocked".
* **Hide apps exists** – Realme UI 3.0+: *Settings > Security & privacy (Privacy) > Hide apps*; requires an access code
  dialled on the dial pad; hides icon, notifications and recent tasks. Not supported on Realme UI R/Go/S/T/U editions.
  Source: realme.com support docs 2058698, 2043738.
* **App lock** (OEM) exists but likewise has no third-party API. BANKVAULT is an independent lock, not an integration.

## 4. Stealth & hiding

| Feature | APK | DO | Verify | Notes |
|---|---|---|---|---|
| Hide other apps' launcher icons | **No** | Yes (`setApplicationHidden`) | DO: yes | Unmanaged: guide to Realme/ColorOS Hide apps, shown as MANUAL_SETUP_REQUIRED |
| Hide BANKVAULT's own icon | Yes | – | Yes | Disables `.Launcher` activity-alias; refused until the QS tile (recovery path) is added |
| FLAG_SECURE on BANKVAULT screens | Yes | – | n/a | **Cannot** protect another app's screens |
| Hide BANKVAULT Recents thumbnail | Yes | – | n/a | `setRecentsScreenshotEnabled(false)` |

## 5. Cyber threat protection

| Feature | APK | Perm | VPN | Verify | Notes |
|---|---|---|---|---|---|
| Device-wide malicious/phishing/tracker DNS filtering, VPN-free | Manual | – | – | **Yes** (`LinkProperties.getPrivateDnsServerName`) | Apps cannot set Private DNS (needs WRITE_SECURE_SETTINGS). BANKVAULT guides + verifies |
| DNS-over-TLS | via Private DNS | – | – | Yes | |
| DNS-over-HTTPS | Browser setting only | – | – | No | |
| Link / Share / QR scanner, homograph, typosquat | Yes | – | – | Yes | Fully offline, 4 verdicts, UNKNOWN ≠ SAFE |
| Short-link expansion | Yes | INTERNET | – | – | Contacts only known shorteners (HEAD, no follow); never the destination |
| Signed threat DB updates | Yes | INTERNET | – | Yes | ECDSA P-256, version-monotonic, expiry, re-verified on load |
| Google Safe Browsing / Web Risk | Licensing-dependent | – | – | – | Not bundled: needs an API key, which must not ship in an APK. Use a server-side proxy that publishes a signed feed |
| On-device antivirus scanning of APKs | Not provided | – | – | – | BANKVAULT does **not** claim antivirus protection |
| Tracker blocking per app / HTTPS inspection | Rejected | – | – | – | No TLS interception, no user CA |

## 6. Anti-tampering

| Check | Detect | Prevent (normal app) | Prevent (DO) |
|---|---|---|---|
| Usage access / overlay / notifications revoked | Yes | No | No |
| VPN revoked or replaced | Yes (`onRevoke`, `prepare()`) | No | Always-on VPN can be set by DO (not done automatically) |
| Uninstall | – | No | Yes (`setUninstallBlocked`) |
| Force Stop / Safe Mode | – | **No** | No (but DO suspension and root iptables rules persist; the VPN dies with the process unless Android's Always-on VPN restarts it) |
| Developer options / USB debugging | Yes | No | (user restriction possible, not applied) |
| Root indicators | Heuristic | – | – |
| Bootloader state | **Not reliably detectable** without key attestation + server | – | – |
| App signature | Yes (shown for comparison) | – | – |

## 7. What this means for the acceptance tests

On an ordinary Realme phone **without** Device Owner or root, the strongest legitimate configuration is:
**BANKVAULT PIN + Usage access + Overlay + Local blackhole VPN + Private DNS filtering + Realme Hide apps (manual)**.
In that configuration a locked banking app **cannot reach its servers** while the VPN is up. If someone force-stops BANKVAULT the
VPN is torn down with it; enabling Android's *Always-on VPN* for BANKVAULT makes the system restart it. With root, the iptables
rules stay in the kernel even if BANKVAULT is killed. With Device Owner, the app additionally cannot run at all while locked,
independent of whether BANKVAULT is running.
