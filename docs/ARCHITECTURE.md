# BANKVAULT – Architecture

## Modules

The specification lists 21 logical modules. They are implemented as **3 Gradle modules** with one package per
logical module, so platform-independent security logic is isolated and testable on a plain JVM.

| Gradle module | Purpose |
|---|---|
| `:core` | Pure Kotlin/JVM. No Android imports. All security decisions live here and are unit-tested. |
| `:app` | Android app: platform adapters, services, Compose UI. |
| `:testbank` | Dummy "bank" used only for acceptance tests (network probes). |

| Logical module (spec §18) | Location |
|---|---|
| app-core | `app/…/AppGraph.kt`, `BankVaultApp.kt` (manual DI) |
| authentication | `core/auth/*` · `app/security/*` · `app/lock/AuthPanel.kt`, `Biometric.kt` |
| banking-protection | `app/apps/InstalledApps.kt`, `app/ui/AppsScreen.kt` |
| application-monitor | `app/monitor/AppMonitorService.kt` |
| network-isolation | `core/network/*` · `app/network/NetworkCoordinator.kt` |
| native-network-integration | `app/network/OemManualBackend.kt` |
| root-firewall | `core/root/IptablesPlan.kt` · `app/root/*` |
| optional-vpn-firewall | `core/vpn/VpnPlan.kt` · `app/vpn/*` |
| stealth-management | `app/stealth/StealthManager.kt`, `app/managed/*` |
| cyber-threat-intelligence | `core/threat/ThreatDatabase.kt` · `app/threat/*` |
| dns-security | `app/dns/PrivateDnsInspector.kt` |
| phishing-protection / safe-browsing | `core/threat/UrlAnalyzer.kt`, `Homograph.kt`, `UrlNormalizer.kt` · `app/ui/ScanScreen.kt` |
| privacy-protection | Private DNS tracker filtering + domain rules (`domain_rules` table) |
| session-manager | `core/session/SessionManager.kt` · `app/session/SessionCoordinator.kt` |
| anti-tampering | `app/tamper/TamperMonitor.kt` |
| security-monitoring / audit-logging | `core/audit/Audit.kt` · `app/data/AuditLogger.kt` |
| emergency-lock | `core/emergency/EmergencyLock.kt` · `app/emergency/*` |
| recovery-manager | `app/ui/MoreScreen.kt` (RecoverySection), `ForgotPinScreen.kt`, `ManagedDeviceController.relinquish` |
| ui-dashboard | `app/ui/*` |
| device compatibility | `core/compat/Compatibility.kt` · `app/compat/DeviceProfiler.kt` |

## System overview

```mermaid
flowchart LR
  subgraph Phone
    UI[Compose UI\nDashboard / Apps / Scan / Activity / More]
    LOCK[LockActivity\nAuthPanel]
    MON[AppMonitorService\nUsageStats poll + session timer]
    SC[SessionCoordinator]
    NC[NetworkCoordinator]
    subgraph core[":core (pure Kotlin)"]
      SM[SessionManager]
      NIE[NetworkIsolationEngine\n+ NetworkStateResolver]
      AUTH[PinHasher / AttemptLimiter / AuthChallenge]
      UA[UrlAnalyzer + ThreatDatabase]
      EL[EmergencyLock]
    end
    VPN[BankVaultVpnService\nblackhole tun]
    ROOT[RootFirewallBackend\niptables/ip6tables]
    OEM[OemManualBackend]
    DPM[ManagedDeviceController\nsuspend / hide]
    KS[(Android Keystore)]
    DB[(Room DB\nencrypted fields)]
  end
  MON -->|protected app resumed| LOCK
  LOCK --> AUTH
  AUTH --> KS
  LOCK -->|success| SC
  SC --> SM
  SC --> NC --> NIE
  NIE --> VPN & ROOT & OEM
  SC --> DPM
  UI --> UA
  EL --> SM & NIE & DPM
  SC & NC & UA --> DB
```

## Authentication flow

```mermaid
sequenceDiagram
  participant U as User
  participant L as LockActivity
  participant P as PinRepository
  participant K as Keystore
  participant S as SessionCoordinator
  U->>L: opens protected app (detected by monitor)
  L->>P: verify(PIN)
  P->>P: AttemptLimiter.gate()
  P->>K: HMAC pepper(PIN)
  P->>P: Argon2id(peppered, salt) == stored?
  alt policy needs biometric
    L->>K: BiometricPrompt + CryptoObject(bio key)
  end
  L->>S: grant(pkg)
  S->>S: SessionManager.onAuthenticated
  S->>S: unsuspend (DO) + network allow (VPN/root)
  L->>U: launches the banking app
  Note over S: tick every 1 s → expiry / grace / screen-off → Revoke → block + suspend
```

## Network restriction flow

```mermaid
flowchart TD
  A[Protected app list + session state] --> B[NetworkIsolationEngine.requested]
  B --> C{Backend}
  C -->|LOCAL_VPN| D[VpnPlanner.plan → establish tun with allowed apps = locked apps\nroutes 0/0 and ::/0, DNS inside tunnel]
  C -->|ROOT| E[IptablesPlan.applyCommands → own chain only]
  C -->|OEM_MANUAL| F[ManualRequired → open Settings]
  D --> G[verify: running plan contains exactly the expected apps]
  E --> H[verify: parse iptables -S + ip6tables -S + jump present]
  F --> I[cannot verify]
  G & H & I --> J[NetworkStateResolver → BLOCKED_* / TEMPORARILY_ALLOWED / PENDING / INACTIVE / MANUAL / VERIFICATION_UNAVAILABLE]
```

Rule: the state shown is computed from what the backend **read back**, never from what was requested.

## Application hiding flow

* **Device Owner / Profile Owner:** lock → `setPackagesSuspended(true)` + `setApplicationHidden(true)`; session grant → reverse;
  verified with `isPackageSuspended` / `isApplicationHidden`.
* **Unmanaged Realme/ColorOS:** owner uses *Hide apps*; BANKVAULT shows guided steps; status `MANUAL_SETUP_REQUIRED`.
* **BANKVAULT's own icon:** activity-alias disabled; refused unless the Quick Settings tile (recovery path) is added.

## Threat intelligence flow

```mermaid
flowchart LR
  Seed[assets/threatdb/seed.txt\nAPK-signed] --> Repo[ThreatRepository]
  Feed[HTTPS feed + .sig] -->|ThreatFeedWorker 12 h, unmetered| Ver[SignedFeedVerifier\nECDSA P-256, version > current, not expired]
  Ver -->|accepted| Store[filesDir/threatdb/current.*] --> Repo
  Repo --> UA[UrlAnalyzer]
  Share[Share sheet] & QR[QR scanner] & Paste[Paste] --> UA --> Verdict[SAFE / SUSPICIOUS / CONFIRMED_MALICIOUS / UNKNOWN]
```

## Recovery flow

```mermaid
flowchart TD
  A[Forgot BANKVAULT PIN] --> B[Recovery PIN on unlock screen] --> C[Set new PIN]
  D[Need banking app now / BANKVAULT broken] --> E[More → Recovery → recovery PIN → Release everything]
  E --> F[unsuspend + unhide, rollback iptables, stop VPN, show icon]
  G[BANKVAULT unavailable] --> H[Android Settings → Apps → BANKVAULT → Force stop / Uninstall]
  H --> I[VPN gone immediately; root rules gone after reboot or 'Release everything']
  J[Device Owner and app broken] --> K[adb: dpm remove-active-admin (debug builds) or factory reset]
```

## Database schema (Room, version 1)

| Table | Columns | Notes |
|---|---|---|
| `protected_apps` | packageName PK, label, blockWifi, blockMobile, sessionDurationMs, backgroundGraceMs, authPolicy?, hideWhenLocked, addedAt | No secrets |
| `audit_log` | id PK, type, timestamp, packageName?, detailEnc BLOB | detail redacted by `AuditRedactor`, then AES-GCM (Keystore) |
| `scan_history` | id PK, timestamp, sanitizedUrl, verdict, categories | URL without query/fragment only |
| `domain_rules` | domain PK, action (ALLOW/BLOCK), scope (THREAT/PRIVACY), addedAt | Owner's lists |

Secrets (PIN verifiers, attempt counters, settings) are in `SecurePrefs` (AES-GCM, Keystore key). Backups and device
transfer are disabled (`data_extraction_rules.xml`). Migrations must be explicit; destructive fallback is intentionally not
enabled because it would silently unprotect apps.

## Key decisions

* **No AccessibilityService.** It would improve launch interception but conflicts with the privacy requirements and Play policy.
* **No traffic forwarding in the VPN.** A blackhole VPN needs no packet parsing, no server and cannot leak data; the trade-off is
  that it cannot do DNS filtering for other apps at the same time – that is delegated to Private DNS.
* **Monotonic clock for sessions, persisted wall clock + rollback guard for lockouts.**
* **Manual DI (`AppGraph`)** instead of Hilt to keep the build simple; every class receives collaborators via its constructor.
