# Permission setup guide

BANKVAULT asks only for what it uses. Each permission is explained in-app (More → Permissions) before Android shows its own prompt.

| Permission | Type | Why | Without it |
|---|---|---|---|
| `PACKAGE_USAGE_STATS` (Usage access) | Special, user grants in Settings | Know which app is in the foreground to show the BANKVAULT lock screen. Only package names + timestamps are read. | No launch detection. Network block / DO suspension still work. |
| `SYSTEM_ALERT_WINDOW` (Display over other apps) | Special | Android 10+ only lets an app bring an activity to the front from the background with this exemption. BANKVAULT draws no overlays. | Lock screen may not appear. |
| `POST_NOTIFICATIONS` | Runtime | Required ongoing notification for the monitor service; protection alerts. Banking app names are hidden on the lock screen. | No alerts; service still runs. |
| `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_SPECIAL_USE` | Normal | Keeps launch detection and session timers alive. Justification string is in the manifest. | – |
| `RECEIVE_BOOT_COMPLETED` | Normal | Re-apply restrictions after reboot / app update. | Protection resumes only when app is opened. |
| `USE_BIOMETRIC` | Normal | BiometricPrompt. | PIN only. |
| `INTERNET`, `ACCESS_NETWORK_STATE` | Normal | Signed threat-feed download (off by default), short-link expansion on request, transport detection, Private DNS verification. | Offline mode. |
| `BIND_VPN_SERVICE` (VPN consent) | System dialog | Optional Mode D blackhole VPN. Android shows a key icon while active. | Use root or OEM manual mode. |
| Device admin / Device Owner | Provisioning | Optional Mode B: suspend/hide apps, block BANKVAULT uninstall. | Mode A behaviour. |
| Root (`su`) | Root manager prompt | Optional Mode C iptables firewall. Probed only when you press "Check root access" or pick Root mode. | Use VPN mode. |

**Not requested:** `QUERY_ALL_PACKAGES` (launcher `<queries>` is enough), `BIND_ACCESSIBILITY_SERVICE`, `REQUEST_INSTALL_PACKAGES`,
SMS, contacts, location, storage, camera (QR scanning uses Google Play services' code scanner UI, which needs no camera permission in our app).

## Google Play notes
* `PACKAGE_USAGE_STATS` and `FOREGROUND_SERVICE_SPECIAL_USE` require a policy declaration in Play Console describing the app-lock use.
* `VpnService` apps must declare VPN use; BANKVAULT's VPN does not route traffic to a server and collects nothing – state this in the declaration.
* `SYSTEM_ALERT_WINDOW` is acceptable for app-lock use but expect review.
