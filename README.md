# BANKVAULT

Developed by **Md. Marufur Rahman Moni**.

A simple, private app lock for Android (Android 10 – 16, tested on Realme UI flows).

## Features
- **App lock** – choose apps; opening one asks for your own 6–8 digit BANKVAULT PIN (or fingerprint).
  Locks again immediately / after 1 or 5 minutes when you leave the app, and whenever the screen turns off.
- **Network access off** – optional: locked apps get no Wi-Fi or mobile data until unlocked. Uses a local VPN that
  contains only the locked apps; no server, nothing is read or sent, other apps keep working.
- **App hide** – with Device Owner, locked apps disappear from the home screen and are opened from BANKVAULT's
  "Open" button. Without Device Owner (Android does not allow hiding other apps), BANKVAULT shows how to use
  Realme's built-in *Hide apps*.
- No internet permission, no accounts, PIN stored only as a salted hash bound to the phone's secure hardware.
- Wrong-PIN delays (30 s after 3 tries, growing to 1 h), survives reboot.
- Crash reports are shown in the app and can be shared – they contain no PINs or personal data.

## Download
GitHub → **Actions** → **Build APK** → newest green run → **Artifacts** → `bankvault-debug-apk`.

All builds are signed with the same key (`app/debug.keystore`), so new versions install as updates.
**If you installed a version before 2.0.0, uninstall it once first** (it was signed with a different key).

## Permissions
| Permission | Why |
|---|---|
| Usage access | Know when a locked app is opened |
| Display over other apps | Show the lock screen on top of it |
| Notifications (optional) | "App lock is on" notification |
| VPN (only if Network access off is on) | Block locked apps' internet |

## Forgot PIN
Settings › Apps › BANKVAULT › Storage › Clear data. This resets BANKVAULT only; no other app or data is touched.

## Tests
Every push runs `:core` unit tests and an end-to-end test on Android 14 and 15 emulators (`tools/ci/smoke.py`):
create PIN, notification permission, lock TestBank, VPN permission, lock screen, wrong/correct PIN, internet blocked
while locked and restored after unlock, relock after leaving, Open button, Hide help, About, force-stop, 1 500 random taps.

The earlier full version (threat scanner, root firewall, emergency tile, …) is kept on branch `claude/bankvault-full`.
