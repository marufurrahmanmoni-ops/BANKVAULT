# Device Owner setup (Mode B) – optional

Device Owner lets BANKVAULT **suspend** locked banking apps (they cannot run, show notifications or be opened from Recents)
and **hide** them from the launcher, and blocks BANKVAULT's own uninstall. It does **not** give a per-app network firewall;
keep using VPN or root mode for network isolation.

> ⚠️ Only provision a phone you own. Device Owner can normally only be set on a phone with **no accounts** added
> (usually right after a factory reset). Removing it later requires BANKVAULT's "Remove Device Owner status" or a factory reset.
> Back up your phone first. Some banking apps refuse to run on managed devices – test with the TestBank app first.

## Steps (ADB)
1. Factory reset the phone, or remove every account in Settings > Accounts (Google, Realme/HeyTap, etc.).
2. Enable Developer options > USB debugging. Connect to a computer with Android platform-tools.
3. Install BANKVAULT: `adb install app-release.apk`
4. Provision:
   ```
   adb shell dpm set-device-owner com.bankvault/.managed.BankVaultAdminReceiver
   ```
   (debug build: `com.bankvault.debug/com.bankvault.managed.BankVaultAdminReceiver`)
5. Expected output: `Success: Device owner set to package com.bankvault`.
6. Re-add your accounts, open BANKVAULT. Dashboard → Compatibility should show "Device Owner: true",
   and "Block protected app from running" becomes Active.
7. Turn **USB debugging off** again (the dashboard flags it).

Realme/ColorOS note: some builds show "Not allowed to set the device owner because there are already some accounts on the device"
even after removing visible accounts – a factory reset is then required.

## Removal
* In BANKVAULT: More → Recovery → recovery PIN → Remove Device Owner status. Then uninstall normally.
* If BANKVAULT is broken: factory reset. (`adb shell dpm remove-active-admin` only works for test-only/debuggable builds.)
