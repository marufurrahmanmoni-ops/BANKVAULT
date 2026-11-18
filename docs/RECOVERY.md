# Recovery instructions

BANKVAULT never permanently locks you out of your banking apps and has no hidden master PIN.

| Situation | What to do |
|---|---|
| Forgot BANKVAULT PIN | Unlock screen → "Forgot PIN? Use recovery PIN" → set a new PIN. |
| Need everything back to normal | More → Recovery → recovery PIN → **Release everything** (unsuspends/unhides apps, removes root rules, stops VPN, shows BANKVAULT icon). |
| BANKVAULT icon hidden | Long-press the **Emergency Lock** Quick Settings tile, or share any link to "Scan link with BANKVAULT" → Open BANKVAULT, or Settings > Apps > BANKVAULT. |
| Forgot both PINs (no Device Owner) | Settings > Apps > BANKVAULT > Force stop > Uninstall. The VPN stops immediately; root rules disappear at next reboot. If you used Realme *Hide apps* / *Network access*, undo those in Settings yourself. |
| Forgot both PINs (Device Owner) | Uninstall is blocked by design. A factory reset is the only way out – which is why the recovery PIN is set during onboarding. Keep it written down offline. |
| A banking app has no internet | Check the dashboard: is a session active? If you used the phone's own *Network access* switch, it is **not** lifted by BANKVAULT – re-enable it in Settings. |
| After reboot / app update | Restrictions are re-applied automatically at boot; sessions always end on reboot. |
| VPN replaced by another VPN app | Dashboard shows *Degraded*; reopen BANKVAULT or switch method. |
