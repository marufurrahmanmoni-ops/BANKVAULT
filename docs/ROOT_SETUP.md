# Root setup (Mode C) – optional

For phones you own that are **already** rooted with an authorised root manager (e.g. Magisk). BANKVAULT never roots a device,
never exploits anything, and never runs destructive commands.

1. Open BANKVAULT → More → Compatibility → "Check root access". Approve the root manager prompt.
2. More → Network isolation method → Root firewall. BANKVAULT:
   * saves `iptables-save` / `ip6tables-save` backups to its private storage,
   * creates chain `bankvault_out` with UID rules for locked apps (IPv4 and IPv6),
   * verifies by reading the live rules back.
3. Verify manually (optional): `adb shell su -c 'iptables -S bankvault_out; ip6tables -S bankvault_out'`.

Rollback: More → Recovery → Release everything, or switch method to Off. Manual emergency rollback:
```
su -c 'for t in iptables ip6tables; do while $t -D OUTPUT -j bankvault_out 2>/dev/null; do :; done; $t -F bankvault_out; $t -X bankvault_out; done'
```
Rules do not survive a reboot on their own; BANKVAULT re-applies them at boot (short unprotected window during early boot).
Note that rooting itself weakens Android's security model and many banking apps refuse to run on rooted phones.
