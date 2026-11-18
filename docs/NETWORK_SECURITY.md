# Network security documentation

## Goal
While a protected app is locked it must not reach external servers over Wi-Fi or Mobile Data; every other app keeps working.

## Methods (choose in More → Network isolation method)

### 1. Local blackhole VPN (recommended without root)
* `VpnService.Builder.addAllowedApplication()` with **only** the locked apps. All other apps (and BANKVAULT) are outside the VPN.
* Routes `0.0.0.0/0` and `::/0`; DNS servers are addresses inside the tunnel → no IPv6 or DNS leak.
* Packets are read from the TUN fd and dropped. Contents are never parsed, stored or forwarded. Only a packet counter exists.
* `setUnderlyingNetworks([])` so blocked apps see "no network" rather than hanging.
* Empty blocked set ⇒ VPN is **stopped**, never established (an empty allow-list would capture every app – unit-tested).
* Re-plan on policy change establishes the new interface **before** closing the old one.
* Unknown/switching network ⇒ every app with any restriction is blocked (fail closed).
* Verification: the running plan's app list must equal the expected set, else the app shows `PROTECTION_PENDING`.
* Limits: only one VPN can be active on Android – starting another VPN app revokes BANKVAULT's (detected via `onRevoke`, alert raised).
  Force-stopping BANKVAULT tears down the VPN; enable **Always-on VPN** for BANKVAULT so Android restarts it. Do **not** enable
  "Block connections without VPN" – that blocks every app.
* Separate Wi-Fi-only / Mobile-only rules work by re-planning on transport change; there is a short window during the switch. Default rule is block both.

### 2. Root firewall (iptables / ip6tables)
* Own chain `bankvault_out`, one jump from `OUTPUT`. Never flushes system chains or changes policies.
* `-m owner --uid-owner <uid> -j REJECT` (all interfaces except `lo`) or interface-specific rules
  (`wlan+` for Wi-Fi; `rmnet+`, `rmnet_data+`, `ccmni+` (MediaTek/Realme), `v4-*` CLAT, … for cellular).
* UIDs < 10000 are refused; no user string reaches the shell.
* `iptables-save`/`ip6tables-save` backup before the first change; on any error the chain is removed (known state).
* Verification parses live `iptables -S` **and** `ip6tables -S` – a missing IPv6 rule is reported as not blocked.
* Rules are re-applied at `BOOT_COMPLETED`. Between kernel boot and that broadcast the app is not blocked.

### 3. Phone's own per-app network access (Realme UI / ColorOS)
* Realme UI 3.0+ / ColorOS 12+: Settings > Mobile network > Data usage > Network access > app > Disable.
* No public API → BANKVAULT cannot set, read, or lift it during a session. Status is `MANUAL_SETUP_REQUIRED`,
  then `VERIFICATION_UNAVAILABLE` after you confirm. Never "Blocked".

### Not used, and why
* `NetworkPolicyManager` / `setUidPolicy`: system-only permission.
* DevicePolicyManager: has no per-app firewall API. (Always-on VPN via DPM is possible but BANKVAULT does not force it.)
* "Background data" toggle: only restricts background use; not a block.

## Network states
`BLOCKED_WIFI`, `BLOCKED_MOBILE_DATA`, `BLOCKED_ALL`, `TEMPORARILY_ALLOWED`, `PROTECTION_PENDING`, `PROTECTION_INACTIVE`,
`MANUAL_SETUP_REQUIRED`, `VERIFICATION_UNAVAILABLE` – computed by `core/network/NetworkStateResolver` from read-back state only.

## Session behaviour
Grant → network allowed (VPN re-plan / iptables chain rebuilt) → session timer (monotonic) →
expiry / screen off / emergency / background longer than grace / reboot → blocked again. A brief switch to SMS for an OTP
within the grace period (default 45 s) keeps the session.
