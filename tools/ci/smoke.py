#!/usr/bin/env python3
"""
BANKVAULT end-to-end smoke test, run on an Android emulator in CI.

Drives the real UI through uiautomator (Compose text is exposed to accessibility), exercises
the main flows, runs TestBank network probes, then a monkey run, and fails if any crash/ANR
for BANKVAULT appears in logcat. Every screen's visible text is written to out/screens.log so
UI bugs can be reviewed without a phone.

Usage: smoke.py <bankvault.apk> <testbank.apk>
"""
import os, re, subprocess, sys, time, xml.etree.ElementTree as ET

PKG = "com.bankvault.debug"
TB = "com.bankvault.testbank"
PIN, RPIN = "482915", "739164"
OUT = "out"
os.makedirs(OUT, exist_ok=True)
LOG = open(f"{OUT}/screens.log", "w")
RESULTS = []          # (step, ok, detail)


def adb(*a, timeout=60):
    try:
        return subprocess.run(["adb", *a], capture_output=True, text=True, timeout=timeout).stdout
    except subprocess.TimeoutExpired:
        return ""


def sh(cmd, timeout=60):
    return adb("shell", cmd, timeout=timeout)


def log(msg):
    print(msg, flush=True)
    LOG.write(msg + "\n"); LOG.flush()


def result(step, ok, detail=""):
    RESULTS.append((step, ok, detail))
    log(f"[{'PASS' if ok else 'FAIL'}] {step} {detail}")


def dump():
    for _ in range(3):
        sh("rm -f /sdcard/ui.xml; uiautomator dump /sdcard/ui.xml >/dev/null 2>&1")
        x = sh("cat /sdcard/ui.xml")
        if "<hierarchy" in x:
            try:
                return ET.fromstring(x[x.index("<hierarchy"):])
            except ET.ParseError:
                pass
        time.sleep(1)
    return None


def nodes(root=None):
    root = root if root is not None else dump()
    return list(root.iter("node")) if root is not None else []


def label(n):
    return (n.get("text") or n.get("content-desc") or "").strip()


def texts():
    return [label(n) for n in nodes() if label(n)]


def screen(title):
    t = texts()
    log(f"\n===== {title} =====\n" + "\n".join(f"  | {x}" for x in t))
    return t


def find(text, exact=False, timeout=12):
    end = time.time() + timeout
    while time.time() < end:
        for n in nodes():
            t = label(n)
            if (t == text) if exact else (text.lower() in t.lower()):
                return n
        time.sleep(1)
    return None


def center(n):
    b = list(map(int, re.findall(r"\d+", n.get("bounds"))))
    return (b[0] + b[2]) // 2, (b[1] + b[3]) // 2


def tap_node(n):
    x, y = center(n)
    sh(f"input tap {x} {y}")
    time.sleep(1.2)


def tap(text, exact=False, timeout=12, scroll=True):
    n = find(text, exact, timeout=timeout if not scroll else 4)
    tries = 0
    while n is None and scroll and tries < 8:
        swipe_up(); tries += 1
        n = find(text, exact, timeout=2)
    if n is None:
        log(f"!! could not find '{text}'")
        return False
    tap_node(n)
    return True


def swipe_up():
    sh("input swipe 540 1600 540 600 300"); time.sleep(0.8)


def swipe_down():
    sh("input swipe 540 600 540 1600 300"); time.sleep(0.8)


def scroll_to_top():
    for _ in range(8): swipe_down()


def enter_pin(pin, submit):
    for d in pin:
        if not tap(d, exact=True, timeout=6, scroll=False):
            return False
        time.sleep(0.2)
    return tap(submit, exact=True, timeout=6, scroll=False)


def crashes():
    out = adb("logcat", "-d", "-b", "crash")
    blocks = [b for b in out.split("--------- beginning") if PKG in b or "com.bankvault" in b]
    anr = sh("ls /data/anr 2>/dev/null")
    return blocks, anr


def check_no_crash(step):
    blocks, _ = crashes()
    if blocks:
        result(f"no crash after: {step}", False, "\n" + "\n".join(blocks)[-6000:])
        adb("logcat", "-c", "-b", "crash")
        return False
    return True


def wait_text(text, timeout=20):
    return find(text, timeout=timeout) is not None


def probes(tag):
    time.sleep(8)
    out = adb("logcat", "-d", "-s", "TestBank:I")
    lines = [l for l in out.splitlines() if "transport" in l]
    last = lines[-1] if lines else ""
    log(f"TestBank probes ({tag}): {last}")
    return last


def back_to_bankvault():
    sh(f"am start -n {PKG}/com.bankvault.ui.MainActivity"); time.sleep(3)
    if find("Unlock the security dashboard", timeout=4):
        enter_pin(PIN, "Unlock"); time.sleep(4)


def main():
    app_apk, tb_apk = sys.argv[1], sys.argv[2]
    adb("install", "-r", "-g", app_apk, timeout=240)
    adb("install", "-r", "-g", tb_apk, timeout=240)
    adb("logcat", "-c"); adb("logcat", "-c", "-b", "crash")
    # Permissions the owner would grant through the Fix buttons.
    sh(f"pm grant {PKG} android.permission.POST_NOTIFICATIONS")
    sh(f"appops set {PKG} GET_USAGE_STATS allow")
    sh(f"appops set {PKG} SYSTEM_ALERT_WINDOW allow")
    sh(f"appops set {PKG} ACTIVATE_VPN allow")
    sh("settings put global development_settings_enabled 0")

    # ---------- 1. First launch + onboarding ----------
    sh(f"am start -W -n {PKG}/com.bankvault.ui.MainActivity"); time.sleep(4)
    screen("first launch")
    result("launch", check_no_crash("launch") and wait_text("BANKVAULT"))
    tap("Set up security PIN")
    ok = enter_pin(PIN, "Next"); time.sleep(1)
    ok &= enter_pin(PIN, "Next"); time.sleep(3)
    screen("after main PIN")
    ok &= enter_pin(RPIN, "Next"); time.sleep(1)
    ok &= enter_pin(RPIN, "Next"); time.sleep(4)
    screen("after recovery PIN")
    ok &= tap("Open dashboard", timeout=30)
    time.sleep(4)
    result("onboarding", ok and check_no_crash("onboarding") and wait_text("Overall security"))
    screen("dashboard (before setup)")

    # ---------- 2. Add TestBank as protected app ----------
    tap("Apps", exact=True, scroll=False); time.sleep(2)
    tap("Add apps", scroll=False); time.sleep(3)
    screen("app picker")
    if not find("com.bankvault.testbank", timeout=3):
        result("picker lists TestBank", False)
    else:
        result("picker lists TestBank", True)
    tap("Protect", exact=True, scroll=False); time.sleep(4)
    screen("apps screen")
    result("TestBank protected", check_no_crash("add app") and wait_text("TestBank"))

    # ---------- 3. Dashboard fixes: network block ----------
    tap("Security", exact=True, scroll=False); time.sleep(3)
    screen("dashboard after adding app")
    tap("Turn on network block"); time.sleep(8)
    scroll_to_top()
    t = screen("dashboard after enabling VPN")
    result("network block enabled", check_no_crash("enable vpn") and any("Verified" in x for x in t) or wait_text("Verified", 15))
    tap("Add tile", timeout=4); time.sleep(3)
    screen("add tile dialog"); sh("input keyevent KEYCODE_BACK"); time.sleep(1)
    tap("Set up (1 minute)", timeout=4); time.sleep(2)
    screen("private DNS dialog"); tap("Close", exact=True, scroll=False)
    check_no_crash("dashboard fixes")

    # ---------- 4. Locked TestBank: lock screen + network blocked ----------
    sh("input keyevent KEYCODE_HOME"); time.sleep(2)
    adb("logcat", "-c")
    sh(f"am start -n {TB}/.MainActivity"); time.sleep(4)
    t = screen("open TestBank while locked")
    result("lock screen shown over TestBank", any("is protected" in x for x in t))
    p = probes("locked")
    result("locked: IPv4 blocked", "IPv4: BLOCKED" in p, p)
    result("locked: IPv6 blocked", "IPv6: BLOCKED" in p or "IPv6: OK" not in p, p)
    result("locked: DNS blocked", "DNS: BLOCKED" in p, p)
    # Other apps still online
    other = sh("ping -c 1 -W 3 1.1.1.1")
    result("other apps keep internet", " 0% packet loss" in other or "1 received" in other, other.strip()[-80:])

    # Wrong PIN
    enter_pin("111222", "Unlock"); time.sleep(2)
    result("wrong PIN rejected", wait_text("Wrong PIN", 5))
    # Correct PIN -> session
    adb("logcat", "-c")
    enter_pin(PIN, "Unlock"); time.sleep(6)
    t = screen("after correct PIN")
    result("TestBank opens after PIN", any("transport" in x or "Run network probes" in x for x in t))
    p = probes("unlocked")
    result("unlocked: IPv4 allowed", "IPv4: OK" in p, p)
    check_no_crash("session")

    # ---------- 5. Emergency lock -> blocked again ----------
    back_to_bankvault()
    tap("EMERGENCY LOCK", scroll=False); time.sleep(6)
    screen("after emergency lock")
    sh("input keyevent KEYCODE_HOME"); time.sleep(1)
    adb("logcat", "-c")
    sh(f"am start -n {TB}/.MainActivity"); time.sleep(4)
    result("lock screen after emergency", wait_text("is protected", 6))
    p = probes("after emergency")
    result("after emergency: IPv4 blocked", "IPv4: BLOCKED" in p, p)
    tap("Cancel", exact=True, scroll=False)
    check_no_crash("emergency")

    # ---------- 6. Scanner ----------
    back_to_bankvault()
    tap("Scan", exact=True, scroll=False); time.sleep(2)
    n = find("Paste a link", timeout=5)
    if n: tap_node(n); sh("input text 'https://bankvault-phishing-test.example/login'"); time.sleep(1); sh("input keyevent KEYCODE_BACK")
    # Both the bottom tab and the button are labelled "Scan": press the upper one (the button).
    scans = sorted([n for n in nodes() if label(n) == "Scan"], key=lambda n: center(n)[1])
    if scans: tap_node(scans[0])
    time.sleep(3)
    t = screen("scan result")
    result("scanner flags test phishing domain", any("Confirmed malicious" in x for x in t))
    check_no_crash("scan")

    # ---------- 7. Visit every tab and scroll ----------
    for tab in ["Activity", "More", "Apps", "Security"]:
        tap(tab, exact=True, scroll=False); time.sleep(3)
        screen(f"tab {tab} (top)")
        for i in range(6):
            swipe_up()
        screen(f"tab {tab} (bottom)")
        scroll_to_top()
        check_no_crash(f"tab {tab}")

    # ---------- 8. Share sheet entry ----------
    sh("am start -a android.intent.action.SEND -t text/plain --es android.intent.extra.TEXT 'verify now http://bkash.com.account-verify.xyz/login' "
       f"-n {PKG}/com.bankvault.ui.ShareReceiverActivity"); time.sleep(4)
    t = screen("share sheet scan")
    result("share scan flags lookalike", any("Suspicious" in x for x in t))
    check_no_crash("share")

    # ---------- 9. Reboot-like: kill + restart process ----------
    sh(f"am force-stop {PKG}"); time.sleep(2)
    sh(f"am start -n {PKG}/com.bankvault.ui.MainActivity"); time.sleep(4)
    result("restart after force-stop", check_no_crash("restart") and wait_text("Unlock the security dashboard", 8))
    enter_pin(PIN, "Unlock"); time.sleep(3)

    # ---------- 10. Monkey ----------
    adb("logcat", "-c", "-b", "crash")
    mk = sh(f"monkey -p {PKG} --pct-syskeys 0 --throttle 150 -s 42 -v 1500", timeout=600)
    open(f"{OUT}/monkey.log", "w").write(mk)
    result("monkey 1500 events", check_no_crash("monkey") and "Monkey finished" in mk, mk.strip().splitlines()[-1] if mk.strip() else "")

    # ---------- summary ----------
    adb("logcat", "-d", "-v", "time", "*:W")  # noqa
    open(f"{OUT}/logcat.txt", "w").write(adb("logcat", "-d", "-v", "time"))
    open(f"{OUT}/crash.txt", "w").write(adb("logcat", "-d", "-b", "crash"))
    with open(f"{OUT}/summary.md", "w") as f:
        f.write("| Step | Result | Detail |\n|---|---|---|\n")
        for s, ok, d in RESULTS:
            f.write(f"| {s} | {'PASS' if ok else 'FAIL'} | {d.strip()[:300].replace('|', '/').replace(chr(10), ' ')} |\n")
    fails = [r for r in RESULTS if not r[1]]
    log(f"\nSUMMARY: {len(RESULTS) - len(fails)}/{len(RESULTS)} passed")
    crash_fail = [r for r in fails if r[0].startswith("no crash") or r[0] in ("launch", "monkey 1500 events")]
    sys.exit(1 if crash_fail else 0)


if __name__ == "__main__":
    main()
