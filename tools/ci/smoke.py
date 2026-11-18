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


def tap(text, exact=False, timeout=12, scroll=True, max_swipes=8):
    n = find(text, exact, timeout=timeout if not scroll else 4)
    tries = 0
    while n is None and scroll and tries < max_swipes:
        swipe_up(); tries += 1
        n = find(text, exact, timeout=2)
    if n is None:
        log(f"!! could not find '{text}'")
        return False
    tap_node(n)
    return True


SIZE = None


def size():
    global SIZE
    if SIZE is None:
        m = re.findall(r"(\d+)x(\d+)", sh("wm size"))
        SIZE = tuple(map(int, m[-1])) if m else (1080, 2400)
    return SIZE


def swipe_up():
    w, h = size(); sh(f"input swipe {w//2} {int(h*0.75)} {w//2} {int(h*0.30)} 300"); time.sleep(0.8)


def swipe_down():
    w, h = size(); sh(f"input swipe {w//2} {int(h*0.30)} {w//2} {int(h*0.75)} 300"); time.sleep(0.8)


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
        txt = "\n".join(blocks)
        # Keep the head of each trace (exception + app frames), drop framework noise.
        keep = [l for l in txt.splitlines() if ("FATAL" in l or "Process:" in l or "Exception" in l or "Error" in l
                or "Caused by" in l or "com.bankvault" in l)]
        result(f"no crash after: {step}", False, "\n" + "\n".join(keep[:60]))
        adb("logcat", "-c", "-b", "crash")
        return False
    return True


def wait_text(text, timeout=20):
    return find(text, timeout=timeout) is not None


def start_testbank():
    """Fresh TestBank process so its onCreate probes run (and no DNS cache from earlier runs)."""
    sh(f"am force-stop {TB}"); time.sleep(1)
    adb("logcat", "-c")
    sh(f"am start -n {TB}/.MainActivity")


def probes(tag):
    last = ""
    for _ in range(90):           # blackholed DNS can take >30 s to time out on Android 14
        out = adb("logcat", "-d", "-s", "TestBank:I")
        lines = [l for l in out.splitlines() if "transport" in l]
        if lines:
            last = lines[-1]; break
        time.sleep(1)
    log(f"TestBank probes ({tag}): {last}")
    return last


def back_to_bankvault():
    sh(f"am start -n {PKG}/com.bankvault.ui.MainActivity"); time.sleep(3)
    if find("Unlock the security dashboard", timeout=4) is not None:
        enter_pin(PIN, "Unlock"); time.sleep(4)


def toggle_for(text):
    """Tap the switch on the same row as the given text."""
    n = find(text, timeout=6)
    if n is None:
        log(f"!! no row '{text}'"); return False
    _, y = center(n)
    sw = [m for m in nodes() if m.get("checkable") == "true"]
    if not sw:
        log("!! no switches on screen"); return False
    best = min(sw, key=lambda m: abs(center(m)[1] - y))
    tap_node(best); return True


def unlock_bankvault():
    if find("Enter your PIN", timeout=4) is not None:
        enter_pin(PIN, "Unlock"); time.sleep(3)


def main():
    app_apk, tb_apk = sys.argv[1], sys.argv[2]
    adb("install", "-r", app_apk, timeout=240)
    adb("install", "-r", "-g", tb_apk, timeout=240)
    adb("logcat", "-c"); adb("logcat", "-c", "-b", "crash")
    # Special access is granted in Settings by the owner; notifications + VPN go through real dialogs.
    sh(f"appops set {PKG} GET_USAGE_STATS allow")
    sh(f"appops set {PKG} SYSTEM_ALERT_WINDOW allow")

    # 1. First launch: create PIN
    sh(f"am start -W -n {PKG}/com.bankvault.ui.MainActivity"); time.sleep(4)
    screen("first launch")
    ok = enter_pin(PIN, "Next"); time.sleep(1)
    ok &= enter_pin(PIN, "Next"); time.sleep(5)
    t = screen("home")
    result("create PIN", check_no_crash("create PIN") and ok and wait_text("App lock is working", 10))

    # 2. Notifications via the Allow button (the Realme crash)
    tap("Allow", exact=True, scroll=False, timeout=6); time.sleep(3)
    screen("notification dialog")
    tap("Allow", exact=True, scroll=False, timeout=6); time.sleep(3)
    result("notifications Allow button", check_no_crash("allow notifications") and "granted=true" in sh(f"dumpsys package {PKG} | grep POST_NOTIFICATIONS"))

    # 3. Lock TestBank
    n = find("Search", timeout=6)
    if n is not None:
        tap_node(n); time.sleep(1); sh("input text TestBank"); time.sleep(1); sh("input keyevent KEYCODE_BACK"); time.sleep(2)
    screen("search TestBank")
    result("lock TestBank switch", toggle_for("TestBank (BANKVAULT test)") and wait_text("Locked", 6))

    # 4. Network access off (real VPN dialog)
    scroll_to_top()
    toggle_for("Block internet for locked apps"); time.sleep(3)
    screen("vpn dialog")
    tap("OK", exact=True, scroll=False, timeout=8); time.sleep(6)
    t = screen("after network on")
    result("network access off enabled", check_no_crash("vpn") and wait_text("internet blocked for 1", 10))

    # 5. Open TestBank while locked
    sh("input keyevent KEYCODE_HOME"); time.sleep(2)
    start_testbank(); time.sleep(4)
    screen("TestBank while locked")
    result("lock screen over TestBank", wait_text("is locked", 6))
    p = probes("locked")
    result("locked: no internet (IPv4)", "IPv4: BLOCKED" in p, p)
    result("locked: no DNS", "DNS: BLOCKED" in p, p)
    other = sh("echo | toybox nc -w 5 1.1.1.1 443 >/dev/null 2>&1 && echo NET_OK || echo NET_FAIL")
    result("other apps keep internet", "NET_OK" in other, other.strip())
    enter_pin("111222", "Unlock"); time.sleep(2)
    result("wrong PIN rejected", wait_text("Wrong PIN", 5))
    adb("logcat", "-c")
    enter_pin(PIN, "Unlock"); time.sleep(5)
    t = screen("after correct PIN")
    result("TestBank usable after PIN", any("Run network probes" in x for x in t))
    tap("Run network probes", scroll=False)
    p = probes("unlocked")
    result("unlocked: internet back", "IPv4: OK" in p, p)
    check_no_crash("unlock")

    # 6. Leave -> relocks immediately (default)
    sh("input keyevent KEYCODE_HOME"); time.sleep(3)
    start_testbank(); time.sleep(4)
    result("relocks after leaving", wait_text("is locked", 6))
    p = probes("relocked")
    result("relocked: no internet", "IPv4: BLOCKED" in p, p)
    tap("Cancel", exact=True, scroll=False)

    # 7. Open button inside BANKVAULT
    sh(f"am start -n {PKG}/com.bankvault.ui.MainActivity"); time.sleep(3)
    unlock_bankvault()
    n = find("Search", timeout=4)
    if n is not None:
        tap_node(n); time.sleep(1); sh("input text TestBank"); sh("input keyevent KEYCODE_BACK"); time.sleep(2)
    tap("Open", exact=True, timeout=6); time.sleep(3)
    ok = wait_text("is locked", 5)
    enter_pin(PIN, "Unlock"); time.sleep(4)
    result("Open button: PIN then app opens", ok and wait_text("Run network probes", 8))

    # 8. Hide help + settings + About
    sh(f"am start -n {PKG}/com.bankvault.ui.MainActivity"); time.sleep(3)
    unlock_bankvault()
    n = find("Search", timeout=4)
    if n is not None:
        tap_node(n); time.sleep(1); sh("input text TestBank"); sh("input keyevent KEYCODE_BACK"); time.sleep(2)
    tap("Hide", exact=True, timeout=6); time.sleep(2)
    screen("hide help")
    result("Hide shows instructions (no Device Owner)", wait_text("Hide apps", 5))
    tap("Copy command", scroll=False); time.sleep(1)
    result("About shows developer", tap("Md. Marufur Rahman Moni", max_swipes=20))
    screen("bottom")
    check_no_crash("settings")

    # 9. Force-stop + restart
    sh(f"am force-stop {PKG}"); time.sleep(2)
    sh(f"am start -n {PKG}/com.bankvault.ui.MainActivity"); time.sleep(4)
    result("restart after force-stop", check_no_crash("restart") and wait_text("Enter your PIN", 8))
    unlock_bankvault()

    # 10. Monkey
    adb("logcat", "-c", "-b", "crash")
    mk = sh(f"monkey -p {PKG} --pct-syskeys 0 --throttle 150 -s 42 -v 1500", timeout=600)
    open(f"{OUT}/monkey.log", "w").write(mk)
    bad = [l for l in mk.splitlines() if "// CRASH" in l or "NOT RESPONDING" in l or "Monkey aborted" in l]
    inj = re.findall(r"Events injected: (\d+)", mk)
    result("monkey 1500 events", check_no_crash("monkey") and not bad, f"injected={inj[-1] if inj else '?'} {' '.join(bad)[:200]}")

    open(f"{OUT}/logcat.txt", "w").write(adb("logcat", "-d", "-v", "time"))
    with open(f"{OUT}/summary.md", "w") as f:
        f.write("| Step | Result | Detail |\n|---|---|---|\n")
        for st, ok2, d in RESULTS:
            f.write(f"| {st} | {'PASS' if ok2 else 'FAIL'} | {d.strip()[:300].replace('|', '/')} |\n")
    fails = [r for r in RESULTS if not r[1]]
    log(f"\nSUMMARY: {len(RESULTS) - len(fails)}/{len(RESULTS)} passed")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
