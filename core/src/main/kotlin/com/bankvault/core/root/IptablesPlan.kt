package com.bankvault.core.root

import com.bankvault.core.network.AppRef
import com.bankvault.core.network.DesiredAccess

/**
 * Generates iptables/ip6tables commands for the rooted firewall (Mode C).
 *
 * Safety properties (all unit-tested):
 *  - Only touches BANKVAULT's own chain `bankvault_out` and one jump rule in OUTPUT.
 *    It never flushes OUTPUT or any system chain, never changes default policies.
 *  - Only numeric app UIDs (>= 10000) are accepted, so system UIDs cannot be blocked and no
 *    user-controlled string ever reaches the shell.
 *  - Rules are applied the same way for IPv4 and IPv6 (incl. DNS, which is just UDP/TCP 53 from
 *    the same UID and therefore covered by the UID match).
 *  - The script is idempotent: re-applying produces the same state.
 *  - A backup (`iptables-save`) is taken before the first change; rollback removes only our chain.
 */
object IptablesPlan {
    const val CHAIN = "bankvault_out"
    const val FIRST_APP_UID = 10_000

    /** Interface patterns. MediaTek devices (many Realme models) use ccmni*, Qualcomm rmnet*. */
    val WIFI_IFACES = listOf("wlan+")
    val CELL_IFACES = listOf("rmnet+", "rmnet_data+", "ccmni+", "v4-rmnet+", "v4-ccmni+", "v4-rmnet_data+", "seth_lte+", "pdp+", "r_rmnet+", "clat4+")

    private val BINARIES = listOf("iptables", "ip6tables")

    fun backupCommands(dir: String): List<String> {
        require(dir.matches(Regex("^/[A-Za-z0-9_./-]+$"))) { "Unsafe backup path" }
        return listOf("iptables-save > $dir/iptables.v4.bak", "ip6tables-save > $dir/iptables.v6.bak")
    }

    fun applyCommands(policies: Map<AppRef, DesiredAccess>): List<String> {
        val cmds = mutableListOf<String>()
        for (bin in BINARIES) {
            cmds += "$bin -w -N $CHAIN 2>/dev/null || true"
            cmds += "$bin -w -F $CHAIN"
            // Insert the jump exactly once.
            cmds += "$bin -w -C OUTPUT -j $CHAIN 2>/dev/null || $bin -w -I OUTPUT 1 -j $CHAIN"
            for ((app, access) in policies.toSortedMap(compareBy { it.uid })) {
                val uid = checkUid(app.uid)
                when {
                    !access.allowWifi && !access.allowMobile ->
                        // Block everything except loopback for this UID.
                        cmds += listOf(
                            "$bin -w -A $CHAIN -o lo -m owner --uid-owner $uid -j RETURN",
                            "$bin -w -A $CHAIN -m owner --uid-owner $uid -j REJECT",
                        )
                    !access.allowWifi -> WIFI_IFACES.forEach { cmds += "$bin -w -A $CHAIN -o $it -m owner --uid-owner $uid -j REJECT" }
                    !access.allowMobile -> CELL_IFACES.forEach { cmds += "$bin -w -A $CHAIN -o $it -m owner --uid-owner $uid -j REJECT" }
                    else -> Unit
                }
            }
            cmds += "$bin -w -A $CHAIN -j RETURN"
        }
        return cmds
    }

    fun rollbackCommands(): List<String> = BINARIES.flatMap { bin ->
        listOf(
            "while $bin -w -D OUTPUT -j $CHAIN 2>/dev/null; do :; done",
            "$bin -w -F $CHAIN 2>/dev/null || true",
            "$bin -w -X $CHAIN 2>/dev/null || true",
        )
    }

    /** Read-back used by verification. */
    fun verifyCommands(): List<String> = BINARIES.map { "$it -w -S $CHAIN" }

    /**
     * Parse `iptables -S bankvault_out` output and compute what is actually enforced for [uid].
     * Verification is based on live kernel state, not on what we intended.
     */
    fun parseEnforced(v4: String, v6: String, uid: Int, jumpPresent: Boolean): DesiredAccess {
        if (!jumpPresent) return DesiredAccess.ALLOW_ALL
        fun blocked(dump: String, ifaces: List<String>?): Boolean {
            val lines = dump.lines().filter { it.contains("--uid-owner $uid ") && it.contains(" -j REJECT") } // -S may append "--reject-with ..."
            return if (ifaces == null) lines.any { !it.contains(" -o ") }
            else lines.any { !it.contains(" -o ") } || ifaces.all { i -> lines.any { it.contains("-o $i ") } }
        }
        val wifiBlocked = blocked(v4, WIFI_IFACES) && blocked(v6, WIFI_IFACES)
        val cellBlocked = blocked(v4, CELL_IFACES) && blocked(v6, CELL_IFACES)
        return DesiredAccess(allowWifi = !wifiBlocked, allowMobile = !cellBlocked)
    }

    private fun checkUid(uid: Int): Int {
        require(uid >= FIRST_APP_UID) { "Refusing to firewall non-app UID $uid" }
        return uid
    }
}
