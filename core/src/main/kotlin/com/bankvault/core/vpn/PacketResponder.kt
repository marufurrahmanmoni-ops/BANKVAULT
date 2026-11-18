package com.bankvault.core.vpn

/**
 * Makes blocked apps fail FAST instead of hanging on timeouts.
 *
 * The blackhole VPN only needs to drop packets, but silent drops make DNS lookups and TCP
 * connects of the locked app wait for long timeouts (tens of seconds on Android 14), and those
 * stalled lookups can linger after the owner unlocks the app. For two packet types we write an
 * immediate refusal back into the tunnel:
 *   - TCP SYN  -> TCP RST/ACK  ("connection refused")
 *   - UDP :53  -> DNS REFUSED   (same query id and question, no answers)
 * Only IP/TCP/UDP headers and the DNS question are read; payloads are never inspected, stored
 * or forwarded. Everything else is dropped. Supports IPv4 and IPv6 (without extension headers).
 */
object PacketResponder {
    private const val TCP = 6
    private const val UDP = 17

    fun respond(p: ByteArray, len: Int = p.size): ByteArray? = try {
        when ((p[0].toInt() ushr 4) and 0xF) {
            4 -> v4(p, len)
            6 -> v6(p, len)
            else -> null
        }
    } catch (_: IndexOutOfBoundsException) { null }

    // ---------------- IPv4 ----------------
    private fun v4(p: ByteArray, len: Int): ByteArray? {
        val ihl = (p[0].toInt() and 0xF) * 4
        if (ihl < 20 || len < ihl) return null
        val total = u16(p, 2).coerceAtMost(len)
        if ((u16(p, 6) and 0x1FFF) != 0 || (u16(p, 6) and 0x2000) != 0) return null // fragments: drop
        val proto = p[9].toInt() and 0xFF
        val src = p.copyOfRange(12, 16); val dst = p.copyOfRange(16, 20)
        val l4 = p.copyOfRange(ihl, total)
        val reply = when (proto) {
            TCP -> tcpRst(l4) ?: return null
            UDP -> dnsRefused(l4) ?: return null
            else -> return null
        }
        val out = ByteArray(20 + reply.size)
        out[0] = 0x45; put16(out, 2, out.size); out[8] = 64; out[9] = proto.toByte()
        System.arraycopy(dst, 0, out, 12, 4); System.arraycopy(src, 0, out, 16, 4)
        put16(out, 10, checksum(out, 0, 20, 0))
        System.arraycopy(reply, 0, out, 20, reply.size)
        fillL4Checksum(out, 20, proto, pseudo4(dst, src, proto, reply.size))
        return out
    }

    // ---------------- IPv6 ----------------
    private fun v6(p: ByteArray, len: Int): ByteArray? {
        if (len < 40) return null
        val payloadLen = u16(p, 4); val next = p[6].toInt() and 0xFF
        val src = p.copyOfRange(8, 24); val dst = p.copyOfRange(24, 40)
        val l4 = p.copyOfRange(40, minOf(len, 40 + payloadLen))
        val reply = when (next) {
            TCP -> tcpRst(l4) ?: return null
            UDP -> dnsRefused(l4) ?: return null
            else -> return null // extension headers / ICMPv6: drop
        }
        val out = ByteArray(40 + reply.size)
        out[0] = 0x60; put16(out, 4, reply.size); out[6] = next.toByte(); out[7] = 64
        System.arraycopy(dst, 0, out, 8, 16); System.arraycopy(src, 0, out, 24, 16)
        System.arraycopy(reply, 0, out, 40, reply.size)
        fillL4Checksum(out, 40, next, pseudo6(dst, src, next, reply.size))
        return out
    }

    /** RST for an initial SYN only; never answer RSTs (avoids loops) or established traffic. */
    private fun tcpRst(t: ByteArray): ByteArray? {
        if (t.size < 20) return null
        val flags = t[13].toInt() and 0xFF
        val syn = flags and 0x02 != 0; val ack = flags and 0x10 != 0; val rst = flags and 0x04 != 0
        if (!syn || ack || rst) return null
        val seq = u32(t, 4)
        val r = ByteArray(20)
        r[0] = t[2]; r[1] = t[3]; r[2] = t[0]; r[3] = t[1]            // swap ports
        put32(r, 8, (seq + 1) and 0xFFFFFFFFL)                         // ack = their seq + 1
        r[12] = 0x50                                                   // data offset 5
        r[13] = 0x14                                                   // RST|ACK
        return r
    }

    /** DNS REFUSED for a standard query to port 53. */
    private fun dnsRefused(u: ByteArray): ByteArray? {
        if (u.size < 8 + 12) return null
        if (u16(u, 2) != 53) return null
        val dns = u.copyOfRange(8, minOf(u.size, u16(u, 4)).coerceAtLeast(8 + 12))
        if (dns[2].toInt() and 0x80 != 0) return null                 // already a response
        if (u16(dns, 4) != 1) return null                              // exactly one question
        var i = 12
        while (i < dns.size && dns[i].toInt() != 0) {
            val l = dns[i].toInt() and 0xFF
            if (l and 0xC0 != 0) return null
            i += l + 1
        }
        val qEnd = i + 1 + 4
        if (qEnd > dns.size) return null
        val resp = dns.copyOfRange(0, qEnd)
        resp[2] = (0x80 or (dns[2].toInt() and 0x79)).toByte()         // QR=1, keep opcode + RD
        resp[3] = (0x80 or 5).toByte()                                 // RA=1, RCODE=REFUSED
        put16(resp, 6, 0); put16(resp, 8, 0); put16(resp, 10, 0)
        val r = ByteArray(8 + resp.size)
        r[0] = u[2]; r[1] = u[3]; r[2] = u[0]; r[3] = u[1]
        put16(r, 4, r.size)
        System.arraycopy(resp, 0, r, 8, resp.size)
        return r
    }

    // ---------------- checksums ----------------
    private fun pseudo4(src: ByteArray, dst: ByteArray, proto: Int, len: Int) =
        src + dst + byteArrayOf(0, proto.toByte(), (len ushr 8).toByte(), len.toByte())

    private fun pseudo6(src: ByteArray, dst: ByteArray, next: Int, len: Int) =
        src + dst + byteArrayOf((len ushr 24).toByte(), (len ushr 16).toByte(), (len ushr 8).toByte(), len.toByte(), 0, 0, 0, next.toByte())

    private fun fillL4Checksum(pkt: ByteArray, off: Int, proto: Int, pseudo: ByteArray) {
        val pos = off + if (proto == TCP) 16 else 6
        put16(pkt, pos, 0)
        var c = checksum(pkt, off, pkt.size - off, sum(pseudo, 0, pseudo.size))
        if (proto == UDP && c == 0) c = 0xFFFF
        put16(pkt, pos, c)
    }

    private fun sum(b: ByteArray, off: Int, len: Int): Long {
        var s = 0L; var i = off
        while (i + 1 < off + len) { s += ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF); i += 2 }
        if ((len and 1) == 1) s += (b[off + len - 1].toInt() and 0xFF) shl 8
        return s
    }

    fun checksum(b: ByteArray, off: Int, len: Int, initial: Long): Int {
        var s = sum(b, off, len) + initial
        while (s ushr 16 != 0L) s = (s and 0xFFFF) + (s ushr 16)
        return (s.inv() and 0xFFFF).toInt()
    }

    private fun u16(b: ByteArray, o: Int) = ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)
    private fun u32(b: ByteArray, o: Int): Long = (u16(b, o).toLong() shl 16) or u16(b, o + 2).toLong()
    private fun put16(b: ByteArray, o: Int, v: Int) { b[o] = (v ushr 8).toByte(); b[o + 1] = v.toByte() }
    private fun put32(b: ByteArray, o: Int, v: Long) { put16(b, o, (v ushr 16).toInt() and 0xFFFF); put16(b, o + 2, (v and 0xFFFF).toInt()) }
}
