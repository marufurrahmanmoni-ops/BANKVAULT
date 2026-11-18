package com.bankvault.core

import com.bankvault.core.vpn.PacketResponder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PacketResponderTest {
    private fun hex(s: String) = s.replace(" ", "").chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun u16(b: ByteArray, o: Int) = ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)

    private fun ipv4(proto: Int, l4: ByteArray): ByteArray {
        val p = ByteArray(20 + l4.size)
        p[0] = 0x45; p[2] = (p.size ushr 8).toByte(); p[3] = p.size.toByte(); p[8] = 64; p[9] = proto.toByte()
        byteArrayOf(10, 215.toByte(), 173.toByte(), 1).copyInto(p, 12)       // src = tun address
        byteArrayOf(1, 1, 1, 1).copyInto(p, 16)                              // dst
        l4.copyInto(p, 20)
        return p
    }

    private fun ipv6(next: Int, l4: ByteArray): ByteArray {
        val p = ByteArray(40 + l4.size)
        p[0] = 0x60; p[4] = (l4.size ushr 8).toByte(); p[5] = l4.size.toByte(); p[6] = next.toByte(); p[7] = 64
        hex("fd00 0b4b 7a17 0000 0000 0000 0000 0001").copyInto(p, 8)
        hex("2606 4700 4700 0000 0000 0000 0000 1111").copyInto(p, 24)
        l4.copyInto(p, 40)
        return p
    }

    // TCP SYN 40000 -> 443, seq 0x01020304
    private val syn = hex("9c40 01bb 01020304 00000000 5002 ffff 0000 0000")
    // DNS query id 0xabcd, RD, 1 question: example.com A IN
    private val dnsQuery = hex("abcd 0100 0001 0000 0000 0000 07 6578616d706c65 03 636f6d 00 0001 0001")
    private fun udp53(payload: ByteArray): ByteArray {
        val u = ByteArray(8 + payload.size)
        u[0] = 0xd4.toByte(); u[1] = 0x31; u[3] = 53; u[4] = (u.size ushr 8).toByte(); u[5] = u.size.toByte()
        payload.copyInto(u, 8); return u
    }

    @Test fun ipv4SynGetsValidRst() {
        val r = PacketResponder.respond(ipv4(6, syn))!!
        assertEquals(0, PacketResponder.checksum(r, 0, 20, 0))                        // IP header checksum valid
        assertEquals(listOf<Byte>(1, 1, 1, 1), r.copyOfRange(12, 16).toList())        // src/dst swapped
        assertEquals(443, u16(r, 20)); assertEquals(40000, u16(r, 22))                // ports swapped
        assertEquals(0x14, r[33].toInt() and 0xFF)                                    // RST|ACK
        assertEquals(0x0102, u16(r, 28)); assertEquals(0x0305, u16(r, 30))            // ack = seq + 1
        // TCP checksum valid: recompute over pseudo header + segment must give 0
        val pseudo = r.copyOfRange(12, 20) + byteArrayOf(0, 6, 0, 20)
        val s = pseudo.foldIndexed(0L) { i, acc, b -> acc + if (i % 2 == 0) (b.toInt() and 0xFF) shl 8 else (b.toInt() and 0xFF) }
        assertEquals(0, PacketResponder.checksum(r, 20, 20, s))
    }

    @Test fun ipv4DnsGetsRefused() {
        val r = PacketResponder.respond(ipv4(17, udp53(dnsQuery)))!!
        val dns = r.copyOfRange(28, r.size)
        assertEquals(0xabcd, u16(dns, 0))                     // same id
        assertTrue(dns[2].toInt() and 0x80 != 0)              // response
        assertEquals(5, dns[3].toInt() and 0x0F)              // REFUSED
        assertEquals(1, u16(dns, 4)); assertEquals(0, u16(dns, 6))
        assertEquals(53, u16(r, 20))                          // from port 53
        assertEquals(0, PacketResponder.checksum(r, 0, 20, 0))
    }

    @Test fun ipv6SynAndDnsAnswered() {
        val rst = PacketResponder.respond(ipv6(6, syn))!!
        assertEquals(0x60, rst[0].toInt() and 0xF0); assertEquals(20, u16(rst, 4)); assertEquals(0x14, rst[53].toInt() and 0xFF)
        val dns = PacketResponder.respond(ipv6(17, udp53(dnsQuery)))!!
        assertEquals(5, dns[40 + 8 + 3].toInt() and 0x0F)
        assertTrue(u16(dns, 46) != 0)                         // UDP checksum mandatory on IPv6
    }

    @Test fun otherTrafficIsDroppedSilently() {
        val ack = syn.copyOf().also { it[13] = 0x10 }                       // established ACK
        assertNull(PacketResponder.respond(ipv4(6, ack)))
        val rst = syn.copyOf().also { it[13] = 0x04 }
        assertNull(PacketResponder.respond(ipv4(6, rst)))                   // never answer RST (no loops)
        val quic = udp53(dnsQuery).also { it[2] = 0x01; it[3] = 0xbb.toByte() } // UDP 443
        assertNull(PacketResponder.respond(ipv4(17, quic)))
        assertNull(PacketResponder.respond(ipv4(1, ByteArray(8))))          // ICMP
        assertNull(PacketResponder.respond(byteArrayOf(0x45, 0, 0)))        // truncated
        assertNull(PacketResponder.respond(ByteArray(0).let { byteArrayOf(0x00) }))
    }
}
