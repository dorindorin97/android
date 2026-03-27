package org.csploit.android.net;

import org.junit.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;

import static org.junit.Assert.*;

/**
 * Unit tests for IP4Address.
 */
public class IP4AddressTest {

    // ── construction ──────────────────────────────────────────────────────────

    @Test
    public void stringConstructor_parsesAddress() throws Exception {
        IP4Address addr = new IP4Address("192.168.1.1");
        assertEquals("192.168.1.1", addr.toString());
    }

    @Test
    public void byteArrayConstructor_roundtrips() throws Exception {
        byte[] bytes = {(byte) 10, (byte) 0, (byte) 0, (byte) 1};
        IP4Address addr = new IP4Address(bytes);
        assertEquals("10.0.0.1", addr.toString());
    }

    @Test
    public void inetAddressConstructor_roundtrips() throws Exception {
        InetAddress inet = InetAddress.getByName("172.16.5.100");
        IP4Address addr = new IP4Address(inet);
        assertEquals("172.16.5.100", addr.toString());
    }

    @Test
    public void stringConstructor_boundaryMin() throws Exception {
        IP4Address addr = new IP4Address("0.0.0.0");
        assertEquals("0.0.0.0", addr.toString());
    }

    @Test
    public void stringConstructor_boundaryMax() throws Exception {
        IP4Address addr = new IP4Address("255.255.255.255");
        assertEquals("255.255.255.255", addr.toString());
    }

    // ── toInteger / toByteArray ───────────────────────────────────────────────

    @Test
    public void toInteger_matchesBigEndianValue() throws Exception {
        IP4Address addr = new IP4Address("1.2.3.4");
        // 1.2.3.4 big-endian = 0x01020304
        assertEquals(0x01020304, addr.toInteger());
    }

    @Test
    public void toByteArray_returnsCopy() throws Exception {
        IP4Address addr = new IP4Address("10.20.30.40");
        byte[] b1 = addr.toByteArray();
        byte[] b2 = addr.toByteArray();
        assertNotSame("toByteArray must return a defensive copy", b1, b2);
        assertArrayEquals(b1, b2);
    }

    @Test
    public void toByteArray_correctValues() throws Exception {
        IP4Address addr = new IP4Address("192.168.0.1");
        byte[] b = addr.toByteArray();
        assertEquals((byte) 192, b[0]);
        assertEquals((byte) 168, b[1]);
        assertEquals((byte) 0,   b[2]);
        assertEquals((byte) 1,   b[3]);
    }

    // ── compareTo ────────────────────────────────────────────────────────────

    @Test
    public void compareTo_lessThan() throws Exception {
        IP4Address a = new IP4Address("10.0.0.1");
        IP4Address b = new IP4Address("10.0.0.2");
        assertTrue("10.0.0.1 < 10.0.0.2", a.compareTo(b) < 0);
    }

    @Test
    public void compareTo_greaterThan() throws Exception {
        // compareTo uses signed int; stay within the same high-octet range
        IP4Address a = new IP4Address("10.0.0.5");
        IP4Address b = new IP4Address("10.0.0.1");
        assertTrue("10.0.0.5 > 10.0.0.1", a.compareTo(b) > 0);
    }

    @Test
    public void compareTo_equal() throws Exception {
        IP4Address a = new IP4Address("172.16.0.1");
        IP4Address b = new IP4Address("172.16.0.1");
        assertEquals(0, a.compareTo(b));
    }

    // ── equals ────────────────────────────────────────────────────────────────

    @Test
    public void equals_sameAddress() throws Exception {
        IP4Address a = new IP4Address("192.168.1.100");
        IP4Address b = new IP4Address("192.168.1.100");
        assertTrue(a.equals(b));
    }

    @Test
    public void equals_differentAddress() throws Exception {
        IP4Address a = new IP4Address("192.168.1.100");
        IP4Address b = new IP4Address("192.168.1.101");
        assertFalse(a.equals(b));
    }

    @Test
    public void equals_inetAddress() throws Exception {
        IP4Address a = new IP4Address("127.0.0.1");
        InetAddress inet = InetAddress.getByName("127.0.0.1");
        assertTrue(a.equals(inet));
    }

    // ── getPrefixLength ───────────────────────────────────────────────────────

    @Test
    public void getPrefixLength_slash24() throws Exception {
        IP4Address mask = new IP4Address("255.255.255.0");
        assertEquals(24, mask.getPrefixLength());
    }

    @Test
    public void getPrefixLength_slash16() throws Exception {
        IP4Address mask = new IP4Address("255.255.0.0");
        assertEquals(16, mask.getPrefixLength());
    }

    @Test
    public void getPrefixLength_slash8() throws Exception {
        IP4Address mask = new IP4Address("255.0.0.0");
        assertEquals(8, mask.getPrefixLength());
    }

    @Test
    public void getPrefixLength_slash32() throws Exception {
        IP4Address mask = new IP4Address("255.255.255.255");
        assertEquals(32, mask.getPrefixLength());
    }

    @Test
    public void getPrefixLength_slash0() throws Exception {
        IP4Address mask = new IP4Address("0.0.0.0");
        assertEquals(0, mask.getPrefixLength());
    }

    // ── next() ───────────────────────────────────────────────────────────────

    @Test
    public void next_incrementsLastOctet() throws Exception {
        IP4Address addr = new IP4Address("192.168.1.1");
        IP4Address next = IP4Address.next(addr);
        assertNotNull(next);
        assertEquals("192.168.1.2", next.toString());
    }

    @Test
    public void next_rollsOverOctet() throws Exception {
        IP4Address addr = new IP4Address("192.168.1.255");
        IP4Address next = IP4Address.next(addr);
        assertNotNull(next);
        assertEquals("192.168.2.0", next.toString());
    }

    @Test
    public void next_maxAddressReturnsNull() throws Exception {
        IP4Address addr = new IP4Address("255.255.255.255");
        IP4Address next = IP4Address.next(addr);
        assertNull("next(255.255.255.255) should return null", next);
    }

    // ── ntohl ─────────────────────────────────────────────────────────────────

    @Test
    public void ntohl_swapsByteOrder() {
        // ntohl(0x01020304) should produce 0x04030201
        assertEquals(0x04030201, IP4Address.ntohl(0x01020304));
    }

    @Test
    public void ntohl_idempotentOnSymmetric() {
        int val = 0x01010101;
        assertEquals(val, IP4Address.ntohl(val));
    }
}
