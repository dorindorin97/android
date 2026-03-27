package org.csploit.android.helpers;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Extended unit tests for NetworkHelper — covers IPv4/IPv6 validation, subnet
 * calculations, MAC address operations, port utilities, and formatting helpers
 * that are not covered by NetworkHelperTest.
 */
public class NetworkHelperExtendedTest {

    // ── isValidIPv4 ───────────────────────────────────────────────────────────

    @Test public void isValidIPv4_valid()   { assertTrue(NetworkHelper.isValidIPv4("192.168.1.1")); }
    @Test public void isValidIPv4_min()     { assertTrue(NetworkHelper.isValidIPv4("0.0.0.0")); }
    @Test public void isValidIPv4_max()     { assertTrue(NetworkHelper.isValidIPv4("255.255.255.255")); }
    @Test public void isValidIPv4_null()    { assertFalse(NetworkHelper.isValidIPv4(null)); }
    @Test public void isValidIPv4_empty()   { assertFalse(NetworkHelper.isValidIPv4("")); }
    @Test public void isValidIPv4_tooFewOctets()  { assertFalse(NetworkHelper.isValidIPv4("192.168.1")); }
    @Test public void isValidIPv4_octetOver255()  { assertFalse(NetworkHelper.isValidIPv4("256.0.0.1")); }
    @Test public void isValidIPv4_withPort()      { assertFalse(NetworkHelper.isValidIPv4("192.168.1.1:80")); }
    @Test public void isValidIPv4_ipv6String()    { assertFalse(NetworkHelper.isValidIPv4("::1")); }

    // ── isValidIPv6 ───────────────────────────────────────────────────────────

    @Test public void isValidIPv6_loopback()       { assertTrue(NetworkHelper.isValidIPv6("::1")); }
    @Test public void isValidIPv6_allZeros()       { assertTrue(NetworkHelper.isValidIPv6("::")); }
    @Test public void isValidIPv6_full()           {
        assertTrue(NetworkHelper.isValidIPv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
    }
    @Test public void isValidIPv6_compressed()     {
        assertTrue(NetworkHelper.isValidIPv6("2001:db8::1"));
    }
    @Test public void isValidIPv6_ipv4String()     { assertFalse(NetworkHelper.isValidIPv6("192.168.1.1")); }
    @Test public void isValidIPv6_null()           { assertFalse(NetworkHelper.isValidIPv6(null)); }

    // ── ipToLong / longToIp roundtrip ─────────────────────────────────────────

    @Test
    public void ipToLong_knownValue() {
        assertEquals(0xC0A80101L, NetworkHelper.ipToLong("192.168.1.1"));
    }

    @Test
    public void ipToLong_loopback() {
        assertEquals(0x7F000001L, NetworkHelper.ipToLong("127.0.0.1"));
    }

    @Test
    public void ipToLong_invalidReturnsMinusOne() {
        assertEquals(-1L, NetworkHelper.ipToLong("not.an.ip"));
    }

    @Test
    public void longToIp_roundtrip() {
        String ip = "10.20.30.40";
        assertEquals(ip, NetworkHelper.longToIp(NetworkHelper.ipToLong(ip)));
    }

    @Test
    public void longToIp_zero() {
        assertEquals("0.0.0.0", NetworkHelper.longToIp(0L));
    }

    // ── isPrivateIP ───────────────────────────────────────────────────────────

    @Test public void isPrivateIP_classA()     { assertTrue(NetworkHelper.isPrivateIP("10.0.0.1")); }
    @Test public void isPrivateIP_classB()     { assertTrue(NetworkHelper.isPrivateIP("172.16.0.1")); }
    @Test public void isPrivateIP_classC()     { assertTrue(NetworkHelper.isPrivateIP("192.168.1.1")); }
    @Test public void isPrivateIP_loopback()   { assertTrue(NetworkHelper.isPrivateIP("127.0.0.1")); }
    @Test public void isPrivateIP_public()     { assertFalse(NetworkHelper.isPrivateIP("8.8.8.8")); }
    @Test public void isPrivateIP_borderClassB_low()  { assertFalse(NetworkHelper.isPrivateIP("172.15.255.255")); }
    @Test public void isPrivateIP_borderClassB_high() { assertTrue(NetworkHelper.isPrivateIP("172.31.0.0")); }
    @Test public void isPrivateIP_null()       { assertFalse(NetworkHelper.isPrivateIP(null)); }

    // ── isLoopback / isMulticast / isBroadcast ────────────────────────────────

    @Test public void isLoopback_loopback()    { assertTrue(NetworkHelper.isLoopback("127.0.0.1")); }
    @Test public void isLoopback_ipv6()        { assertTrue(NetworkHelper.isLoopback("::1")); }
    @Test public void isLoopback_other()       { assertFalse(NetworkHelper.isLoopback("192.168.1.1")); }
    @Test public void isLoopback_null()        { assertFalse(NetworkHelper.isLoopback(null)); }

    @Test public void isMulticast_true()       { assertTrue(NetworkHelper.isMulticast("224.0.0.1")); }
    @Test public void isMulticast_false()      { assertFalse(NetworkHelper.isMulticast("192.168.1.1")); }
    @Test public void isMulticast_boundary()   { assertTrue(NetworkHelper.isMulticast("239.255.255.255")); }

    @Test public void isBroadcast_true()       { assertTrue(NetworkHelper.isBroadcast("255.255.255.255")); }
    @Test public void isBroadcast_false()      { assertFalse(NetworkHelper.isBroadcast("192.168.1.255")); }

    // ── subnet operations ─────────────────────────────────────────────────────

    @Test
    public void getBroadcastAddress_slash24() {
        assertEquals("192.168.1.255", NetworkHelper.getBroadcastAddress("192.168.1.1", "255.255.255.0"));
    }

    @Test
    public void getBroadcastAddress_nullArgs_returnsNull() {
        assertNull(NetworkHelper.getBroadcastAddress(null, "255.255.255.0"));
    }

    @Test
    public void getNetworkAddress_slash24() {
        assertEquals("192.168.1.0", NetworkHelper.getNetworkAddress("192.168.1.100", "255.255.255.0"));
    }

    @Test
    public void netmaskToCidr_slash24() {
        assertEquals(24, NetworkHelper.netmaskToCidr("255.255.255.0"));
    }

    @Test
    public void netmaskToCidr_slash16() {
        assertEquals(16, NetworkHelper.netmaskToCidr("255.255.0.0"));
    }

    @Test
    public void netmaskToCidr_slash0() {
        assertEquals(0, NetworkHelper.netmaskToCidr("0.0.0.0"));
    }

    @Test
    public void netmaskToCidr_slash32() {
        assertEquals(32, NetworkHelper.netmaskToCidr("255.255.255.255"));
    }

    @Test
    public void cidrToNetmask_slash24() {
        assertEquals("255.255.255.0", NetworkHelper.cidrToNetmask(24));
    }

    @Test
    public void cidrToNetmask_slash0() {
        assertEquals("0.0.0.0", NetworkHelper.cidrToNetmask(0));
    }

    @Test
    public void cidrToNetmask_slash32() {
        assertEquals("255.255.255.255", NetworkHelper.cidrToNetmask(32));
    }

    @Test
    public void cidrToNetmask_invalid_returnsNull() {
        assertNull(NetworkHelper.cidrToNetmask(-1));
        assertNull(NetworkHelper.cidrToNetmask(33));
    }

    @Test
    public void cidrNetmask_roundtrip() {
        for (int cidr = 0; cidr <= 32; cidr++) {
            String mask = NetworkHelper.cidrToNetmask(cidr);
            assertNotNull("cidr=" + cidr, mask);
            assertEquals("roundtrip failed at cidr=" + cidr, cidr, NetworkHelper.netmaskToCidr(mask));
        }
    }

    @Test
    public void isInSubnet_inside() {
        assertTrue(NetworkHelper.isInSubnet("192.168.1.100", "192.168.1.0", 24));
    }

    @Test
    public void isInSubnet_outside() {
        assertFalse(NetworkHelper.isInSubnet("192.168.2.1", "192.168.1.0", 24));
    }

    @Test
    public void isInSubnet_networkAddress_isInside() {
        assertTrue(NetworkHelper.isInSubnet("10.0.0.0", "10.0.0.0", 8));
    }

    @Test
    public void getUsableHostCount_slash24() {
        assertEquals(254L, NetworkHelper.getUsableHostCount(24));
    }

    @Test
    public void getUsableHostCount_slash32() {
        assertEquals(1L, NetworkHelper.getUsableHostCount(32));
    }

    @Test
    public void getUsableHostCount_slash0() {
        // 2^32 - 2
        assertEquals(4294967294L, NetworkHelper.getUsableHostCount(0));
    }

    // ── port validation ───────────────────────────────────────────────────────

    @Test public void isValidPort_min()      { assertTrue(NetworkHelper.isValidPort(1)); }
    @Test public void isValidPort_max()      { assertTrue(NetworkHelper.isValidPort(65535)); }
    @Test public void isValidPort_zero()     { assertFalse(NetworkHelper.isValidPort(0)); }
    @Test public void isValidPort_negative() { assertFalse(NetworkHelper.isValidPort(-1)); }
    @Test public void isValidPort_over()     { assertFalse(NetworkHelper.isValidPort(65536)); }

    @Test public void isWellKnownPort_http() { assertTrue(NetworkHelper.isWellKnownPort(80)); }
    @Test public void isWellKnownPort_high() { assertFalse(NetworkHelper.isWellKnownPort(1024)); }

    @Test public void isRegisteredPort_mysql()  { assertTrue(NetworkHelper.isRegisteredPort(3306)); }
    @Test public void isRegisteredPort_below()  { assertFalse(NetworkHelper.isRegisteredPort(80)); }

    @Test public void isDynamicPort_true()   { assertTrue(NetworkHelper.isDynamicPort(50000)); }
    @Test public void isDynamicPort_false()  { assertFalse(NetworkHelper.isDynamicPort(3306)); }

    @Test
    public void parsePort_valid() {
        assertEquals(8080, NetworkHelper.parsePort("8080"));
    }

    @Test
    public void parsePort_withSpaces() {
        assertEquals(443, NetworkHelper.parsePort("  443  "));
    }

    @Test
    public void parsePort_invalid() {
        assertEquals(-1, NetworkHelper.parsePort("not-a-port"));
    }

    @Test
    public void parsePort_zero() {
        assertEquals(-1, NetworkHelper.parsePort("0"));
    }

    @Test
    public void parsePort_null() {
        assertEquals(-1, NetworkHelper.parsePort(null));
    }

    // ── MAC address ───────────────────────────────────────────────────────────

    @Test public void isValidMAC_colons()     { assertTrue(NetworkHelper.isValidMAC("00:1A:2B:3C:4D:5E")); }
    @Test public void isValidMAC_hyphens()    { assertTrue(NetworkHelper.isValidMAC("00-1A-2B-3C-4D-5E")); }
    @Test public void isValidMAC_lowercase()  { assertTrue(NetworkHelper.isValidMAC("aa:bb:cc:dd:ee:ff")); }
    @Test public void isValidMAC_tooShort()   { assertFalse(NetworkHelper.isValidMAC("00:1A:2B:3C:4D")); }
    @Test public void isValidMAC_null()       { assertFalse(NetworkHelper.isValidMAC(null)); }
    @Test public void isValidMAC_noSeparator(){ assertFalse(NetworkHelper.isValidMAC("001A2B3C4D5E")); }

    @Test
    public void bytesToMac_correctFormat() {
        byte[] bytes = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
        assertEquals("00:1A:2B:3C:4D:5E", NetworkHelper.bytesToMac(bytes));
    }

    @Test
    public void bytesToMac_null_returnsNull() {
        assertNull(NetworkHelper.bytesToMac(null));
    }

    @Test
    public void bytesToMac_wrongLength_returnsNull() {
        assertNull(NetworkHelper.bytesToMac(new byte[]{1, 2, 3}));
    }

    @Test
    public void macToBytes_roundtrip() {
        String mac = "AA:BB:CC:DD:EE:FF";
        byte[] bytes = NetworkHelper.macToBytes(mac);
        assertNotNull(bytes);
        assertEquals(mac, NetworkHelper.bytesToMac(bytes));
    }

    @Test
    public void macToBytes_invalidMac_returnsNull() {
        assertNull(NetworkHelper.macToBytes("not:a:mac"));
    }

    // ── formatting helpers ────────────────────────────────────────────────────

    @Test
    public void formatNetworkSpeed_bytes() {
        assertEquals("500 B/s", NetworkHelper.formatNetworkSpeed(500));
    }

    @Test
    public void formatNetworkSpeed_kilobytes() {
        String result = NetworkHelper.formatNetworkSpeed(2048);
        assertTrue("Should contain KB/s", result.contains("KB/s"));
    }

    @Test
    public void formatNetworkSpeed_megabytes() {
        String result = NetworkHelper.formatNetworkSpeed(2 * 1024 * 1024);
        assertTrue("Should contain MB/s", result.contains("MB/s"));
    }

    @Test
    public void formatIpPort_ipv4() {
        assertEquals("192.168.1.1:8080", NetworkHelper.formatIpPort("192.168.1.1", 8080));
    }

    @Test
    public void formatIpPort_ipv6_brackets() {
        String result = NetworkHelper.formatIpPort("::1", 80);
        assertTrue("IPv6 must be bracketed", result.startsWith("["));
        assertTrue(result.endsWith("]:80"));
    }

    @Test
    public void formatIpPort_nullIp() {
        assertEquals(":443", NetworkHelper.formatIpPort(null, 443));
    }
}
