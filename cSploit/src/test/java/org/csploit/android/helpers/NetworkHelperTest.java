package org.csploit.android.helpers;

import junit.framework.Assert;
import junit.framework.TestCase;

import java.net.InetAddress;

import static org.junit.Assert.*;
import static org.hamcrest.CoreMatchers.*;

/**
 * Comprehensive unit tests for NetworkHelper utility class
 *
 * Tests OUI code extraction, InetAddress comparison, and network utilities.
 *
 * @author cSploit Team
 * @version 1.0
 */
public class NetworkHelperTest extends TestCase {

  /**
   * Test OUI (Organizationally Unique Identifier) code extraction
   */
  public void testGetOUICode() throws Exception {
    byte[] address = new byte[] { 0x01, 0x02, 0x03 };

    int fromString = NetworkHelper.getOUICode("010203");
    int fromMAC = NetworkHelper.getOUICode(address);

    Assert.assertEquals(fromString + " differs from " + fromMAC, fromString, fromMAC);
  }

  /**
   * Test OUI code with different byte values
   */
  public void testGetOUICodeVariations() throws Exception {
    // Test with zeros
    byte[] zeroAddress = new byte[] { 0x00, 0x00, 0x00 };
    int zeroOUI = NetworkHelper.getOUICode(zeroAddress);
    Assert.assertEquals("Zero OUI should match", 0, zeroOUI);

    // Test with max values
    byte[] maxAddress = new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF };
    int maxOUI = NetworkHelper.getOUICode(maxAddress);
    Assert.assertTrue("Max OUI should be positive", maxOUI > 0);
  }

  /**
   * Test InetAddress comparison with equal addresses
   */
  public void testCompareInetAddress() throws Exception {
    InetAddress a, b;

    a = InetAddress.getLocalHost();
    b = InetAddress.getByAddress("127.0.0.1", new byte[] {127, 0, 0, 1});

    assertThat(a, is(b));

    int res = NetworkHelper.compareInetAddresses(a, b);

    assertThat(res, is(0));

    b = InetAddress.getByAddress(new byte[] {(byte) 192, (byte) 168, 1, 1});

    assertThat(a, not(b));

    res = NetworkHelper.compareInetAddresses(a, b);

    assertThat(a + " should be less than " + b, res < 0, is(true));
  }

  /**
   * Test InetAddress comparison with specific addresses
   */
  public void testCompareInetAddressSpecific() throws Exception {
    InetAddress lower = InetAddress.getByAddress(new byte[] {127, 0, 0, 1});
    InetAddress higher = InetAddress.getByAddress(new byte[] {127, 0, 0, 2});

    int res = NetworkHelper.compareInetAddresses(lower, higher);
    Assert.assertTrue("127.0.0.1 should be less than 127.0.0.2", res < 0);

    // Reverse comparison
    res = NetworkHelper.compareInetAddresses(higher, lower);
    Assert.assertTrue("127.0.0.2 should be greater than 127.0.0.1", res > 0);
  }

  /**
   * Test byte array operations for MAC addresses
   */
  public void testMACAddressHandling() throws Exception {
    // Test valid MAC address
    byte[] validMAC = new byte[] { 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E };
    assertNotNull("Valid MAC should be handled", validMAC);
    Assert.assertEquals("MAC address should have 6 bytes", 6, validMAC.length);

    // Test OUI from MAC
    byte[] oui = new byte[] { validMAC[0], validMAC[1], validMAC[2] };
    assertNotNull("OUI extraction should work", oui);
  }

  /**
   * Test IPv4 address boundary cases
   */
  public void testIPv4Boundaries() throws Exception {
    InetAddress minIP = InetAddress.getByAddress(new byte[] {0, 0, 0, 0});
    InetAddress maxIP = InetAddress.getByAddress(new byte[] {
        (byte) 255, (byte) 255, (byte) 255, (byte) 255});

    int res = NetworkHelper.compareInetAddresses(minIP, maxIP);
    Assert.assertTrue("0.0.0.0 should be less than 255.255.255.255", res < 0);
  }
}
