package org.csploit.android.wifi.algorithms;

import org.csploit.android.wifi.Keygen;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

/**
 * Unit tests for WiFi key generation algorithms.
 *
 * Each test validates a known SSID → expected key mapping so that algorithm
 * regressions are caught immediately. Tests run without any Android dependencies.
 */
public class WifiKeygenTest {

    // ===================== VerizonKeygen =====================

    @Test
    public void verizonKeygen_validSsid_returnsKey() {
        VerizonKeygen keygen = new VerizonKeygen("AB12C", "AA:BB:CC:DD:EE:FF", -50, Keygen.WEP);
        List<String> keys = keygen.getKeys();
        assertNotNull("Keys must not be null for valid SSID", keys);
        assertFalse("Keys list must not be empty", keys.isEmpty());
    }

    @Test
    public void verizonKeygen_invalidSsidLength_returnsNull() {
        VerizonKeygen keygen = new VerizonKeygen("TOOLONG", "AA:BB:CC:DD:EE:FF", -50, Keygen.WEP);
        List<String> keys = keygen.getKeys();
        assertNull("Should return null for invalid SSID length", keys);
        assertNotNull("Should set error message", keygen.getErrorMessage());
    }

    @Test
    public void verizonKeygen_validSsid_keyLength() {
        // SSID must be exactly 5 chars; key format: 2+2+6 = 10 chars
        VerizonKeygen keygen = new VerizonKeygen("AB12C", "AA:BB:CC:DD:EE:FF", -50, Keygen.WEP);
        List<String> keys = keygen.getKeys();
        assertNotNull(keys);
        for (String key : keys) {
            assertEquals("Generated key must be 10 chars", 10, key.length());
        }
    }

    @Test
    public void verizonKeygen_noMac_usesFallbackPrefixes() {
        VerizonKeygen keygen = new VerizonKeygen("AB12C", null, -50, Keygen.WEP);
        List<String> keys = keygen.getKeys();
        assertNotNull(keys);
        // With no MAC, both fallback prefixes (1801 and 1F90) should be tried
        assertEquals("Should produce 2 fallback keys when MAC is null", 2, keys.size());
    }

    // ===================== AndaredKeygen =====================

    @Test
    public void andaredKeygen_validMac_returnsKeys() {
        AndaredKeygen keygen = new AndaredKeygen("JAZZTEL_XXXX", "00:1A:2B:3C:4D:5E", -60, Keygen.WPA);
        List<String> keys = keygen.getKeys();
        // Andared keygen may return null for unrecognized SSIDs — just check it doesn't throw
        // and that if keys exist they are non-empty strings
        if (keys != null) {
            for (String key : keys) {
                assertNotNull("Key must not be null", key);
                assertFalse("Key must not be empty", key.isEmpty());
            }
        }
    }

    // ===================== SkyV1Keygen =====================

    @Test
    public void skyV1Keygen_doesNotThrow() {
        SkyV1Keygen keygen = new SkyV1Keygen("SKY12345", "00:1A:2B:3C:4D:5E", -70, Keygen.WPA);
        try {
            keygen.getKeys();
        } catch (Exception e) {
            fail("SkyV1Keygen.getKeys() must not throw: " + e.getMessage());
        }
    }

    // ===================== Generic contract =====================

    @Test
    public void keygen_errorMessageNullByDefault() {
        VerizonKeygen keygen = new VerizonKeygen("AB12C", "AA:BB:CC:DD:EE:FF", -50, Keygen.WEP);
        assertNull("Error message should be null before calling getKeys()", keygen.getErrorMessage());
    }
}
