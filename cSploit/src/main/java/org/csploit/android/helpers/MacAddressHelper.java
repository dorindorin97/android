/*
 * This file is part of cSploit.
 *
 * cSploit is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * cSploit is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with cSploit.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.csploit.android.helpers;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.regex.Pattern;

/**
 * Helper class for MAC address manipulation and validation.
 * Provides utilities for MAC address operations.
 */
public class MacAddressHelper {
    
    /** Tag for logging. */
    public static final String TAG = "MacAddressHelper";
    
    // MAC address patterns
    private static final Pattern MAC_COLON_PATTERN = Pattern.compile(
            "^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"
    );
    
    private static final Pattern MAC_DASH_PATTERN = Pattern.compile(
            "^([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}$"
    );
    
    private static final Pattern MAC_NO_SEP_PATTERN = Pattern.compile(
            "^[0-9A-Fa-f]{12}$"
    );
    
    /**
     * Check if a string is a valid MAC address.
     * 
     * @param mac MAC address string (supports colon, dash, or no separator)
     * @return true if valid MAC address
     */
    public static boolean isValidMac(@Nullable String mac) {
        if (mac == null || mac.isEmpty()) {
            return false;
        }
        
        return MAC_COLON_PATTERN.matcher(mac).matches() ||
               MAC_DASH_PATTERN.matcher(mac).matches() ||
               MAC_NO_SEP_PATTERN.matcher(mac).matches();
    }
    
    /**
     * Normalize MAC address to colon-separated uppercase format.
     * 
     * @param mac MAC address in any valid format
     * @return Normalized MAC (e.g., "AA:BB:CC:DD:EE:FF"), or null if invalid
     */
    @Nullable
    public static String normalizeMac(@Nullable String mac) {
        if (!isValidMac(mac)) {
            return null;
        }
        
        // Remove all separators and convert to uppercase
        String cleanMac = mac.replace(":", "").replace("-", "").toUpperCase();
        
        // Insert colons
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 12; i += 2) {
            if (i > 0) {
                sb.append(':');
            }
            sb.append(cleanMac.substring(i, i + 2));
        }
        
        return sb.toString();
    }
    
    /**
     * Convert MAC address to byte array.
     * 
     * @param mac MAC address string
     * @return Byte array (length 6), or null if invalid
     */
    @Nullable
    public static byte[] macToBytes(@Nullable String mac) {
        if (!isValidMac(mac)) {
            return null;
        }
        
        String cleanMac = mac.replace(":", "").replace("-", "");
        byte[] bytes = new byte[6];
        
        for (int i = 0; i < 6; i++) {
            bytes[i] = (byte) Integer.parseInt(cleanMac.substring(i * 2, i * 2 + 2), 16);
        }
        
        return bytes;
    }
    
    /**
     * Convert byte array to MAC address string.
     * 
     * @param bytes Byte array (must be length 6)
     * @return MAC address string with colons
     */
    @Nullable
    public static String bytesToMac(@Nullable byte[] bytes) {
        if (bytes == null || bytes.length != 6) {
            return null;
        }
        
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            if (i > 0) {
                sb.append(':');
            }
            sb.append(String.format("%02X", bytes[i] & 0xFF));
        }
        
        return sb.toString();
    }
    
    /**
     * Convert MAC address to long.
     * 
     * @param mac MAC address string
     * @return Long representation
     */
    public static long macToLong(@Nullable String mac) {
        byte[] bytes = macToBytes(mac);
        if (bytes == null) {
            return -1;
        }
        
        long result = 0;
        for (int i = 0; i < 6; i++) {
            result = (result << 8) | (bytes[i] & 0xFF);
        }
        return result;
    }
    
    /**
     * Convert long to MAC address string.
     * 
     * @param mac Long representation
     * @return MAC address string
     */
    @NonNull
    public static String longToMac(long mac) {
        byte[] bytes = new byte[6];
        for (int i = 5; i >= 0; i--) {
            bytes[i] = (byte) (mac & 0xFF);
            mac >>= 8;
        }
        return bytesToMac(bytes);
    }
    
    /**
     * Check if MAC address is broadcast (FF:FF:FF:FF:FF:FF).
     * 
     * @param mac MAC address string
     * @return true if broadcast address
     */
    public static boolean isBroadcast(@Nullable String mac) {
        String normalized = normalizeMac(mac);
        return "FF:FF:FF:FF:FF:FF".equals(normalized);
    }
    
    /**
     * Check if MAC address is multicast.
     * 
     * @param mac MAC address string
     * @return true if multicast address
     */
    public static boolean isMulticast(@Nullable String mac) {
        byte[] bytes = macToBytes(mac);
        if (bytes == null) {
            return false;
        }
        return (bytes[0] & 0x01) != 0;
    }
    
    /**
     * Check if MAC address is locally administered.
     * 
     * @param mac MAC address string
     * @return true if locally administered
     */
    public static boolean isLocallyAdministered(@Nullable String mac) {
        byte[] bytes = macToBytes(mac);
        if (bytes == null) {
            return false;
        }
        return (bytes[0] & 0x02) != 0;
    }
    
    /**
     * Get OUI (Organizationally Unique Identifier) from MAC address.
     * This is the first 3 bytes which identify the manufacturer.
     * 
     * @param mac MAC address string
     * @return OUI string (e.g., "AA:BB:CC"), or null if invalid
     */
    @Nullable
    public static String getOui(@Nullable String mac) {
        String normalized = normalizeMac(mac);
        if (normalized == null) {
            return null;
        }
        return normalized.substring(0, 8);
    }
    
    /**
     * Get NIC-specific portion of MAC address.
     * This is the last 3 bytes.
     * 
     * @param mac MAC address string
     * @return NIC portion (e.g., "DD:EE:FF"), or null if invalid
     */
    @Nullable
    public static String getNic(@Nullable String mac) {
        String normalized = normalizeMac(mac);
        if (normalized == null) {
            return null;
        }
        return normalized.substring(9);
    }
    
    /**
     * Compare two MAC addresses for equality.
     * 
     * @param mac1 First MAC address
     * @param mac2 Second MAC address
     * @return true if equal
     */
    public static boolean equals(@Nullable String mac1, @Nullable String mac2) {
        String norm1 = normalizeMac(mac1);
        String norm2 = normalizeMac(mac2);
        
        if (norm1 == null || norm2 == null) {
            return norm1 == norm2;
        }
        
        return norm1.equals(norm2);
    }
    
    /**
     * Format MAC address with custom separator.
     * 
     * @param mac MAC address string
     * @param separator Separator character
     * @param uppercase Whether to use uppercase
     * @return Formatted MAC address
     */
    @Nullable
    public static String format(@Nullable String mac, char separator, boolean uppercase) {
        String normalized = normalizeMac(mac);
        if (normalized == null) {
            return null;
        }
        
        String result = normalized.replace(':', separator);
        return uppercase ? result.toUpperCase() : result.toLowerCase();
    }
    
    /**
     * Generate a random MAC address.
     * 
     * @param locallyAdministered Whether to set locally administered bit
     * @return Random MAC address string
     */
    @NonNull
    public static String generateRandom(boolean locallyAdministered) {
        byte[] bytes = new byte[6];
        new java.util.Random().nextBytes(bytes);
        
        // Clear multicast bit
        bytes[0] = (byte) (bytes[0] & 0xFE);
        
        if (locallyAdministered) {
            // Set locally administered bit
            bytes[0] = (byte) (bytes[0] | 0x02);
        } else {
            // Clear locally administered bit
            bytes[0] = (byte) (bytes[0] & 0xFD);
        }
        
        return bytesToMac(bytes);
    }
    
    /**
     * Mask MAC address for privacy (e.g., "AA:BB:CC:XX:XX:XX").
     * 
     * @param mac MAC address string
     * @param visibleOctets Number of octets to show (1-6)
     * @return Masked MAC address
     */
    @Nullable
    public static String mask(@Nullable String mac, int visibleOctets) {
        String normalized = normalizeMac(mac);
        if (normalized == null) {
            return null;
        }
        
        if (visibleOctets < 1) visibleOctets = 1;
        if (visibleOctets > 6) visibleOctets = 6;
        
        String[] parts = normalized.split(":");
        StringBuilder sb = new StringBuilder();
        
        for (int i = 0; i < 6; i++) {
            if (i > 0) sb.append(':');
            sb.append(i < visibleOctets ? parts[i] : "XX");
        }
        
        return sb.toString();
    }
    
    private MacAddressHelper() {
        // Prevent instantiation
    }
}
