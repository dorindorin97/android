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

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Helper class for IPv6 address operations.
 * Provides validation, conversion, and manipulation of IPv6 addresses.
 */
public final class IPv6Helper {

    private static final String TAG = "IPv6Helper";

    // IPv6 regex patterns
    private static final Pattern IPV6_FULL_PATTERN = Pattern.compile(
            "^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$");

    private static final Pattern IPV6_COMPRESSED_PATTERN = Pattern.compile(
            "^((?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*)?)::((?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*)?)$");

    private static final Pattern IPV6_MIXED_PATTERN = Pattern.compile(
            "^(?:[0-9a-fA-F]{1,4}:){6}(?:(?:[0-9]{1,3}\\.){3}[0-9]{1,3})$");

    // Well-known IPv6 addresses
    public static final String LOOPBACK = "::1";
    public static final String ANY = "::";
    public static final String LINK_LOCAL_PREFIX = "fe80::";
    public static final String MULTICAST_ALL_NODES = "ff02::1";
    public static final String MULTICAST_ALL_ROUTERS = "ff02::2";

    private IPv6Helper() {
        // Prevent instantiation
    }

    /**
     * Check if a string is a valid IPv6 address.
     *
     * @param address Address string to validate
     * @return true if valid IPv6 address
     */
    public static boolean isValidIPv6(@Nullable String address) {
        if (address == null || address.isEmpty()) {
            return false;
        }

        // Remove zone ID if present (e.g., fe80::1%eth0)
        String cleanAddress = removeZoneId(address);

        // Check against patterns
        if (IPV6_FULL_PATTERN.matcher(cleanAddress).matches()) {
            return true;
        }
        if (IPV6_COMPRESSED_PATTERN.matcher(cleanAddress).matches()) {
            return true;
        }
        if (IPV6_MIXED_PATTERN.matcher(cleanAddress).matches()) {
            return true;
        }

        // Try parsing with Java's InetAddress
        try {
            InetAddress inet = InetAddress.getByName(cleanAddress);
            return inet instanceof Inet6Address;
        } catch (UnknownHostException e) {
            return false;
        }
    }

    /**
     * Check if address is a link-local IPv6 address.
     *
     * @param address Address to check
     * @return true if link-local
     */
    public static boolean isLinkLocal(@Nullable String address) {
        if (address == null) {
            return false;
        }
        String normalized = normalize(address);
        return normalized != null && normalized.toLowerCase().startsWith("fe80:");
    }

    /**
     * Check if address is a loopback IPv6 address.
     *
     * @param address Address to check
     * @return true if loopback (::1)
     */
    public static boolean isLoopback(@Nullable String address) {
        if (address == null) {
            return false;
        }
        String normalized = normalize(address);
        return LOOPBACK.equals(normalized) || "0:0:0:0:0:0:0:1".equals(normalized);
    }

    /**
     * Check if address is a multicast IPv6 address.
     *
     * @param address Address to check
     * @return true if multicast (starts with ff)
     */
    public static boolean isMulticast(@Nullable String address) {
        if (address == null) {
            return false;
        }
        String normalized = removeZoneId(address.toLowerCase().trim());
        return normalized.startsWith("ff");
    }

    /**
     * Check if address is a global unicast IPv6 address.
     *
     * @param address Address to check
     * @return true if global unicast (starts with 2xxx or 3xxx)
     */
    public static boolean isGlobalUnicast(@Nullable String address) {
        if (address == null) {
            return false;
        }
        String normalized = removeZoneId(address.toLowerCase().trim());
        char first = normalized.charAt(0);
        return first == '2' || first == '3';
    }

    /**
     * Check if address is a unique local address (ULA).
     *
     * @param address Address to check
     * @return true if ULA (starts with fc or fd)
     */
    public static boolean isUniqueLocal(@Nullable String address) {
        if (address == null) {
            return false;
        }
        String normalized = removeZoneId(address.toLowerCase().trim());
        return normalized.startsWith("fc") || normalized.startsWith("fd");
    }

    /**
     * Normalize an IPv6 address to standard format.
     *
     * @param address Address to normalize
     * @return Normalized address or null if invalid
     */
    @Nullable
    public static String normalize(@Nullable String address) {
        if (address == null || address.isEmpty()) {
            return null;
        }

        try {
            String cleanAddress = removeZoneId(address);
            InetAddress inet = InetAddress.getByName(cleanAddress);
            if (inet instanceof Inet6Address) {
                return inet.getHostAddress();
            }
        } catch (UnknownHostException e) {
            LoggingHelper.debug("Failed to normalize IPv6 address: " + address);
        }
        return null;
    }

    /**
     * Expand an IPv6 address to full form (all 8 groups, no ::).
     *
     * @param address Address to expand
     * @return Expanded address or null if invalid
     */
    @Nullable
    public static String expand(@Nullable String address) {
        if (address == null) {
            return null;
        }

        try {
            String cleanAddress = removeZoneId(address);
            InetAddress inet = InetAddress.getByName(cleanAddress);
            if (inet instanceof Inet6Address) {
                byte[] bytes = inet.getAddress();
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < 16; i += 2) {
                    if (i > 0) {
                        sb.append(":");
                    }
                    sb.append(String.format("%02x%02x", bytes[i] & 0xff, bytes[i + 1] & 0xff));
                }
                return sb.toString();
            }
        } catch (UnknownHostException e) {
            LoggingHelper.debug("Failed to expand IPv6 address: " + address);
        }
        return null;
    }

    /**
     * Compress an IPv6 address (use :: for longest run of zeros).
     *
     * @param address Address to compress
     * @return Compressed address or null if invalid
     */
    @Nullable
    public static String compress(@Nullable String address) {
        String expanded = expand(address);
        if (expanded == null) {
            return null;
        }

        // Split into groups
        String[] groups = expanded.split(":");

        // Find longest run of zeros
        int maxStart = -1;
        int maxLen = 0;
        int currentStart = -1;
        int currentLen = 0;

        for (int i = 0; i < groups.length; i++) {
            if ("0000".equals(groups[i])) {
                if (currentStart == -1) {
                    currentStart = i;
                    currentLen = 1;
                } else {
                    currentLen++;
                }
            } else {
                if (currentLen > maxLen) {
                    maxStart = currentStart;
                    maxLen = currentLen;
                }
                currentStart = -1;
                currentLen = 0;
            }
        }
        if (currentLen > maxLen) {
            maxStart = currentStart;
            maxLen = currentLen;
        }

        // Build compressed string
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < groups.length; i++) {
            if (i == maxStart && maxLen > 1) {
                sb.append(i == 0 ? "::" : ":");
                i += maxLen - 1;
            } else {
                if (i > 0 && !(i == maxStart + maxLen && maxLen > 1)) {
                    sb.append(":");
                }
                // Remove leading zeros from each group
                sb.append(groups[i].replaceFirst("^0+(?!$)", ""));
            }
        }

        return sb.toString();
    }

    /**
     * Remove zone ID from IPv6 address (e.g., fe80::1%eth0 -> fe80::1).
     *
     * @param address Address with possible zone ID
     * @return Address without zone ID
     */
    @NonNull
    public static String removeZoneId(@NonNull String address) {
        int zoneIdx = address.indexOf('%');
        return zoneIdx >= 0 ? address.substring(0, zoneIdx) : address;
    }

    /**
     * Extract zone ID from IPv6 address.
     *
     * @param address Address with possible zone ID
     * @return Zone ID or null if none
     */
    @Nullable
    public static String getZoneId(@NonNull String address) {
        int zoneIdx = address.indexOf('%');
        return zoneIdx >= 0 ? address.substring(zoneIdx + 1) : null;
    }

    /**
     * Convert IPv6 address to bytes.
     *
     * @param address IPv6 address string
     * @return 16-byte array or null if invalid
     */
    @Nullable
    public static byte[] toBytes(@Nullable String address) {
        if (address == null) {
            return null;
        }

        try {
            String cleanAddress = removeZoneId(address);
            InetAddress inet = InetAddress.getByName(cleanAddress);
            if (inet instanceof Inet6Address) {
                return inet.getAddress();
            }
        } catch (UnknownHostException e) {
            LoggingHelper.debug("Failed to convert IPv6 to bytes: " + address);
        }
        return null;
    }

    /**
     * Convert bytes to IPv6 address string.
     *
     * @param bytes 16-byte array
     * @return IPv6 address string or null if invalid
     */
    @Nullable
    public static String fromBytes(@Nullable byte[] bytes) {
        if (bytes == null || bytes.length != 16) {
            return null;
        }

        try {
            InetAddress inet = Inet6Address.getByAddress(bytes);
            return inet.getHostAddress();
        } catch (UnknownHostException e) {
            LoggingHelper.debug("Failed to convert bytes to IPv6");
        }
        return null;
    }

    /**
     * Get all IPv6 addresses for the device.
     *
     * @return List of IPv6 addresses
     */
    @NonNull
    public static List<String> getAllIPv6Addresses() {
        List<String> addresses = new ArrayList<>();

        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces != null && interfaces.hasMoreElements()) {
                NetworkInterface iface = interfaces.nextElement();
                Enumeration<InetAddress> inetAddresses = iface.getInetAddresses();
                while (inetAddresses.hasMoreElements()) {
                    InetAddress addr = inetAddresses.nextElement();
                    if (addr instanceof Inet6Address) {
                        addresses.add(addr.getHostAddress());
                    }
                }
            }
        } catch (SocketException e) {
            LoggingHelper.error("Failed to get IPv6 addresses: " + e.getMessage());
        }

        return addresses;
    }

    /**
     * Get global IPv6 addresses for the device.
     *
     * @return List of global IPv6 addresses
     */
    @NonNull
    public static List<String> getGlobalIPv6Addresses() {
        List<String> addresses = new ArrayList<>();
        for (String addr : getAllIPv6Addresses()) {
            if (isGlobalUnicast(addr)) {
                addresses.add(addr);
            }
        }
        return addresses;
    }

    /**
     * Get link-local IPv6 addresses for the device.
     *
     * @return List of link-local IPv6 addresses
     */
    @NonNull
    public static List<String> getLinkLocalIPv6Addresses() {
        List<String> addresses = new ArrayList<>();
        for (String addr : getAllIPv6Addresses()) {
            if (isLinkLocal(addr)) {
                addresses.add(addr);
            }
        }
        return addresses;
    }

    /**
     * Check if device has any IPv6 connectivity.
     *
     * @return true if device has at least one non-loopback IPv6 address
     */
    public static boolean hasIPv6Connectivity() {
        for (String addr : getAllIPv6Addresses()) {
            if (!isLoopback(addr)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if device has global IPv6 connectivity.
     *
     * @return true if device has at least one global unicast IPv6 address
     */
    public static boolean hasGlobalIPv6Connectivity() {
        return !getGlobalIPv6Addresses().isEmpty();
    }

    /**
     * Calculate network prefix from address and prefix length.
     *
     * @param address IPv6 address
     * @param prefixLength Prefix length (0-128)
     * @return Network prefix address or null if invalid
     */
    @Nullable
    public static String getNetworkPrefix(@Nullable String address, int prefixLength) {
        if (address == null || prefixLength < 0 || prefixLength > 128) {
            return null;
        }

        byte[] bytes = toBytes(address);
        if (bytes == null) {
            return null;
        }

        // Apply prefix mask
        int fullBytes = prefixLength / 8;
        int remainingBits = prefixLength % 8;

        for (int i = fullBytes; i < 16; i++) {
            if (i == fullBytes && remainingBits > 0) {
                int mask = (0xFF << (8 - remainingBits)) & 0xFF;
                bytes[i] = (byte) (bytes[i] & mask);
            } else {
                bytes[i] = 0;
            }
        }

        return fromBytes(bytes);
    }

    /**
     * Format IPv6 address for URL (with brackets).
     *
     * @param address IPv6 address
     * @return Address formatted for URL (e.g., [::1]) or null if invalid
     */
    @Nullable
    public static String formatForUrl(@Nullable String address) {
        String normalized = normalize(address);
        if (normalized == null) {
            return null;
        }
        return "[" + removeZoneId(normalized) + "]";
    }

    /**
     * Get IPv6 address type as a string.
     *
     * @param address IPv6 address
     * @return Type description
     */
    @NonNull
    public static String getAddressType(@Nullable String address) {
        if (!isValidIPv6(address)) {
            return "Invalid";
        }
        if (isLoopback(address)) {
            return "Loopback";
        }
        if (isLinkLocal(address)) {
            return "Link-Local";
        }
        if (isMulticast(address)) {
            return "Multicast";
        }
        if (isUniqueLocal(address)) {
            return "Unique Local (ULA)";
        }
        if (isGlobalUnicast(address)) {
            return "Global Unicast";
        }
        return "Unknown";
    }
}
