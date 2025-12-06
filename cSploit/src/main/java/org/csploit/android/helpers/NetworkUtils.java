/*
 * This file is part of the cSploit.
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

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Utility class for common network operations.
 * Provides helper methods for IP address manipulation, validation, and formatting.
 */
public final class NetworkUtils {

    private static final String TAG = "NetworkUtils";

    // IP address validation patterns
    private static final Pattern IPV4_PATTERN = Pattern.compile(
        "^(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])$"
    );

    private static final Pattern IPV6_PATTERN = Pattern.compile(
        "^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|" +
        "^(?:[0-9a-fA-F]{1,4}:){1,7}:$|" +
        "^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|" +
        "^(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}$|" +
        "^(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}$|" +
        "^(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}$|" +
        "^(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}$|" +
        "^[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}$|" +
        "^:(?::[0-9a-fA-F]{1,4}){1,7}$|" +
        "^::$"
    );

    private static final Pattern MAC_PATTERN = Pattern.compile(
        "^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
    );

    private NetworkUtils() {
        // Private constructor to prevent instantiation
    }

    /**
     * Validate an IPv4 address string.
     *
     * @param ip the IP address to validate
     * @return true if the IP is a valid IPv4 address
     */
    public static boolean isValidIPv4(String ip) {
        return ip != null && IPV4_PATTERN.matcher(ip).matches();
    }

    /**
     * Validate an IPv6 address string.
     *
     * @param ip the IP address to validate
     * @return true if the IP is a valid IPv6 address
     */
    public static boolean isValidIPv6(String ip) {
        return ip != null && IPV6_PATTERN.matcher(ip).matches();
    }

    /**
     * Validate any IP address (IPv4 or IPv6).
     *
     * @param ip the IP address to validate
     * @return true if the IP is valid
     */
    public static boolean isValidIP(String ip) {
        return isValidIPv4(ip) || isValidIPv6(ip);
    }

    /**
     * Validate a MAC address string.
     *
     * @param mac the MAC address to validate
     * @return true if the MAC address is valid
     */
    public static boolean isValidMAC(String mac) {
        return mac != null && MAC_PATTERN.matcher(mac).matches();
    }

    /**
     * Convert a byte array to a MAC address string.
     *
     * @param bytes the MAC address bytes (6 bytes)
     * @return the formatted MAC address string (XX:XX:XX:XX:XX:XX)
     */
    public static String bytesToMac(byte[] bytes) {
        if (bytes == null || bytes.length != 6) {
            return null;
        }
        StringBuilder sb = new StringBuilder(17);
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format(Locale.US, "%02X", bytes[i] & 0xFF));
        }
        return sb.toString();
    }

    /**
     * Convert a MAC address string to bytes.
     *
     * @param mac the MAC address string
     * @return the MAC address as a byte array, or null if invalid
     */
    public static byte[] macToBytes(String mac) {
        if (!isValidMAC(mac)) {
            return null;
        }
        String[] parts = mac.split("[:-]");
        byte[] bytes = new byte[6];
        for (int i = 0; i < 6; i++) {
            bytes[i] = (byte) Integer.parseInt(parts[i], 16);
        }
        return bytes;
    }

    /**
     * Convert an IP address to its long representation.
     *
     * @param ip the IPv4 address
     * @return the IP as a long value
     */
    public static long ipToLong(String ip) {
        if (!isValidIPv4(ip)) {
            return -1;
        }
        String[] parts = ip.split("\\.");
        return ((Long.parseLong(parts[0]) << 24) +
                (Long.parseLong(parts[1]) << 16) +
                (Long.parseLong(parts[2]) << 8) +
                Long.parseLong(parts[3]));
    }

    /**
     * Convert a long value to an IPv4 address string.
     *
     * @param ip the IP as a long value
     * @return the IPv4 address string
     */
    public static String longToIp(long ip) {
        return String.format(Locale.US, "%d.%d.%d.%d",
            (ip >> 24) & 0xFF,
            (ip >> 16) & 0xFF,
            (ip >> 8) & 0xFF,
            ip & 0xFF);
    }

    /**
     * Check if an IP address is in a private range (RFC 1918).
     *
     * @param ip the IP address to check
     * @return true if the IP is private
     */
    public static boolean isPrivateIP(String ip) {
        if (!isValidIPv4(ip)) {
            return false;
        }
        String[] parts = ip.split("\\.");
        int first = Integer.parseInt(parts[0]);
        int second = Integer.parseInt(parts[1]);

        // 10.0.0.0/8
        if (first == 10) return true;
        // 172.16.0.0/12
        if (first == 172 && second >= 16 && second <= 31) return true;
        // 192.168.0.0/16
        if (first == 192 && second == 168) return true;
        // 127.0.0.0/8 (loopback)
        if (first == 127) return true;

        return false;
    }

    /**
     * Check if an IP address is a loopback address.
     *
     * @param ip the IP address to check
     * @return true if the IP is a loopback address
     */
    public static boolean isLoopback(String ip) {
        if (ip == null) return false;
        return ip.equals("127.0.0.1") || ip.equals("::1") || ip.startsWith("127.");
    }

    /**
     * Get the broadcast address for a given IP and subnet mask.
     *
     * @param ip the IP address
     * @param netmask the subnet mask
     * @return the broadcast address
     */
    public static String getBroadcastAddress(String ip, String netmask) {
        if (!isValidIPv4(ip) || !isValidIPv4(netmask)) {
            return null;
        }
        long ipLong = ipToLong(ip);
        long maskLong = ipToLong(netmask);
        long broadcast = (ipLong & maskLong) | (~maskLong & 0xFFFFFFFFL);
        return longToIp(broadcast);
    }

    /**
     * Get the network address for a given IP and subnet mask.
     *
     * @param ip the IP address
     * @param netmask the subnet mask
     * @return the network address
     */
    public static String getNetworkAddress(String ip, String netmask) {
        if (!isValidIPv4(ip) || !isValidIPv4(netmask)) {
            return null;
        }
        long ipLong = ipToLong(ip);
        long maskLong = ipToLong(netmask);
        return longToIp(ipLong & maskLong);
    }

    /**
     * Calculate the CIDR prefix length from a subnet mask.
     *
     * @param netmask the subnet mask
     * @return the CIDR prefix length (0-32)
     */
    public static int netmaskToCidr(String netmask) {
        if (!isValidIPv4(netmask)) {
            return -1;
        }
        long maskLong = ipToLong(netmask);
        int cidr = 0;
        while ((maskLong & 0x80000000L) != 0) {
            cidr++;
            maskLong <<= 1;
        }
        return cidr;
    }

    /**
     * Convert a CIDR prefix length to a subnet mask.
     *
     * @param cidr the CIDR prefix length (0-32)
     * @return the subnet mask
     */
    public static String cidrToNetmask(int cidr) {
        if (cidr < 0 || cidr > 32) {
            return null;
        }
        long mask = cidr == 0 ? 0 : 0xFFFFFFFFL << (32 - cidr);
        return longToIp(mask);
    }

    /**
     * Get all network interfaces on the device.
     *
     * @return list of interface names
     */
    public static List<String> getNetworkInterfaces() {
        List<String> interfaces = new ArrayList<>();
        try {
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                interfaces.add(ni.getName());
            }
        } catch (SocketException e) {
            LoggingHelper.e(TAG, "Failed to get network interfaces", e);
        }
        return interfaces;
    }

    /**
     * Check if a hostname can be resolved to an IP address.
     *
     * @param hostname the hostname to check
     * @return true if the hostname can be resolved
     */
    public static boolean canResolve(String hostname) {
        if (hostname == null || hostname.isEmpty()) {
            return false;
        }
        try {
            InetAddress.getByName(hostname);
            return true;
        } catch (UnknownHostException e) {
            return false;
        }
    }

    /**
     * Resolve a hostname to its IP addresses.
     *
     * @param hostname the hostname to resolve
     * @return list of IP addresses, or empty list if resolution fails
     */
    public static List<String> resolveHostname(String hostname) {
        List<String> addresses = new ArrayList<>();
        if (hostname == null || hostname.isEmpty()) {
            return addresses;
        }
        try {
            InetAddress[] results = InetAddress.getAllByName(hostname);
            for (InetAddress addr : results) {
                addresses.add(addr.getHostAddress());
            }
        } catch (UnknownHostException e) {
            LoggingHelper.d(TAG, "Failed to resolve hostname: " + hostname);
        }
        return addresses;
    }

    /**
     * Check if a port number is valid.
     *
     * @param port the port number to check
     * @return true if the port is valid (1-65535)
     */
    public static boolean isValidPort(int port) {
        return port > 0 && port <= 65535;
    }

    /**
     * Check if a port number is in the well-known range.
     *
     * @param port the port number to check
     * @return true if the port is well-known (1-1023)
     */
    public static boolean isWellKnownPort(int port) {
        return port > 0 && port <= 1023;
    }

    /**
     * Check if a port number is in the registered range.
     *
     * @param port the port number to check
     * @return true if the port is registered (1024-49151)
     */
    public static boolean isRegisteredPort(int port) {
        return port >= 1024 && port <= 49151;
    }

    /**
     * Check if a port number is in the dynamic/private range.
     *
     * @param port the port number to check
     * @return true if the port is dynamic (49152-65535)
     */
    public static boolean isDynamicPort(int port) {
        return port >= 49152 && port <= 65535;
    }
}
