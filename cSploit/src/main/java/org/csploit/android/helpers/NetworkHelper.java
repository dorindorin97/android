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

import org.apache.commons.compress.utils.IOUtils;
import org.csploit.android.helpers.LoggingHelper;
import org.csploit.android.core.Child;
import org.csploit.android.core.ChildManager;
import org.csploit.android.core.System;
import org.csploit.android.tools.Ip;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Unified network utility class for cSploit.
 *
 * Provides:
 * - IP address validation and manipulation (IPv4/IPv6)
 * - MAC address operations
 * - Network interface utilities
 * - Gateway detection
 * - CIDR/subnet calculations
 * - Port validation
 * - Hostname resolution
 */
public final class NetworkHelper {

    private static final String TAG = "NetworkHelper";

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

    private NetworkHelper() {}

    // ==================== OUI & MAC Address Operations ====================

    /**
     * Translate an OUI to its integer representation
     * @param macAddress the 6-byte array that represents a MAC address
     * @return the OUI integer
     */
    public static int getOUICode(byte[] macAddress) {
        if (macAddress == null || macAddress.length < 3) {
            return 0;
        }
        return ((macAddress[0] & 0xFF) << 16) | ((macAddress[1] & 0xFF) << 8) | (macAddress[2] & 0xFF);
    }

    /**
     * Translate an OUI to its integer representation
     * @param hexOui a string that holds OUI in hexadecimal form (e.g. "ACDE48")
     * @return the OUI integer
     */
    public static int getOUICode(String hexOui) {
        if (hexOui == null || hexOui.isEmpty()) {
            return 0;
        }
        try {
            return Integer.parseInt(hexOui, 16);
        } catch (NumberFormatException e) {
            return 0;
        }
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

    // ==================== IP Address Validation ====================

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

    // ==================== IP Address Conversion ====================

    /**
     * Convert an IP address to its long representation.
     *
     * @param ip the IPv4 address
     * @return the IP as a long value, or -1 if invalid
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
     * Convert InetAddress to long
     *
     * @param addr the InetAddress
     * @return the IP as a long value
     */
    public static long inetAddressToLong(InetAddress addr) {
        if (addr == null) {
            return -1;
        }
        byte[] bytes = addr.getAddress();
        if (bytes.length != 4) {
            return -1; // Not IPv4
        }
        return ((long)(bytes[0] & 0xFF) << 24) |
               ((long)(bytes[1] & 0xFF) << 16) |
               ((long)(bytes[2] & 0xFF) << 8) |
               (bytes[3] & 0xFF);
    }

    // ==================== IP Address Classification ====================

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
     * Check if an IP address is a multicast address.
     *
     * @param ip the IP address to check
     * @return true if the IP is a multicast address
     */
    public static boolean isMulticast(String ip) {
        if (!isValidIPv4(ip)) {
            return false;
        }
        String[] parts = ip.split("\\.");
        int first = Integer.parseInt(parts[0]);
        return first >= 224 && first <= 239;
    }

    /**
     * Check if an IP address is a broadcast address.
     *
     * @param ip the IP address to check
     * @return true if the IP is the broadcast address
     */
    public static boolean isBroadcast(String ip) {
        return "255.255.255.255".equals(ip);
    }

    // ==================== Subnet Operations ====================

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
     * @return the CIDR prefix length (0-32), or -1 if invalid
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
     * @return the subnet mask, or null if invalid
     */
    public static String cidrToNetmask(int cidr) {
        if (cidr < 0 || cidr > 32) {
            return null;
        }
        long mask = cidr == 0 ? 0 : 0xFFFFFFFFL << (32 - cidr);
        return longToIp(mask);
    }

    /**
     * Calculate the number of usable hosts in a subnet.
     *
     * @param cidr the CIDR prefix length
     * @return the number of usable hosts
     */
    public static long getUsableHostCount(int cidr) {
        if (cidr < 0 || cidr > 32) {
            return 0;
        }
        if (cidr >= 31) {
            return cidr == 31 ? 2 : 1;
        }
        return (1L << (32 - cidr)) - 2;
    }

    /**
     * Check if an IP is within a subnet.
     *
     * @param ip the IP to check
     * @param networkIp the network address
     * @param cidr the CIDR prefix length
     * @return true if the IP is within the subnet
     */
    public static boolean isInSubnet(String ip, String networkIp, int cidr) {
        if (!isValidIPv4(ip) || !isValidIPv4(networkIp) || cidr < 0 || cidr > 32) {
            return false;
        }
        long ipLong = ipToLong(ip);
        long networkLong = ipToLong(networkIp);
        long mask = cidr == 0 ? 0 : 0xFFFFFFFFL << (32 - cidr);
        return (ipLong & mask) == (networkLong & mask);
    }

    // ==================== Byte Array Comparisons ====================

    /**
     * Compare two byte arrays by length and each byte value.
     * @return -1 if a < b, 0 if equal, +1 if a > b
     */
    public static int compareByteArray(byte[] a, byte[] b) {
        if (a == null && b == null) return 0;
        if (a == null) return -1;
        if (b == null) return 1;

        int result = a.length - b.length;
        if (result != 0) {
            return result;
        }

        for (int i = 0; i < a.length; i++) {
            result = ((short) a[i] & 0xFF) - ((short) b[i] & 0xFF);
            if (result != 0) {
                return result;
            }
        }
        return 0;
    }

    /**
     * Compare two InetAddresses.
     * @return -1 if a < b, 0 if equal, +1 if a > b
     */
    public static int compareInetAddresses(InetAddress a, InetAddress b) {
        if (a == null && b == null) return 0;
        if (a == null) return -1;
        if (b == null) return 1;
        return compareByteArray(a.getAddress(), b.getAddress());
    }

    // ==================== Gateway Detection ====================

    /**
     * Get the gateway address for a network interface.
     *
     * @param iface the interface name
     * @return the gateway IP address, or null if not found
     */
    public static String getIfaceGateway(String iface) {
        if (iface == null || iface.isEmpty()) {
            return null;
        }

        Pattern pattern = Pattern.compile(
            String.format("^%s\\t+00000000\\t+([0-9A-F]{8})", iface),
            Pattern.CASE_INSENSITIVE
        );
        BufferedReader reader = null;
        String line;

        try {
            reader = new BufferedReader(new InputStreamReader(new FileInputStream("/proc/net/route")));

            while ((line = reader.readLine()) != null) {
                Matcher matcher = pattern.matcher(line);
                if (!matcher.find()) {
                    continue;
                }
                String rawAddress = matcher.group(1);
                StringBuilder sb = new StringBuilder();
                for (int i = 6; ; i -= 2) {
                    String part = rawAddress.substring(i, i + 2);
                    sb.append(Integer.parseInt(part, 16));
                    if (i > 0) {
                        sb.append('.');
                    } else {
                        break;
                    }
                }
                String res = sb.toString();
                LoggingHelper.debug("found system default gateway for interface " + iface + ": " + res);
                return res;
            }
        } catch (IOException e) {
            LoggingHelper.e(TAG, "Failed to get gateway via route", e);
        } finally {
            IOUtils.closeQuietly(reader);
        }

        LoggingHelper.warning("falling back to ip tool");
        return getIfaceGatewayUsingIp(iface);
    }

    private static String getIfaceGatewayUsingIp(String iface) {
        if (!System.isCoreInitialized()) {
            return null;
        }

        final StringBuilder sb = new StringBuilder();

        try {
            Child process = System.getTools().ip.getGatewayForIface(iface, new Ip.GatewayReceiver() {
                @Override
                public void onGatewayFound(String gateway) {
                    sb.append(gateway);
                }
            });
            process.join();
        } catch (ChildManager.ChildNotStartedException | InterruptedException e) {
            LoggingHelper.e(TAG, "Failed to get gateway via ip tool", e);
        }

        return sb.length() > 0 ? sb.toString() : null;
    }

    // ==================== Network Interface Utilities ====================

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
     * Get active (up and not loopback) network interfaces.
     *
     * @return list of active interface names
     */
    public static List<String> getActiveNetworkInterfaces() {
        List<String> interfaces = new ArrayList<>();
        try {
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (ni.isUp() && !ni.isLoopback()) {
                    interfaces.add(ni.getName());
                }
            }
        } catch (SocketException e) {
            LoggingHelper.e(TAG, "Failed to get active network interfaces", e);
        }
        return interfaces;
    }

    /**
     * Get the MAC address of a network interface.
     *
     * @param interfaceName the interface name
     * @return the MAC address string, or null if not available
     */
    public static String getInterfaceMacAddress(String interfaceName) {
        try {
            NetworkInterface ni = NetworkInterface.getByName(interfaceName);
            if (ni != null) {
                byte[] mac = ni.getHardwareAddress();
                if (mac != null) {
                    return bytesToMac(mac);
                }
            }
        } catch (SocketException e) {
            LoggingHelper.e(TAG, "Failed to get MAC address for " + interfaceName, e);
        }
        return null;
    }

    // ==================== Hostname Resolution ====================

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
     * Resolve a hostname to its first IP address.
     *
     * @param hostname the hostname to resolve
     * @return the IP address, or null if resolution fails
     */
    public static String resolveHostnameFirst(String hostname) {
        if (hostname == null || hostname.isEmpty()) {
            return null;
        }
        try {
            InetAddress addr = InetAddress.getByName(hostname);
            return addr.getHostAddress();
        } catch (UnknownHostException e) {
            return null;
        }
    }

    /**
     * Perform reverse DNS lookup.
     *
     * @param ip the IP address
     * @return the hostname, or the IP if lookup fails
     */
    public static String reverseLookup(String ip) {
        if (!isValidIP(ip)) {
            return ip;
        }
        try {
            InetAddress addr = InetAddress.getByName(ip);
            String hostname = addr.getCanonicalHostName();
            // If canonical name equals the IP, lookup failed
            return hostname.equals(ip) ? ip : hostname;
        } catch (UnknownHostException e) {
            return ip;
        }
    }

    // ==================== Port Validation ====================

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

    /**
     * Parse a port string to integer.
     *
     * @param portStr the port string
     * @return the port number, or -1 if invalid
     */
    public static int parsePort(String portStr) {
        if (portStr == null || portStr.isEmpty()) {
            return -1;
        }
        try {
            int port = Integer.parseInt(portStr.trim());
            return isValidPort(port) ? port : -1;
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    // ==================== Utility Methods ====================

    /**
     * Format bytes as a human-readable network speed string.
     *
     * @param bytesPerSecond bytes per second
     * @return formatted string (e.g., "1.5 MB/s")
     */
    public static String formatNetworkSpeed(long bytesPerSecond) {
        if (bytesPerSecond < 1024) {
            return bytesPerSecond + " B/s";
        } else if (bytesPerSecond < 1024 * 1024) {
            return String.format(Locale.US, "%.1f KB/s", bytesPerSecond / 1024.0);
        } else if (bytesPerSecond < 1024 * 1024 * 1024) {
            return String.format(Locale.US, "%.1f MB/s", bytesPerSecond / (1024.0 * 1024));
        } else {
            return String.format(Locale.US, "%.2f GB/s", bytesPerSecond / (1024.0 * 1024 * 1024));
        }
    }

    /**
     * Format an IP and port combination.
     *
     * @param ip the IP address
     * @param port the port number
     * @return formatted string (e.g., "192.168.1.1:8080" or "[::1]:8080")
     */
    public static String formatIpPort(String ip, int port) {
        if (ip == null) {
            return ":" + port;
        }
        if (isValidIPv6(ip)) {
            return "[" + ip + "]:" + port;
        }
        return ip + ":" + port;
    }
}
