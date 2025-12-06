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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with cSploit. If not, see <http://www.gnu.org/licenses/>.
 */

package org.csploit.android.helpers;

import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * SubnetHelper - Subnet calculation and IP range utilities.
 * 
 * Provides:
 * - CIDR notation parsing
 * - Subnet mask calculations
 * - IP range generation
 * - Network/broadcast address calculation
 * - Subnet validation
 * 
 * Usage:
 * {@code
 * SubnetInfo info = SubnetHelper.getSubnetInfo("192.168.1.0/24");
 * String broadcast = info.getBroadcastAddress();
 * int hostCount = info.getAddressCount();
 * 
 * List<String> hosts = SubnetHelper.getHostAddresses("192.168.1.0/24");
 * }
 */
public final class SubnetHelper {
    
    private static final String TAG = "SubnetHelper";
    
    /**
     * Subnet information container.
     */
    public static class SubnetInfo {
        private final String networkAddress;
        private final String broadcastAddress;
        private final String netmask;
        private final int cidr;
        private final long lowAddress;
        private final long highAddress;
        
        SubnetInfo(String network, String broadcast, String netmask, int cidr,
                  long lowAddr, long highAddr) {
            this.networkAddress = network;
            this.broadcastAddress = broadcast;
            this.netmask = netmask;
            this.cidr = cidr;
            this.lowAddress = lowAddr;
            this.highAddress = highAddr;
        }
        
        public String getNetworkAddress() {
            return networkAddress;
        }
        
        public String getBroadcastAddress() {
            return broadcastAddress;
        }
        
        public String getNetmask() {
            return netmask;
        }
        
        public int getCidr() {
            return cidr;
        }
        
        public String getLowAddress() {
            return longToIp(lowAddress);
        }
        
        public String getHighAddress() {
            return longToIp(highAddress);
        }
        
        /**
         * Get total address count in subnet.
         */
        public long getAddressCount() {
            return highAddress - lowAddress + 1;
        }
        
        /**
         * Get usable host count (excludes network and broadcast).
         */
        public long getUsableHostCount() {
            long count = getAddressCount();
            return count > 2 ? count - 2 : 0;
        }
        
        /**
         * Check if IP is in this subnet.
         */
        public boolean isInRange(@NonNull String ip) {
            long ipLong = ipToLong(ip);
            return ipLong >= lowAddress && ipLong <= highAddress;
        }
        
        /**
         * Check if IP is a usable host address (not network or broadcast).
         */
        public boolean isUsableHost(@NonNull String ip) {
            long ipLong = ipToLong(ip);
            long networkLong = ipToLong(networkAddress);
            long broadcastLong = ipToLong(broadcastAddress);
            return ipLong > networkLong && ipLong < broadcastLong;
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("%s/%d (mask: %s, hosts: %d)",
                    networkAddress, cidr, netmask, getUsableHostCount());
        }
    }
    
    private SubnetHelper() {}
    
    /**
     * Get subnet information from CIDR notation.
     * 
     * @param cidrNotation IP/prefix (e.g., "192.168.1.0/24")
     * @return SubnetInfo or null if invalid
     */
    @Nullable
    public static SubnetInfo getSubnetInfo(@NonNull String cidrNotation) {
        try {
            String[] parts = cidrNotation.split("/");
            if (parts.length != 2) {
                return null;
            }
            
            String ip = parts[0];
            int prefix = Integer.parseInt(parts[1]);
            
            return getSubnetInfo(ip, prefix);
        } catch (Exception e) {
            Log.w(TAG, "Invalid CIDR notation: " + cidrNotation, e);
            return null;
        }
    }
    
    /**
     * Get subnet information from IP and prefix length.
     * 
     * @param ip base IP address
     * @param prefixLength prefix length (0-32)
     * @return SubnetInfo or null if invalid
     */
    @Nullable
    public static SubnetInfo getSubnetInfo(@NonNull String ip, int prefixLength) {
        if (prefixLength < 0 || prefixLength > 32) {
            return null;
        }
        
        try {
            long ipLong = ipToLong(ip);
            long mask = prefixToMask(prefixLength);
            
            long networkLong = ipLong & mask;
            long broadcastLong = networkLong | (~mask & 0xFFFFFFFFL);
            
            String networkAddress = longToIp(networkLong);
            String broadcastAddress = longToIp(broadcastLong);
            String netmask = longToIp(mask);
            
            // First usable host is network + 1, last is broadcast - 1
            long lowAddr = networkLong;
            long highAddr = broadcastLong;
            
            return new SubnetInfo(networkAddress, broadcastAddress, netmask,
                    prefixLength, lowAddr, highAddr);
        } catch (Exception e) {
            Log.w(TAG, "Failed to calculate subnet info", e);
            return null;
        }
    }
    
    /**
     * Get list of all host addresses in subnet.
     * Warning: Can be very large for small prefix lengths.
     * 
     * @param cidrNotation CIDR notation
     * @return list of IP addresses
     */
    @NonNull
    public static List<String> getHostAddresses(@NonNull String cidrNotation) {
        return getHostAddresses(cidrNotation, Integer.MAX_VALUE);
    }
    
    /**
     * Get list of host addresses in subnet with limit.
     * 
     * @param cidrNotation CIDR notation
     * @param maxHosts maximum hosts to return
     * @return list of IP addresses
     */
    @NonNull
    public static List<String> getHostAddresses(@NonNull String cidrNotation, int maxHosts) {
        SubnetInfo info = getSubnetInfo(cidrNotation);
        if (info == null) {
            return Collections.emptyList();
        }
        
        List<String> addresses = new ArrayList<>();
        long networkLong = ipToLong(info.networkAddress);
        long broadcastLong = ipToLong(info.broadcastAddress);
        
        // Start from network + 1, end at broadcast - 1
        for (long i = networkLong + 1; i < broadcastLong && addresses.size() < maxHosts; i++) {
            addresses.add(longToIp(i));
        }
        
        return addresses;
    }
    
    /**
     * Convert prefix length to netmask.
     * 
     * @param prefix prefix length (0-32)
     * @return netmask as long
     */
    public static long prefixToMask(int prefix) {
        if (prefix == 0) return 0;
        if (prefix == 32) return 0xFFFFFFFFL;
        return ~((1L << (32 - prefix)) - 1) & 0xFFFFFFFFL;
    }
    
    /**
     * Convert prefix length to netmask string.
     * 
     * @param prefix prefix length (0-32)
     * @return netmask string (e.g., "255.255.255.0")
     */
    @NonNull
    public static String prefixToNetmask(int prefix) {
        return longToIp(prefixToMask(prefix));
    }
    
    /**
     * Convert netmask to prefix length.
     * 
     * @param netmask netmask string
     * @return prefix length or -1 if invalid
     */
    public static int netmaskToPrefix(@NonNull String netmask) {
        long mask = ipToLong(netmask);
        int prefix = 0;
        
        // Count leading 1s
        for (int i = 31; i >= 0; i--) {
            if ((mask & (1L << i)) != 0) {
                prefix++;
            } else {
                break;
            }
        }
        
        // Verify it's a valid netmask (all 1s followed by all 0s)
        long expectedMask = prefixToMask(prefix);
        return mask == expectedMask ? prefix : -1;
    }
    
    /**
     * Convert IP string to long.
     * 
     * @param ip IP address string
     * @return IP as long value
     */
    public static long ipToLong(@NonNull String ip) {
        String[] octets = ip.split("\\.");
        if (octets.length != 4) {
            throw new IllegalArgumentException("Invalid IP: " + ip);
        }
        
        long result = 0;
        for (int i = 0; i < 4; i++) {
            result = (result << 8) | Integer.parseInt(octets[i]);
        }
        return result & 0xFFFFFFFFL;
    }
    
    /**
     * Convert long to IP string.
     * 
     * @param ip IP as long value
     * @return IP address string
     */
    @NonNull
    public static String longToIp(long ip) {
        return String.format(Locale.US, "%d.%d.%d.%d",
                (ip >> 24) & 0xFF,
                (ip >> 16) & 0xFF,
                (ip >> 8) & 0xFF,
                ip & 0xFF);
    }
    
    /**
     * Check if IP address is valid IPv4.
     * 
     * @param ip IP address string
     * @return true if valid
     */
    public static boolean isValidIpv4(@Nullable String ip) {
        if (ip == null || ip.isEmpty()) {
            return false;
        }
        
        String[] octets = ip.split("\\.");
        if (octets.length != 4) {
            return false;
        }
        
        try {
            for (String octet : octets) {
                int value = Integer.parseInt(octet);
                if (value < 0 || value > 255) {
                    return false;
                }
            }
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }
    
    /**
     * Check if IP is a private address.
     * 
     * @param ip IP address
     * @return true if private
     */
    public static boolean isPrivateIp(@NonNull String ip) {
        long ipLong = ipToLong(ip);
        
        // 10.0.0.0/8
        if (ipLong >= ipToLong("10.0.0.0") && ipLong <= ipToLong("10.255.255.255")) {
            return true;
        }
        
        // 172.16.0.0/12
        if (ipLong >= ipToLong("172.16.0.0") && ipLong <= ipToLong("172.31.255.255")) {
            return true;
        }
        
        // 192.168.0.0/16
        if (ipLong >= ipToLong("192.168.0.0") && ipLong <= ipToLong("192.168.255.255")) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Check if IP is a loopback address.
     * 
     * @param ip IP address
     * @return true if loopback
     */
    public static boolean isLoopback(@NonNull String ip) {
        long ipLong = ipToLong(ip);
        return ipLong >= ipToLong("127.0.0.0") && ipLong <= ipToLong("127.255.255.255");
    }
    
    /**
     * Check if IP is a link-local address.
     * 
     * @param ip IP address
     * @return true if link-local
     */
    public static boolean isLinkLocal(@NonNull String ip) {
        long ipLong = ipToLong(ip);
        return ipLong >= ipToLong("169.254.0.0") && ipLong <= ipToLong("169.254.255.255");
    }
    
    /**
     * Check if IP is a multicast address.
     * 
     * @param ip IP address
     * @return true if multicast
     */
    public static boolean isMulticast(@NonNull String ip) {
        long ipLong = ipToLong(ip);
        return ipLong >= ipToLong("224.0.0.0") && ipLong <= ipToLong("239.255.255.255");
    }
    
    /**
     * Get common subnet sizes.
     */
    @NonNull
    public static String[] getCommonSubnetSizes() {
        return new String[]{
                "/32 - Single host (1)",
                "/31 - Point-to-point (2)",
                "/30 - Small (4 total, 2 usable)",
                "/29 - Small (8 total, 6 usable)",
                "/28 - Small (16 total, 14 usable)",
                "/27 - Small (32 total, 30 usable)",
                "/26 - Medium (64 total, 62 usable)",
                "/25 - Medium (128 total, 126 usable)",
                "/24 - Class C (256 total, 254 usable)",
                "/23 - Large (512 total, 510 usable)",
                "/22 - Large (1024 total, 1022 usable)",
                "/16 - Class B (65536 total)",
                "/8 - Class A (16M total)"
        };
    }
    
    /**
     * Calculate the smallest subnet that contains two IPs.
     * 
     * @param ip1 first IP
     * @param ip2 second IP
     * @return CIDR notation for smallest containing subnet
     */
    @Nullable
    public static String getSmallestContainingSubnet(@NonNull String ip1, @NonNull String ip2) {
        try {
            long l1 = ipToLong(ip1);
            long l2 = ipToLong(ip2);
            
            // Find the highest bit where they differ
            long xor = l1 ^ l2;
            int prefix = 32;
            
            for (int i = 31; i >= 0; i--) {
                if ((xor & (1L << i)) != 0) {
                    prefix = 31 - i;
                    break;
                }
            }
            
            long mask = prefixToMask(prefix);
            long network = l1 & mask;
            
            return longToIp(network) + "/" + prefix;
        } catch (Exception e) {
            Log.w(TAG, "Failed to calculate containing subnet", e);
            return null;
        }
    }
    
    /**
     * Increment IP address by 1.
     */
    @NonNull
    public static String incrementIp(@NonNull String ip) {
        return longToIp(ipToLong(ip) + 1);
    }
    
    /**
     * Decrement IP address by 1.
     */
    @NonNull
    public static String decrementIp(@NonNull String ip) {
        return longToIp(ipToLong(ip) - 1);
    }
}
