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
import org.csploit.android.helpers.LoggingHelper;
import androidx.annotation.Nullable;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Helper class for IP address manipulation and validation.
 * Provides utilities for IPv4 address operations.
 */
public class IpAddressHelper {
    
    private static final String TAG = "IpAddressHelper";
    
    // IPv4 regex pattern
    private static final Pattern IPV4_PATTERN = Pattern.compile(
            "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}" +
            "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    );
    
    // Private IP address ranges
    private static final long[] PRIVATE_RANGES_START = {
            ipToLong("10.0.0.0"),
            ipToLong("172.16.0.0"),
            ipToLong("192.168.0.0")
    };
    
    private static final long[] PRIVATE_RANGES_END = {
            ipToLong("10.255.255.255"),
            ipToLong("172.31.255.255"),
            ipToLong("192.168.255.255")
    };
    
    /**
     * Check if a string is a valid IPv4 address.
     * 
     * @param ip IP address string
     * @return true if valid IPv4 address
     */
    public static boolean isValidIpv4(@Nullable String ip) {
        if (ip == null || ip.isEmpty()) {
            return false;
        }
        return IPV4_PATTERN.matcher(ip).matches();
    }
    
    /**
     * Convert IP address string to long.
     * 
     * @param ip IPv4 address string
     * @return Long representation of IP address, or -1 if invalid
     */
    public static long ipToLong(@Nullable String ip) {
        if (!isValidIpv4(ip)) {
            return -1;
        }
        
        String[] octets = ip.split("\\.");
        long result = 0;
        for (int i = 0; i < 4; i++) {
            result = (result << 8) | Integer.parseInt(octets[i]);
        }
        return result;
    }
    
    /**
     * Convert long to IP address string.
     * 
     * @param ip Long representation of IP
     * @return IPv4 address string
     */
    @NonNull
    public static String longToIp(long ip) {
        return ((ip >> 24) & 0xFF) + "." +
               ((ip >> 16) & 0xFF) + "." +
               ((ip >> 8) & 0xFF) + "." +
               (ip & 0xFF);
    }
    
    /**
     * Convert IP address to byte array.
     * 
     * @param ip IPv4 address string
     * @return Byte array representation, or null if invalid
     */
    @Nullable
    public static byte[] ipToBytes(@Nullable String ip) {
        if (!isValidIpv4(ip)) {
            return null;
        }
        
        String[] octets = ip.split("\\.");
        byte[] result = new byte[4];
        for (int i = 0; i < 4; i++) {
            result[i] = (byte) Integer.parseInt(octets[i]);
        }
        return result;
    }
    
    /**
     * Convert byte array to IP address string.
     * 
     * @param bytes Byte array (must be length 4)
     * @return IPv4 address string, or null if invalid
     */
    @Nullable
    public static String bytesToIp(@Nullable byte[] bytes) {
        if (bytes == null || bytes.length != 4) {
            return null;
        }
        
        return (bytes[0] & 0xFF) + "." +
               (bytes[1] & 0xFF) + "." +
               (bytes[2] & 0xFF) + "." +
               (bytes[3] & 0xFF);
    }
    
    /**
     * Check if an IP address is in a private range.
     * 
     * @param ip IPv4 address string
     * @return true if private address
     */
    public static boolean isPrivateIp(@Nullable String ip) {
        long ipLong = ipToLong(ip);
        if (ipLong < 0) {
            return false;
        }
        
        for (int i = 0; i < PRIVATE_RANGES_START.length; i++) {
            if (ipLong >= PRIVATE_RANGES_START[i] && ipLong <= PRIVATE_RANGES_END[i]) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Check if an IP address is localhost.
     * 
     * @param ip IPv4 address string
     * @return true if localhost
     */
    public static boolean isLocalhost(@Nullable String ip) {
        if (ip == null) return false;
        return ip.equals("127.0.0.1") || ip.equals("localhost") || ip.startsWith("127.");
    }
    
    /**
     * Check if an IP address is a broadcast address.
     * 
     * @param ip IPv4 address string
     * @return true if broadcast address
     */
    public static boolean isBroadcast(@Nullable String ip) {
        if (ip == null) return false;
        return ip.equals("255.255.255.255") || ip.endsWith(".255");
    }
    
    /**
     * Calculate the network address from IP and subnet mask.
     * 
     * @param ip IPv4 address string
     * @param mask Subnet mask string
     * @return Network address string
     */
    @Nullable
    public static String getNetworkAddress(@Nullable String ip, @Nullable String mask) {
        long ipLong = ipToLong(ip);
        long maskLong = ipToLong(mask);
        
        if (ipLong < 0 || maskLong < 0) {
            return null;
        }
        
        return longToIp(ipLong & maskLong);
    }
    
    /**
     * Calculate the broadcast address from IP and subnet mask.
     * 
     * @param ip IPv4 address string
     * @param mask Subnet mask string
     * @return Broadcast address string
     */
    @Nullable
    public static String getBroadcastAddress(@Nullable String ip, @Nullable String mask) {
        long ipLong = ipToLong(ip);
        long maskLong = ipToLong(mask);
        
        if (ipLong < 0 || maskLong < 0) {
            return null;
        }
        
        long inverseMask = ~maskLong & 0xFFFFFFFFL;
        return longToIp((ipLong & maskLong) | inverseMask);
    }
    
    /**
     * Convert CIDR prefix length to subnet mask.
     * 
     * @param cidr CIDR prefix length (0-32)
     * @return Subnet mask string
     */
    @NonNull
    public static String cidrToMask(int cidr) {
        if (cidr < 0) cidr = 0;
        if (cidr > 32) cidr = 32;
        
        long mask = cidr == 0 ? 0 : 0xFFFFFFFFL << (32 - cidr);
        return longToIp(mask);
    }
    
    /**
     * Convert subnet mask to CIDR prefix length.
     * 
     * @param mask Subnet mask string
     * @return CIDR prefix length, or -1 if invalid
     */
    public static int maskToCidr(@Nullable String mask) {
        long maskLong = ipToLong(mask);
        if (maskLong < 0) {
            return -1;
        }
        
        int cidr = 0;
        while ((maskLong & 0x80000000L) != 0) {
            cidr++;
            maskLong <<= 1;
        }
        return cidr;
    }
    
    /**
     * Get the number of hosts in a subnet.
     * 
     * @param cidr CIDR prefix length
     * @return Number of usable host addresses
     */
    public static long getHostCount(int cidr) {
        if (cidr >= 31) return 0;
        return (1L << (32 - cidr)) - 2;
    }
    
    /**
     * Check if two IP addresses are in the same subnet.
     * 
     * @param ip1 First IP address
     * @param ip2 Second IP address
     * @param mask Subnet mask
     * @return true if same subnet
     */
    public static boolean isSameSubnet(@Nullable String ip1, @Nullable String ip2, 
                                       @Nullable String mask) {
        String net1 = getNetworkAddress(ip1, mask);
        String net2 = getNetworkAddress(ip2, mask);
        
        if (net1 == null || net2 == null) {
            return false;
        }
        
        return net1.equals(net2);
    }
    
    /**
     * Get all local IP addresses.
     * 
     * @return List of local IP addresses
     */
    @NonNull
    public static List<String> getLocalIpAddresses() {
        List<String> addresses = new ArrayList<>();
        
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            if (interfaces == null) return addresses;
            
            for (NetworkInterface netInterface : Collections.list(interfaces)) {
                if (netInterface.isLoopback() || !netInterface.isUp()) {
                    continue;
                }
                
                Enumeration<InetAddress> inetAddresses = netInterface.getInetAddresses();
                for (InetAddress addr : Collections.list(inetAddresses)) {
                    if (addr instanceof Inet4Address) {
                        addresses.add(addr.getHostAddress());
                    }
                }
            }
        } catch (SocketException e) {
            LoggingHelper.e(TAG, "Error getting local IP addresses", e);
        }
        
        return addresses;
    }
    
    /**
     * Resolve hostname to IP address.
     * 
     * @param hostname Hostname to resolve
     * @return IP address string, or null if resolution fails
     */
    @Nullable
    public static String resolveHostname(@NonNull String hostname) {
        try {
            InetAddress address = InetAddress.getByName(hostname);
            return address.getHostAddress();
        } catch (UnknownHostException e) {
            LoggingHelper.w(TAG, "Failed to resolve hostname: " + hostname);
            return null;
        }
    }
    
    /**
     * Reverse DNS lookup - get hostname from IP.
     * 
     * @param ip IP address
     * @return Hostname, or IP if lookup fails
     */
    @NonNull
    public static String getHostname(@NonNull String ip) {
        try {
            InetAddress address = InetAddress.getByName(ip);
            String hostname = address.getCanonicalHostName();
            // Returns IP if no hostname found
            return hostname.equals(ip) ? ip : hostname;
        } catch (UnknownHostException e) {
            return ip;
        }
    }
    
    /**
     * Increment an IP address by one.
     * 
     * @param ip IPv4 address string
     * @return Next IP address
     */
    @Nullable
    public static String incrementIp(@Nullable String ip) {
        long ipLong = ipToLong(ip);
        if (ipLong < 0 || ipLong >= 0xFFFFFFFFL) {
            return null;
        }
        return longToIp(ipLong + 1);
    }
    
    /**
     * Decrement an IP address by one.
     * 
     * @param ip IPv4 address string
     * @return Previous IP address
     */
    @Nullable
    public static String decrementIp(@Nullable String ip) {
        long ipLong = ipToLong(ip);
        if (ipLong <= 0) {
            return null;
        }
        return longToIp(ipLong - 1);
    }
    
    private IpAddressHelper() {
        // Prevent instantiation
    }
}
