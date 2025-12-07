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

import android.content.Context;
import android.net.TrafficStats;
import android.os.Build;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * NetworkInterfaceHelper - Utilities for network interface inspection and manipulation.
 * 
 * Provides methods for:
 * - Listing network interfaces
 * - Getting interface statistics
 * - Reading interface configuration
 * - Managing interface state (with root)
 */
public final class NetworkInterfaceHelper {
    
    /**
     * Tag for logging. Made public for external logging reference.
     */
    public static final String TAG = "NetworkInterfaceHelper";
    
    // Interface info patterns - made public for custom parsing needs
    /**
     * Pattern to extract IP address from ifconfig output.
     * Usage: Matcher m = IP_PATTERN.matcher(ifconfigOutput); if (m.find()) ip = m.group(1);
     */
    public static final Pattern IP_PATTERN = Pattern.compile("inet\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)");
    
    /**
     * Pattern to extract netmask from ifconfig output.
     */
    public static final Pattern NETMASK_PATTERN = Pattern.compile("netmask\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)");
    
    /**
     * Pattern to extract MAC address from ifconfig output.
     */
    public static final Pattern MAC_PATTERN = Pattern.compile("ether\\s+([0-9a-fA-F:]{17})");
    
    /**
     * Pattern to extract MTU from ifconfig output.
     */
    public static final Pattern MTU_PATTERN = Pattern.compile("mtu\\s+(\\d+)");
    
    private NetworkInterfaceHelper() {}
    
    /**
     * Network interface information.
     */
    public static class InterfaceInfo {
        public final String name;
        public final String ipAddress;
        public final String netmask;
        public final String macAddress;
        public final int mtu;
        public final boolean isUp;
        public final boolean isLoopback;
        public final boolean isWireless;
        public final long rxBytes;
        public final long txBytes;
        public final long rxPackets;
        public final long txPackets;
        
        public InterfaceInfo(String name, String ipAddress, String netmask, String macAddress,
                             int mtu, boolean isUp, boolean isLoopback, boolean isWireless,
                             long rxBytes, long txBytes, long rxPackets, long txPackets) {
            this.name = name;
            this.ipAddress = ipAddress;
            this.netmask = netmask;
            this.macAddress = macAddress;
            this.mtu = mtu;
            this.isUp = isUp;
            this.isLoopback = isLoopback;
            this.isWireless = isWireless;
            this.rxBytes = rxBytes;
            this.txBytes = txBytes;
            this.rxPackets = rxPackets;
            this.txPackets = txPackets;
        }
        
        @Override
        @NonNull
        public String toString() {
            return String.format("%s: %s/%s (%s) %s", 
                    name, ipAddress, netmask, macAddress, isUp ? "UP" : "DOWN");
        }
    }
    
    /**
     * Get list of all network interfaces.
     * 
     * @return List of interface names
     */
    @NonNull
    public static List<String> getInterfaceNames() {
        List<String> interfaces = new ArrayList<>();
        
        File netDir = new File("/sys/class/net");
        if (netDir.exists() && netDir.isDirectory()) {
            File[] files = netDir.listFiles();
            if (files != null) {
                for (File f : files) {
                    interfaces.add(f.getName());
                }
            }
        }
        
        Collections.sort(interfaces);
        return interfaces;
    }
    
    /**
     * Get list of non-loopback interfaces.
     * 
     * @return List of interface names
     */
    @NonNull
    public static List<String> getNonLoopbackInterfaces() {
        List<String> interfaces = new ArrayList<>();
        for (String name : getInterfaceNames()) {
            if (!name.equals("lo") && !name.startsWith("dummy")) {
                interfaces.add(name);
            }
        }
        return interfaces;
    }
    
    /**
     * Get list of wireless interfaces.
     * 
     * @return List of wireless interface names
     */
    @NonNull
    public static List<String> getWirelessInterfaces() {
        List<String> wireless = new ArrayList<>();
        for (String name : getInterfaceNames()) {
            if (isWirelessInterface(name)) {
                wireless.add(name);
            }
        }
        return wireless;
    }
    
    /**
     * Check if an interface is wireless.
     * 
     * @param interfaceName Interface name
     * @return true if wireless
     */
    public static boolean isWirelessInterface(@NonNull String interfaceName) {
        File wireless = new File("/sys/class/net/" + interfaceName + "/wireless");
        return wireless.exists();
    }
    
    /**
     * Check if an interface is up.
     * 
     * @param interfaceName Interface name
     * @return true if up
     */
    public static boolean isInterfaceUp(@NonNull String interfaceName) {
        String flags = readSysFile("/sys/class/net/" + interfaceName + "/flags");
        if (flags != null) {
            try {
                int flagValue = Integer.parseInt(flags.replace("0x", ""), 16);
                return (flagValue & 0x1) != 0; // IFF_UP
            } catch (NumberFormatException e) {
                // Ignore
            }
        }
        return false;
    }
    
    /**
     * Get interface information.
     * 
     * @param interfaceName Interface name
     * @return Interface info or null
     */
    @Nullable
    public static InterfaceInfo getInterfaceInfo(@NonNull String interfaceName) {
        // Get basic info from sysfs
        String basePath = "/sys/class/net/" + interfaceName;
        
        if (!new File(basePath).exists()) {
            return null;
        }
        
        // Read MAC address
        String mac = readSysFile(basePath + "/address");
        if (mac != null) {
            mac = mac.toUpperCase();
        }
        
        // Read MTU
        int mtu = 1500;
        String mtuStr = readSysFile(basePath + "/mtu");
        if (mtuStr != null) {
            try {
                mtu = Integer.parseInt(mtuStr);
            } catch (NumberFormatException e) {
                // Use default
            }
        }
        
        // Check interface state
        boolean isUp = isInterfaceUp(interfaceName);
        boolean isLoopback = interfaceName.equals("lo");
        boolean isWireless = isWirelessInterface(interfaceName);
        
        // Read statistics
        long rxBytes = readLongSysFile(basePath + "/statistics/rx_bytes");
        long txBytes = readLongSysFile(basePath + "/statistics/tx_bytes");
        long rxPackets = readLongSysFile(basePath + "/statistics/rx_packets");
        long txPackets = readLongSysFile(basePath + "/statistics/tx_packets");
        
        // Get IP address using ip command
        String ipAddress = null;
        String netmask = null;
        
        ShellHelper.ShellResult result = ShellHelper.exec("ip addr show " + interfaceName);
        if (result.isSuccess()) {
            String output = result.getOutput();
            Matcher ipMatcher = IP_PATTERN.matcher(output);
            if (ipMatcher.find()) {
                ipAddress = ipMatcher.group(1);
            }
            
            // Parse CIDR notation for netmask
            Pattern cidrPattern = Pattern.compile("inet\\s+\\d+\\.\\d+\\.\\d+\\.\\d+/(\\d+)");
            Matcher cidrMatcher = cidrPattern.matcher(output);
            if (cidrMatcher.find()) {
                int prefix = Integer.parseInt(cidrMatcher.group(1));
                netmask = cidrToNetmask(prefix);
            }
        }
        
        return new InterfaceInfo(interfaceName, ipAddress, netmask, mac, mtu,
                isUp, isLoopback, isWireless, rxBytes, txBytes, rxPackets, txPackets);
    }
    
    /**
     * Get all interface information.
     * 
     * @return Map of interface name to info
     */
    @NonNull
    public static Map<String, InterfaceInfo> getAllInterfaceInfo() {
        Map<String, InterfaceInfo> result = new HashMap<>();
        for (String name : getInterfaceNames()) {
            InterfaceInfo info = getInterfaceInfo(name);
            if (info != null) {
                result.put(name, info);
            }
        }
        return result;
    }
    
    /**
     * Bring an interface up (requires root).
     * 
     * @param interfaceName Interface name
     * @return true if successful
     */
    public static boolean setInterfaceUp(@NonNull String interfaceName) {
        String safeName = InputSanitizer.sanitizeForShell(interfaceName);
        ShellHelper.ShellResult result = ShellHelper.execRoot("ip link set " + safeName + " up");
        return result.isSuccess();
    }
    
    /**
     * Bring an interface down (requires root).
     * 
     * @param interfaceName Interface name
     * @return true if successful
     */
    public static boolean setInterfaceDown(@NonNull String interfaceName) {
        String safeName = InputSanitizer.sanitizeForShell(interfaceName);
        ShellHelper.ShellResult result = ShellHelper.execRoot("ip link set " + safeName + " down");
        return result.isSuccess();
    }
    
    /**
     * Set interface IP address (requires root).
     * 
     * @param interfaceName Interface name
     * @param ipAddress IP address with CIDR (e.g., "192.168.1.100/24")
     * @return true if successful
     */
    public static boolean setInterfaceIp(@NonNull String interfaceName, @NonNull String ipAddress) {
        String safeName = InputSanitizer.sanitizeForShell(interfaceName);
        String safeIp = InputSanitizer.sanitizeForShell(ipAddress);
        
        // Flush existing addresses
        ShellHelper.execRoot("ip addr flush dev " + safeName);
        
        // Add new address
        ShellHelper.ShellResult result = ShellHelper.execRoot("ip addr add " + safeIp + " dev " + safeName);
        return result.isSuccess();
    }
    
    /**
     * Set interface MAC address (requires root, interface must be down).
     * 
     * @param interfaceName Interface name
     * @param macAddress MAC address
     * @return true if successful
     */
    public static boolean setInterfaceMac(@NonNull String interfaceName, @NonNull String macAddress) {
        if (!MacAddressHelper.isValidMac(macAddress)) {
            return false;
        }
        
        String safeName = InputSanitizer.sanitizeForShell(interfaceName);
        String safeMac = MacAddressHelper.format(macAddress, ':', false);
        
        // Must be down to change MAC
        setInterfaceDown(interfaceName);
        
        ShellHelper.ShellResult result = ShellHelper.execRoot("ip link set " + safeName + " address " + safeMac);
        boolean success = result.isSuccess();
        
        // Bring back up
        setInterfaceUp(interfaceName);
        
        return success;
    }
    
    /**
     * Enable promiscuous mode on an interface (requires root).
     * 
     * @param interfaceName Interface name
     * @return true if successful
     */
    public static boolean setPromiscuousMode(@NonNull String interfaceName, boolean enable) {
        String safeName = InputSanitizer.sanitizeForShell(interfaceName);
        String mode = enable ? "on" : "off";
        ShellHelper.ShellResult result = ShellHelper.execRoot("ip link set " + safeName + " promisc " + mode);
        return result.isSuccess();
    }
    
    /**
     * Get the default gateway IP.
     * 
     * @return Gateway IP or null
     */
    @Nullable
    public static String getDefaultGateway() {
        ShellHelper.ShellResult result = ShellHelper.exec("ip route show default");
        if (result.isSuccess()) {
            Pattern pattern = Pattern.compile("default via (\\d+\\.\\d+\\.\\d+\\.\\d+)");
            Matcher matcher = pattern.matcher(result.getOutput());
            if (matcher.find()) {
                return matcher.group(1);
            }
        }
        return null;
    }
    
    /**
     * Get the interface used for default route.
     * 
     * @return Interface name or null
     */
    @Nullable
    public static String getDefaultInterface() {
        ShellHelper.ShellResult result = ShellHelper.exec("ip route show default");
        if (result.isSuccess()) {
            Pattern pattern = Pattern.compile("dev\\s+(\\S+)");
            Matcher matcher = pattern.matcher(result.getOutput());
            if (matcher.find()) {
                return matcher.group(1);
            }
        }
        return null;
    }
    
    /**
     * Get DNS servers.
     * 
     * @return List of DNS server IPs
     */
    @NonNull
    public static List<String> getDnsServers() {
        List<String> servers = new ArrayList<>();
        
        // Try resolv.conf
        String content = ShellHelper.readFile("/etc/resolv.conf", false);
        if (content != null) {
            Pattern pattern = Pattern.compile("nameserver\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)");
            Matcher matcher = pattern.matcher(content);
            while (matcher.find()) {
                servers.add(matcher.group(1));
            }
        }
        
        // Try Android's getprop
        if (servers.isEmpty()) {
            for (int i = 1; i <= 4; i++) {
                ShellHelper.ShellResult result = ShellHelper.exec("getprop net.dns" + i);
                if (result.isSuccess()) {
                    String dns = result.getOutput().trim();
                    if (!dns.isEmpty() && IpAddressHelper.isValidIpv4(dns)) {
                        servers.add(dns);
                    }
                }
            }
        }
        
        return servers;
    }
    
    /**
     * Enable IP forwarding (requires root).
     * 
     * @return true if successful
     */
    public static boolean enableIpForwarding() {
        return ShellHelper.writeFile("/proc/sys/net/ipv4/ip_forward", "1", true);
    }
    
    /**
     * Disable IP forwarding (requires root).
     * 
     * @return true if successful
     */
    public static boolean disableIpForwarding() {
        return ShellHelper.writeFile("/proc/sys/net/ipv4/ip_forward", "0", true);
    }
    
    /**
     * Check if IP forwarding is enabled.
     * 
     * @return true if enabled
     */
    public static boolean isIpForwardingEnabled() {
        String content = ShellHelper.readFile("/proc/sys/net/ipv4/ip_forward", false);
        return content != null && content.trim().equals("1");
    }
    
    /**
     * Get ARP table entries.
     * 
     * @return Map of IP to MAC addresses
     */
    @NonNull
    public static Map<String, String> getArpTable() {
        Map<String, String> table = new HashMap<>();
        
        ShellHelper.ShellResult result = ShellHelper.exec("ip neigh show");
        if (result.isSuccess()) {
            Pattern pattern = Pattern.compile("(\\d+\\.\\d+\\.\\d+\\.\\d+).*lladdr\\s+([0-9a-fA-F:]{17})");
            for (String line : result.getOutputLines()) {
                Matcher matcher = pattern.matcher(line);
                if (matcher.find()) {
                    table.put(matcher.group(1), matcher.group(2).toUpperCase());
                }
            }
        }
        
        return table;
    }
    
    @Nullable
    private static String readSysFile(String path) {
        try (BufferedReader reader = new BufferedReader(new FileReader(path))) {
            return reader.readLine();
        } catch (IOException e) {
            return null;
        }
    }
    
    private static long readLongSysFile(String path) {
        String content = readSysFile(path);
        if (content != null) {
            try {
                return Long.parseLong(content.trim());
            } catch (NumberFormatException e) {
                // Ignore
            }
        }
        return 0;
    }
    
    @NonNull
    private static String cidrToNetmask(int prefix) {
        int mask = 0xFFFFFFFF << (32 - prefix);
        return String.format("%d.%d.%d.%d",
                (mask >> 24) & 0xFF,
                (mask >> 16) & 0xFF,
                (mask >> 8) & 0xFF,
                mask & 0xFF);
    }
}
