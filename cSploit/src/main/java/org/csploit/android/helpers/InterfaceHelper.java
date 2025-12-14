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

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * InterfaceHelper - Network interface management utilities.
 *
 * @deprecated Use {@link NetworkInterfaceHelper} instead, which provides better
 * integration with ShellHelper and more robust error handling. This class
 * remains for backwards compatibility but will be removed in a future release.
 *
 * Provides:
 * - Interface enumeration
 * - Interface configuration
 * - Statistics collection
 * - Wireless interface detection
 * - Interface state management
 *
 * Usage:
 * {@code
 * // List interfaces
 * List<InterfaceInfo> interfaces = InterfaceHelper.listInterfaces();
 *
 * // Get interface details
 * InterfaceInfo eth0 = InterfaceHelper.getInterface("eth0");
 *
 * // Get wireless interfaces
 * List<InterfaceInfo> wifi = InterfaceHelper.getWirelessInterfaces();
 * }
 *
 * @see NetworkInterfaceHelper
 */
@Deprecated
public final class InterfaceHelper {
    
    private static final String TAG = "InterfaceHelper";
    
    /**
     * Interface types.
     */
    public enum InterfaceType {
        ETHERNET,
        WIFI,
        LOOPBACK,
        BRIDGE,
        VIRTUAL,
        TUNNEL,
        BLUETOOTH,
        CELLULAR,
        USB,
        UNKNOWN
    }
    
    /**
     * Interface state.
     */
    public enum InterfaceState {
        UP,
        DOWN,
        UNKNOWN
    }
    
    /**
     * Interface information.
     */
    public static class InterfaceInfo {
        public String name;
        public InterfaceType type;
        public InterfaceState state;
        public String macAddress;
        public String ipv4Address;
        public String ipv4Netmask;
        public String ipv4Broadcast;
        public String ipv6Address;
        public int mtu;
        public boolean isUp;
        public boolean isRunning;
        public boolean isLoopback;
        public boolean isBroadcast;
        public boolean isMulticast;
        public boolean isPointToPoint;
        public long rxBytes;
        public long txBytes;
        public long rxPackets;
        public long txPackets;
        public long rxErrors;
        public long txErrors;
        public long rxDropped;
        public long txDropped;
        
        @NonNull
        @Override
        public String toString() {
            return String.format("Interface{name='%s', type=%s, state=%s, ip=%s, mac=%s}",
                    name, type, state, ipv4Address, macAddress);
        }
    }
    
    private InterfaceHelper() {}
    
    /**
     * List all network interfaces.
     */
    @NonNull
    public static List<InterfaceInfo> listInterfaces() {
        List<InterfaceInfo> interfaces = new ArrayList<>();
        
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"ip", "link", "show"});
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
            String line;
            InterfaceInfo current = null;
            
            Pattern namePattern = Pattern.compile("^\\d+:\\s+(\\S+):");
            Pattern macPattern = Pattern.compile("link/ether\\s+([0-9a-fA-F:]+)");
            Pattern statePattern = Pattern.compile("state\\s+(\\S+)");
            Pattern mtuPattern = Pattern.compile("mtu\\s+(\\d+)");
            
            while ((line = reader.readLine()) != null) {
                Matcher nameMatcher = namePattern.matcher(line);
                if (nameMatcher.find()) {
                    if (current != null) {
                        interfaces.add(current);
                    }
                    current = new InterfaceInfo();
                    current.name = nameMatcher.group(1).replace("@.*", "");
                    current.type = detectType(current.name);
                    
                    // Parse flags
                    current.isUp = line.contains("<") && line.contains("UP");
                    current.isRunning = line.contains("LOWER_UP");
                    current.isLoopback = line.contains("LOOPBACK");
                    current.isBroadcast = line.contains("BROADCAST");
                    current.isMulticast = line.contains("MULTICAST");
                    current.isPointToPoint = line.contains("POINTOPOINT");
                    
                    Matcher mtuMatcher = mtuPattern.matcher(line);
                    if (mtuMatcher.find()) {
                        current.mtu = Integer.parseInt(mtuMatcher.group(1));
                    }
                    
                    Matcher stateMatcher = statePattern.matcher(line);
                    if (stateMatcher.find()) {
                        String stateStr = stateMatcher.group(1);
                        if ("UP".equals(stateStr)) {
                            current.state = InterfaceState.UP;
                        } else if ("DOWN".equals(stateStr)) {
                            current.state = InterfaceState.DOWN;
                        } else {
                            current.state = InterfaceState.UNKNOWN;
                        }
                    }
                }
                
                if (current != null) {
                    Matcher macMatcher = macPattern.matcher(line);
                    if (macMatcher.find()) {
                        current.macAddress = macMatcher.group(1).toLowerCase();
                    }
                }
            }
            
            if (current != null) {
                interfaces.add(current);
            }
            
            process.waitFor();
            
            // Get IP addresses
            for (InterfaceInfo iface : interfaces) {
                getInterfaceAddresses(iface);
                getInterfaceStatistics(iface);
            }
            
        } catch (Exception e) {
            Log.e(TAG, "Failed to list interfaces", e);
        }
        
        return interfaces;
    }
    
    /**
     * Get interface by name.
     */
    @Nullable
    public static InterfaceInfo getInterface(@NonNull String name) {
        for (InterfaceInfo iface : listInterfaces()) {
            if (iface.name.equals(name)) {
                return iface;
            }
        }
        return null;
    }
    
    /**
     * Get IP addresses for interface.
     */
    private static void getInterfaceAddresses(@NonNull InterfaceInfo iface) {
        try {
            Process process = Runtime.getRuntime().exec(new String[]{
                    "ip", "addr", "show", "dev", iface.name
            });
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
            String line;
            
            Pattern inet4Pattern = Pattern.compile("inet\\s+([0-9.]+)/?(\\d*)");
            Pattern inet6Pattern = Pattern.compile("inet6\\s+([0-9a-fA-F:]+)");
            Pattern brdPattern = Pattern.compile("brd\\s+([0-9.]+)");
            
            while ((line = reader.readLine()) != null) {
                Matcher inet4Matcher = inet4Pattern.matcher(line);
                if (inet4Matcher.find() && iface.ipv4Address == null) {
                    iface.ipv4Address = inet4Matcher.group(1);
                    if (inet4Matcher.group(2) != null && !inet4Matcher.group(2).isEmpty()) {
                        int prefix = Integer.parseInt(inet4Matcher.group(2));
                        iface.ipv4Netmask = prefixToNetmask(prefix);
                    }
                    
                    Matcher brdMatcher = brdPattern.matcher(line);
                    if (brdMatcher.find()) {
                        iface.ipv4Broadcast = brdMatcher.group(1);
                    }
                }
                
                Matcher inet6Matcher = inet6Pattern.matcher(line);
                if (inet6Matcher.find() && iface.ipv6Address == null) {
                    String addr = inet6Matcher.group(1);
                    if (!addr.startsWith("fe80")) { // Skip link-local
                        iface.ipv6Address = addr;
                    }
                }
            }
            
            process.waitFor();
        } catch (Exception e) {
            Log.w(TAG, "Failed to get addresses for: " + iface.name, e);
        }
    }
    
    /**
     * Get interface statistics.
     */
    private static void getInterfaceStatistics(@NonNull InterfaceInfo iface) {
        try {
            // Read from /sys/class/net/{iface}/statistics/
            String basePath = "/sys/class/net/" + iface.name + "/statistics/";
            
            iface.rxBytes = readLongFromFile(basePath + "rx_bytes");
            iface.txBytes = readLongFromFile(basePath + "tx_bytes");
            iface.rxPackets = readLongFromFile(basePath + "rx_packets");
            iface.txPackets = readLongFromFile(basePath + "tx_packets");
            iface.rxErrors = readLongFromFile(basePath + "rx_errors");
            iface.txErrors = readLongFromFile(basePath + "tx_errors");
            iface.rxDropped = readLongFromFile(basePath + "rx_dropped");
            iface.txDropped = readLongFromFile(basePath + "tx_dropped");
        } catch (Exception e) {
            Log.w(TAG, "Failed to get statistics for: " + iface.name, e);
        }
    }
    
    /**
     * Read long value from file.
     */
    private static long readLongFromFile(String path) {
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"cat", path});
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
            String line = reader.readLine();
            process.waitFor();
            return line != null ? Long.parseLong(line.trim()) : 0;
        } catch (Exception e) {
            return 0;
        }
    }
    
    /**
     * Detect interface type from name.
     */
    @NonNull
    private static InterfaceType detectType(@NonNull String name) {
        if (name.equals("lo") || name.startsWith("lo:")) {
            return InterfaceType.LOOPBACK;
        }
        if (name.startsWith("eth") || name.startsWith("en")) {
            return InterfaceType.ETHERNET;
        }
        if (name.startsWith("wlan") || name.startsWith("wl")) {
            return InterfaceType.WIFI;
        }
        if (name.startsWith("br")) {
            return InterfaceType.BRIDGE;
        }
        if (name.startsWith("tun") || name.startsWith("tap")) {
            return InterfaceType.TUNNEL;
        }
        if (name.startsWith("bt") || name.startsWith("bnep")) {
            return InterfaceType.BLUETOOTH;
        }
        if (name.startsWith("rmnet") || name.startsWith("ccmni")) {
            return InterfaceType.CELLULAR;
        }
        if (name.startsWith("usb") || name.startsWith("rndis")) {
            return InterfaceType.USB;
        }
        if (name.startsWith("veth") || name.startsWith("docker") || name.startsWith("vir")) {
            return InterfaceType.VIRTUAL;
        }
        return InterfaceType.UNKNOWN;
    }
    
    /**
     * Get wireless interfaces only.
     */
    @NonNull
    public static List<InterfaceInfo> getWirelessInterfaces() {
        List<InterfaceInfo> wireless = new ArrayList<>();
        for (InterfaceInfo iface : listInterfaces()) {
            if (iface.type == InterfaceType.WIFI) {
                wireless.add(iface);
            }
        }
        return wireless;
    }
    
    /**
     * Get first active interface with IP.
     */
    @Nullable
    public static InterfaceInfo getActiveInterface() {
        for (InterfaceInfo iface : listInterfaces()) {
            if (iface.isUp && iface.ipv4Address != null && !iface.isLoopback) {
                return iface;
            }
        }
        return null;
    }
    
    /**
     * Get default gateway interface.
     */
    @Nullable
    public static InterfaceInfo getDefaultGatewayInterface() {
        try {
            Process process = Runtime.getRuntime().exec(new String[]{
                    "ip", "route", "show", "default"
            });
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
            String line = reader.readLine();
            process.waitFor();
            
            if (line != null) {
                Pattern devPattern = Pattern.compile("dev\\s+(\\S+)");
                Matcher matcher = devPattern.matcher(line);
                if (matcher.find()) {
                    return getInterface(matcher.group(1));
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "Failed to get default gateway interface", e);
        }
        return null;
    }
    
    /**
     * Set interface up.
     */
    public static boolean setInterfaceUp(@NonNull String name) {
        return executeCommand("ip", "link", "set", name, "up");
    }
    
    /**
     * Set interface down.
     */
    public static boolean setInterfaceDown(@NonNull String name) {
        return executeCommand("ip", "link", "set", name, "down");
    }
    
    /**
     * Set interface IP address.
     */
    public static boolean setIpAddress(@NonNull String name, @NonNull String ip, int prefixLength) {
        return executeCommand("ip", "addr", "add", ip + "/" + prefixLength, "dev", name);
    }
    
    /**
     * Remove interface IP address.
     */
    public static boolean removeIpAddress(@NonNull String name, @NonNull String ip, int prefixLength) {
        return executeCommand("ip", "addr", "del", ip + "/" + prefixLength, "dev", name);
    }
    
    /**
     * Set interface MAC address.
     */
    public static boolean setMacAddress(@NonNull String name, @NonNull String mac) {
        // Interface must be down first
        if (!setInterfaceDown(name)) {
            return false;
        }
        
        boolean success = executeCommand("ip", "link", "set", name, "address", mac);
        
        // Bring interface back up
        setInterfaceUp(name);
        
        return success;
    }
    
    /**
     * Set interface MTU.
     */
    public static boolean setMtu(@NonNull String name, int mtu) {
        return executeCommand("ip", "link", "set", name, "mtu", String.valueOf(mtu));
    }
    
    /**
     * Execute command.
     */
    private static boolean executeCommand(String... args) {
        try {
            Process process = Runtime.getRuntime().exec(args);
            process.waitFor();
            return process.exitValue() == 0;
        } catch (Exception e) {
            Log.e(TAG, "Command failed: " + String.join(" ", args), e);
            return false;
        }
    }
    
    /**
     * Convert prefix length to netmask.
     */
    @NonNull
    private static String prefixToNetmask(int prefix) {
        int mask = 0xFFFFFFFF << (32 - prefix);
        return String.format("%d.%d.%d.%d",
                (mask >> 24) & 0xFF,
                (mask >> 16) & 0xFF,
                (mask >> 8) & 0xFF,
                mask & 0xFF);
    }
    
    /**
     * Get total network statistics.
     */
    @NonNull
    public static NetworkStats getTotalStats() {
        NetworkStats total = new NetworkStats();
        
        for (InterfaceInfo iface : listInterfaces()) {
            if (!iface.isLoopback) {
                total.rxBytes += iface.rxBytes;
                total.txBytes += iface.txBytes;
                total.rxPackets += iface.rxPackets;
                total.txPackets += iface.txPackets;
                total.rxErrors += iface.rxErrors;
                total.txErrors += iface.txErrors;
            }
        }
        
        return total;
    }
    
    /**
     * Network statistics.
     */
    public static class NetworkStats {
        public long rxBytes;
        public long txBytes;
        public long rxPackets;
        public long txPackets;
        public long rxErrors;
        public long txErrors;
        
        public long getTotalBytes() {
            return rxBytes + txBytes;
        }
        
        public long getTotalPackets() {
            return rxPackets + txPackets;
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("NetworkStats{rx=%dMB, tx=%dMB, packets=%d}",
                    rxBytes / (1024 * 1024), txBytes / (1024 * 1024), getTotalPackets());
        }
    }
}
