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
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * ArpHelper - ARP table utilities and operations.
 * 
 * Provides:
 * - ARP table reading
 * - IP to MAC resolution
 * - ARP cache management
 * - Network neighbor discovery
 * 
 * Usage:
 * {@code
 * // Get ARP table
 * List<ArpEntry> entries = ArpHelper.getArpTable();
 * 
 * // Get MAC for IP
 * String mac = ArpHelper.getMacForIp("192.168.1.1");
 * 
 * // Check if IP is in ARP cache
 * boolean cached = ArpHelper.isInArpCache("192.168.1.1");
 * }
 */
public final class ArpHelper {
    
    private static final String TAG = "ArpHelper";
    
    private static final String ARP_TABLE_PATH = "/proc/net/arp";
    
    // ARP entry pattern: IP, HW type, Flags, HW address, Mask, Device
    private static final Pattern ARP_PATTERN = Pattern.compile(
            "^(\\d+\\.\\d+\\.\\d+\\.\\d+)\\s+" +    // IP address
            "0x([0-9a-fA-F]+)\\s+" +                  // Hardware type
            "0x([0-9a-fA-F]+)\\s+" +                  // Flags
            "([0-9a-fA-F:]+)\\s+" +                   // MAC address
            "\\*?\\s+" +                              // Mask
            "(\\S+)");                                // Device
    
    /**
     * ARP entry representation.
     */
    public static class ArpEntry {
        public final String ipAddress;
        public final String macAddress;
        public final int hwType;
        public final int flags;
        public final String device;
        public final long timestamp;
        
        public ArpEntry(String ip, String mac, int hwType, int flags, String device) {
            this.ipAddress = ip;
            this.macAddress = mac.toUpperCase();
            this.hwType = hwType;
            this.flags = flags;
            this.device = device;
            this.timestamp = java.lang.System.currentTimeMillis();
        }
        
        /**
         * Check if entry is complete (has valid MAC).
         */
        public boolean isComplete() {
            return (flags & 0x02) != 0;
        }
        
        /**
         * Check if entry is permanent.
         */
        public boolean isPermanent() {
            return (flags & 0x04) != 0;
        }
        
        /**
         * Check if entry is published (proxy ARP).
         */
        public boolean isPublished() {
            return (flags & 0x08) != 0;
        }
        
        /**
         * Check if MAC is valid (not all zeros).
         */
        public boolean hasValidMac() {
            return macAddress != null && 
                   !macAddress.isEmpty() && 
                   !macAddress.equals("00:00:00:00:00:00");
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("ArpEntry{ip=%s, mac=%s, device=%s, complete=%b}",
                    ipAddress, macAddress, device, isComplete());
        }
    }
    
    private ArpHelper() {}
    
    /**
     * Get entire ARP table.
     * 
     * @return list of ARP entries
     */
    @NonNull
    public static List<ArpEntry> getArpTable() {
        List<ArpEntry> entries = new ArrayList<>();
        
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(new java.io.FileInputStream(ARP_TABLE_PATH)))) {
            
            String line;
            boolean firstLine = true;
            
            while ((line = reader.readLine()) != null) {
                // Skip header line
                if (firstLine) {
                    firstLine = false;
                    continue;
                }
                
                ArpEntry entry = parseArpLine(line);
                if (entry != null) {
                    entries.add(entry);
                }
            }
        } catch (IOException e) {
            Log.w(TAG, "Failed to read ARP table: " + e.getMessage());
        }
        
        return entries;
    }
    
    /**
     * Get ARP entries filtered by device.
     * 
     * @param device network device name (e.g., "wlan0")
     * @return filtered ARP entries
     */
    @NonNull
    public static List<ArpEntry> getArpTableForDevice(@NonNull String device) {
        List<ArpEntry> all = getArpTable();
        List<ArpEntry> filtered = new ArrayList<>();
        
        for (ArpEntry entry : all) {
            if (device.equals(entry.device)) {
                filtered.add(entry);
            }
        }
        
        return filtered;
    }
    
    /**
     * Get MAC address for an IP from ARP cache.
     * 
     * @param ip IP address
     * @return MAC address or null if not found
     */
    @Nullable
    public static String getMacForIp(@NonNull String ip) {
        List<ArpEntry> entries = getArpTable();
        
        for (ArpEntry entry : entries) {
            if (ip.equals(entry.ipAddress) && entry.hasValidMac()) {
                return entry.macAddress;
            }
        }
        
        return null;
    }
    
    /**
     * Get IP address for a MAC from ARP cache.
     * 
     * @param mac MAC address
     * @return IP address or null if not found
     */
    @Nullable
    public static String getIpForMac(@NonNull String mac) {
        String normalizedMac = mac.toUpperCase().replace("-", ":");
        List<ArpEntry> entries = getArpTable();
        
        for (ArpEntry entry : entries) {
            if (normalizedMac.equals(entry.macAddress)) {
                return entry.ipAddress;
            }
        }
        
        return null;
    }
    
    /**
     * Check if IP is in ARP cache.
     * 
     * @param ip IP address
     * @return true if in cache
     */
    public static boolean isInArpCache(@NonNull String ip) {
        return getMacForIp(ip) != null;
    }
    
    /**
     * Get map of IP to MAC from ARP table.
     * 
     * @return map of IP addresses to MAC addresses
     */
    @NonNull
    public static Map<String, String> getIpToMacMap() {
        Map<String, String> map = new HashMap<>();
        
        for (ArpEntry entry : getArpTable()) {
            if (entry.hasValidMac()) {
                map.put(entry.ipAddress, entry.macAddress);
            }
        }
        
        return map;
    }
    
    /**
     * Get count of entries in ARP table.
     */
    public static int getArpEntryCount() {
        return getArpTable().size();
    }
    
    /**
     * Get only complete (valid) ARP entries.
     */
    @NonNull
    public static List<ArpEntry> getCompleteEntries() {
        List<ArpEntry> all = getArpTable();
        List<ArpEntry> complete = new ArrayList<>();
        
        for (ArpEntry entry : all) {
            if (entry.isComplete() && entry.hasValidMac()) {
                complete.add(entry);
            }
        }
        
        return complete;
    }
    
    /**
     * Parse a single line from ARP table.
     */
    @Nullable
    private static ArpEntry parseArpLine(String line) {
        if (line == null || line.isEmpty()) {
            return null;
        }
        
        Matcher matcher = ARP_PATTERN.matcher(line.trim());
        if (!matcher.find()) {
            return null;
        }
        
        try {
            String ip = matcher.group(1);
            int hwType = Integer.parseInt(matcher.group(2), 16);
            int flags = Integer.parseInt(matcher.group(3), 16);
            String mac = matcher.group(4);
            String device = matcher.group(5);
            
            return new ArpEntry(ip, mac, hwType, flags, device);
        } catch (Exception e) {
            Log.w(TAG, "Failed to parse ARP line: " + line, e);
            return null;
        }
    }
    
    /**
     * Trigger ARP resolution for an IP by pinging it.
     * This is a best-effort method to populate the ARP cache.
     * 
     * @param ip IP address to resolve
     * @return true if ping was sent successfully
     */
    public static boolean triggerArpResolution(@NonNull String ip) {
        try {
            ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", "-W", "1", ip);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            // Read output to prevent blocking
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
            while (reader.readLine() != null) {
                // Consume output
            }
            
            int exitCode = process.waitFor();
            return exitCode == 0;
        } catch (Exception e) {
            Log.w(TAG, "Failed to trigger ARP resolution for " + ip, e);
            return false;
        }
    }
    
    /**
     * Clear the ARP cache entry for an IP.
     * Requires root privileges.
     * 
     * @param ip IP address to clear
     * @return true if command was executed
     */
    public static boolean clearArpEntry(@NonNull String ip) {
        try {
            ProcessBuilder pb = new ProcessBuilder("ip", "neigh", "del", ip, "dev", "wlan0");
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
            while (reader.readLine() != null) {
                // Consume output
            }
            
            return process.waitFor() == 0;
        } catch (Exception e) {
            Log.w(TAG, "Failed to clear ARP entry for " + ip, e);
            return false;
        }
    }
}
