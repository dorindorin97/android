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

import androidx.annotation.NonNull;
import org.csploit.android.helpers.LoggingHelper;
import androidx.annotation.Nullable;
import org.csploit.android.helpers.LoggingHelper;

import org.csploit.android.core.System;
import org.csploit.android.helpers.LoggingHelper;
import org.csploit.android.helpers.MacAddressHelper;
import org.csploit.android.helpers.LoggingHelper;
import org.csploit.android.net.Target;
import org.csploit.android.helpers.LoggingHelper;

import java.net.InetAddress;
import org.csploit.android.helpers.LoggingHelper;
import java.util.ArrayList;
import org.csploit.android.helpers.LoggingHelper;
import java.util.Collections;
import org.csploit.android.helpers.LoggingHelper;
import java.util.Comparator;
import org.csploit.android.helpers.LoggingHelper;
import java.util.List;
import org.csploit.android.helpers.LoggingHelper;

/**
 * TargetHelper - Utility class for target management and filtering.
 * 
 * Provides methods for:
 * - Filtering targets by type, state, or attributes
 * - Sorting targets by various criteria
 * - Target information extraction
 * - Bulk target operations
 * - Target validation
 * 
 * Usage:
 * {@code
 * // Get all endpoints with open ports
 * List<Target> withPorts = TargetHelper.getTargetsWithPorts(System.getTargets());
 * 
 * // Get target by IP
 * Target t = TargetHelper.findByIp(System.getTargets(), "192.168.1.1");
 * 
 * // Sort by IP address
 * List<Target> sorted = TargetHelper.sortByIp(targets);
 * }
 */
public final class TargetHelper {
    
    public static final String TAG = "TargetHelper";
    
    private TargetHelper() {}
    
    /**
     * Sorting criteria for targets.
     */
    public enum SortBy {
        IP_ADDRESS,
        HOSTNAME,
        MAC_ADDRESS,
        TYPE,
        PORT_COUNT
    }
    
    /**
     * Filter targets by type.
     * 
     * @param targets list of targets to filter
     * @param type target type to match
     * @return filtered list of targets
     */
    @NonNull
    public static List<Target> filterByType(@Nullable List<Target> targets, 
                                            @NonNull Target.Type type) {
        if (targets == null || targets.isEmpty()) {
            return new ArrayList<>();
        }
        
        List<Target> filtered = new ArrayList<>();
        for (Target target : targets) {
            if (target != null && target.getType() == type) {
                filtered.add(target);
            }
        }
        return filtered;
    }
    
    /**
     * Get only endpoint targets.
     * 
     * @param targets list of targets
     * @return list of endpoint targets
     */
    @NonNull
    public static List<Target> getEndpoints(@Nullable List<Target> targets) {
        return filterByType(targets, Target.Type.ENDPOINT);
    }
    
    /**
     * Get targets that have open ports.
     * 
     * @param targets list of targets
     * @return targets with at least one open port
     */
    @NonNull
    public static List<Target> getTargetsWithPorts(@Nullable List<Target> targets) {
        if (targets == null || targets.isEmpty()) {
            return new ArrayList<>();
        }
        
        List<Target> result = new ArrayList<>();
        for (Target target : targets) {
            if (target != null && target.hasOpenPorts()) {
                result.add(target);
            }
        }
        return result;
    }
    
    /**
     * Get targets that have a specific port open.
     * 
     * @param targets list of targets
     * @param port port number to check
     * @return targets with the specified port open
     */
    @NonNull
    public static List<Target> getTargetsWithPort(@Nullable List<Target> targets, int port) {
        if (targets == null || targets.isEmpty()) {
            return new ArrayList<>();
        }
        
        List<Target> result = new ArrayList<>();
        for (Target target : targets) {
            if (target != null && hasPort(target, port)) {
                result.add(target);
            }
        }
        return result;
    }
    
    /**
     * Check if a target has a specific port open.
     * 
     * @param target target to check
     * @param port port number
     * @return true if port is open
     */
    public static boolean hasPort(@Nullable Target target, int port) {
        if (target == null) {
            return false;
        }
        
        List<Target.Port> ports = target.getOpenPorts();
        if (ports == null) {
            return false;
        }
        
        for (Target.Port p : ports) {
            if (p.getNumber() == port) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Find target by IP address.
     * 
     * @param targets list of targets
     * @param ipAddress IP address to find
     * @return matching target or null
     */
    @Nullable
    public static Target findByIp(@Nullable List<Target> targets, @NonNull String ipAddress) {
        if (targets == null || targets.isEmpty()) {
            return null;
        }
        
        for (Target target : targets) {
            if (target != null) {
                InetAddress addr = target.getAddress();
                if (addr != null && ipAddress.equals(addr.getHostAddress())) {
                    return target;
                }
            }
        }
        return null;
    }
    
    /**
     * Find target by MAC address.
     * 
     * @param targets list of targets
     * @param macAddress MAC address to find (any format)
     * @return matching target or null
     */
    @Nullable
    public static Target findByMac(@Nullable List<Target> targets, @NonNull String macAddress) {
        if (targets == null || targets.isEmpty()) {
            return null;
        }
        
        String normalizedMac = MacAddressHelper.normalizeMac(macAddress);
        if (normalizedMac == null) {
            return null;
        }
        
        for (Target target : targets) {
            if (target != null) {
                String targetMac = target.getMacAddress();
                if (targetMac != null) {
                    String normalizedTargetMac = MacAddressHelper.normalizeMac(targetMac);
                    if (normalizedMac.equals(normalizedTargetMac)) {
                        return target;
                    }
                }
            }
        }
        return null;
    }
    
    /**
     * Find target by hostname.
     * 
     * @param targets list of targets
     * @param hostname hostname to find (case-insensitive)
     * @return matching target or null
     */
    @Nullable
    public static Target findByHostname(@Nullable List<Target> targets, @NonNull String hostname) {
        if (targets == null || targets.isEmpty()) {
            return null;
        }
        
        String lowerHostname = hostname.toLowerCase();
        for (Target target : targets) {
            if (target != null) {
                String targetHostname = target.getHostname();
                if (targetHostname != null && targetHostname.toLowerCase().equals(lowerHostname)) {
                    return target;
                }
            }
        }
        return null;
    }
    
    /**
     * Sort targets by IP address.
     * 
     * @param targets list of targets to sort
     * @return sorted list (original list is not modified)
     */
    @NonNull
    public static List<Target> sortByIp(@Nullable List<Target> targets) {
        return sort(targets, SortBy.IP_ADDRESS);
    }
    
    /**
     * Sort targets by criteria.
     * 
     * @param targets list of targets
     * @param sortBy sorting criteria
     * @return sorted list (original is not modified)
     */
    @NonNull
    public static List<Target> sort(@Nullable List<Target> targets, @NonNull SortBy sortBy) {
        if (targets == null || targets.isEmpty()) {
            return new ArrayList<>();
        }
        
        List<Target> sorted = new ArrayList<>(targets);
        Comparator<Target> comparator = getComparator(sortBy);
        Collections.sort(sorted, comparator);
        return sorted;
    }
    
    /**
     * Get comparator for sorting criteria.
     */
    @NonNull
    private static Comparator<Target> getComparator(@NonNull SortBy sortBy) {
        switch (sortBy) {
            case IP_ADDRESS:
                return new IpComparator();
            case HOSTNAME:
                return new HostnameComparator();
            case MAC_ADDRESS:
                return new MacComparator();
            case TYPE:
                return new TypeComparator();
            case PORT_COUNT:
                return new PortCountComparator();
            default:
                return new IpComparator();
        }
    }
    
    /**
     * Get display name for a target.
     * Returns hostname if available, otherwise IP address.
     * 
     * @param target target
     * @return display name
     */
    @NonNull
    public static String getDisplayName(@Nullable Target target) {
        if (target == null) {
            return "Unknown";
        }
        
        String hostname = target.getHostname();
        if (hostname != null && !hostname.isEmpty()) {
            return hostname;
        }
        
        InetAddress addr = target.getAddress();
        if (addr != null) {
            return addr.getHostAddress();
        }
        
        return "Unknown";
    }
    
    /**
     * Get summary info for a target.
     * 
     * @param target target
     * @return human-readable summary
     */
    @NonNull
    public static String getSummary(@Nullable Target target) {
        if (target == null) {
            return "No target";
        }
        
        StringBuilder sb = new StringBuilder();
        sb.append(getDisplayName(target));
        
        String mac = target.getMacAddress();
        if (mac != null && !mac.isEmpty()) {
            sb.append(" (").append(mac).append(")");
        }
        
        List<Target.Port> ports = target.getOpenPorts();
        if (ports != null && !ports.isEmpty()) {
            sb.append(" - ").append(ports.size()).append(" open port(s)");
        }
        
        return sb.toString();
    }
    
    /**
     * Get open port numbers as list.
     * 
     * @param target target
     * @return list of port numbers
     */
    @NonNull
    public static List<Integer> getOpenPortNumbers(@Nullable Target target) {
        List<Integer> result = new ArrayList<>();
        if (target == null) {
            return result;
        }
        
        List<Target.Port> ports = target.getOpenPorts();
        if (ports == null) {
            return result;
        }
        
        for (Target.Port port : ports) {
            result.add(port.getNumber());
        }
        Collections.sort(result);
        return result;
    }
    
    /**
     * Check if target is the gateway.
     * 
     * @param target target to check
     * @return true if target is the gateway
     */
    public static boolean isGateway(@Nullable Target target) {
        if (target == null) {
            return false;
        }
        
        try {
            Target gateway = System.getNetwork().getGateway();
            if (gateway == null) {
                return false;
            }
            
            InetAddress targetAddr = target.getAddress();
            InetAddress gatewayAddr = gateway.getAddress();
            
            if (targetAddr != null && gatewayAddr != null) {
                return targetAddr.equals(gatewayAddr);
            }
        } catch (Exception e) {
            LoggingHelper.w(TAG, "Error checking gateway: " + e.getMessage());
        }
        return false;
    }
    
    /**
     * Check if target is local device.
     * 
     * @param target target to check
     * @return true if target is local device
     */
    public static boolean isLocalDevice(@Nullable Target target) {
        if (target == null) {
            return false;
        }
        return target.getType() == Target.Type.NETWORK;
    }
    
    /**
     * Count targets by type.
     * 
     * @param targets list of targets
     * @return count of each type
     */
    @NonNull
    public static java.util.Map<Target.Type, Integer> countByType(@Nullable List<Target> targets) {
        java.util.Map<Target.Type, Integer> counts = new java.util.HashMap<>();
        
        for (Target.Type type : Target.Type.values()) {
            counts.put(type, 0);
        }
        
        if (targets == null) {
            return counts;
        }
        
        for (Target target : targets) {
            if (target != null) {
                Target.Type type = target.getType();
                counts.put(type, counts.get(type) + 1);
            }
        }
        
        return counts;
    }
    
    // Comparator implementations
    
    private static class IpComparator implements Comparator<Target> {
        @Override
        public int compare(Target t1, Target t2) {
            if (t1 == null && t2 == null) return 0;
            if (t1 == null) return -1;
            if (t2 == null) return 1;
            
            InetAddress a1 = t1.getAddress();
            InetAddress a2 = t2.getAddress();
            
            if (a1 == null && a2 == null) return 0;
            if (a1 == null) return -1;
            if (a2 == null) return 1;
            
            byte[] b1 = a1.getAddress();
            byte[] b2 = a2.getAddress();
            
            for (int i = 0; i < Math.min(b1.length, b2.length); i++) {
                int cmp = (b1[i] & 0xFF) - (b2[i] & 0xFF);
                if (cmp != 0) return cmp;
            }
            return b1.length - b2.length;
        }
    }
    
    private static class HostnameComparator implements Comparator<Target> {
        @Override
        public int compare(Target t1, Target t2) {
            if (t1 == null && t2 == null) return 0;
            if (t1 == null) return -1;
            if (t2 == null) return 1;
            
            String h1 = t1.getHostname();
            String h2 = t2.getHostname();
            
            if (h1 == null && h2 == null) return 0;
            if (h1 == null) return 1;
            if (h2 == null) return -1;
            
            return h1.compareToIgnoreCase(h2);
        }
    }
    
    private static class MacComparator implements Comparator<Target> {
        @Override
        public int compare(Target t1, Target t2) {
            if (t1 == null && t2 == null) return 0;
            if (t1 == null) return -1;
            if (t2 == null) return 1;
            
            String m1 = t1.getMacAddress();
            String m2 = t2.getMacAddress();
            
            if (m1 == null && m2 == null) return 0;
            if (m1 == null) return 1;
            if (m2 == null) return -1;
            
            return m1.compareToIgnoreCase(m2);
        }
    }
    
    private static class TypeComparator implements Comparator<Target> {
        @Override
        public int compare(Target t1, Target t2) {
            if (t1 == null && t2 == null) return 0;
            if (t1 == null) return -1;
            if (t2 == null) return 1;
            
            return t1.getType().ordinal() - t2.getType().ordinal();
        }
    }
    
    private static class PortCountComparator implements Comparator<Target> {
        @Override
        public int compare(Target t1, Target t2) {
            if (t1 == null && t2 == null) return 0;
            if (t1 == null) return -1;
            if (t2 == null) return 1;
            
            List<Target.Port> p1 = t1.getOpenPorts();
            List<Target.Port> p2 = t2.getOpenPorts();
            
            int c1 = p1 != null ? p1.size() : 0;
            int c2 = p2 != null ? p2.size() : 0;
            
            // Descending order (most ports first)
            return c2 - c1;
        }
    }
}
