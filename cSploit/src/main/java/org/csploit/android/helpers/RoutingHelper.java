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
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * RoutingHelper - Network routing table utilities.
 * 
 * Provides:
 * - Routing table inspection
 * - Default gateway detection
 * - Route analysis
 * - Network interface routing
 * - Route metrics calculation
 * 
 * Usage:
 * {@code
 * // Get routing table
 * List<RouteEntry> routes = RoutingHelper.getRoutingTable();
 * 
 * // Get default gateway
 * String gateway = RoutingHelper.getDefaultGateway();
 * 
 * // Find route for destination
 * RouteEntry route = RoutingHelper.findRouteFor("8.8.8.8");
 * }
 */
public final class RoutingHelper {
    
    private static final String TAG = "RoutingHelper";
    
    // Cache for route lookups
    private static final ConcurrentHashMap<String, RouteEntry> routeCache = new ConcurrentHashMap<>();
    private static long lastCacheUpdate = 0;
    private static final long CACHE_TTL_MS = 30000; // 30 seconds
    
    /**
     * Route flags.
     */
    public enum RouteFlag {
        UP("U", "Route is up"),
        HOST("H", "Target is a host"),
        GATEWAY("G", "Use gateway"),
        REINSTATE("R", "Reinstate route for dynamic routing"),
        DYNAMIC("D", "Dynamically installed by routing daemon"),
        MODIFIED("M", "Modified from routing daemon"),
        REJECT("!", "Reject route");
        
        private final String flag;
        private final String description;
        
        RouteFlag(String flag, String description) {
            this.flag = flag;
            this.description = description;
        }
        
        public String getFlag() {
            return flag;
        }
        
        public String getDescription() {
            return description;
        }
        
        @Nullable
        public static RouteFlag fromFlag(String flag) {
            for (RouteFlag rf : values()) {
                if (rf.flag.equals(flag)) {
                    return rf;
                }
            }
            return null;
        }
    }
    
    /**
     * Routing table entry.
     */
    public static class RouteEntry {
        public String destination;
        public String gateway;
        public String netmask;
        public String interfaceName;
        public List<RouteFlag> flags;
        public int metric;
        public int refCount;
        public int useCount;
        public boolean isDefault;
        public boolean isHost;
        public boolean usesGateway;
        
        public RouteEntry() {
            flags = new ArrayList<>();
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("Route{dest=%s, gw=%s, mask=%s, if=%s, metric=%d}",
                    destination, gateway, netmask, interfaceName, metric);
        }
    }
    
    private RoutingHelper() {}
    
    /**
     * Get full routing table.
     */
    @NonNull
    public static List<RouteEntry> getRoutingTable() {
        List<RouteEntry> routes = new ArrayList<>();
        
        // Try /proc/net/route first
        routes = parseRouteFile();
        if (!routes.isEmpty()) {
            return routes;
        }
        
        // Fall back to ip route command
        routes = parseIpRouteCommand();
        
        return routes;
    }
    
    /**
     * Parse /proc/net/route file.
     */
    @NonNull
    private static List<RouteEntry> parseRouteFile() {
        List<RouteEntry> routes = new ArrayList<>();
        File routeFile = new File("/proc/net/route");
        
        if (!routeFile.exists() || !routeFile.canRead()) {
            return routes;
        }
        
        try (BufferedReader reader = new BufferedReader(new FileReader(routeFile))) {
            String line;
            boolean firstLine = true;
            
            while ((line = reader.readLine()) != null) {
                if (firstLine) {
                    firstLine = false;
                    continue; // Skip header
                }
                
                RouteEntry entry = parseRouteLine(line);
                if (entry != null) {
                    routes.add(entry);
                }
            }
        } catch (IOException e) {
            Log.e(TAG, "Failed to read routing table", e);
        }
        
        return routes;
    }
    
    /**
     * Parse a single route line from /proc/net/route.
     */
    @Nullable
    private static RouteEntry parseRouteLine(@NonNull String line) {
        try {
            String[] parts = line.trim().split("\\s+");
            if (parts.length < 8) {
                return null;
            }
            
            RouteEntry entry = new RouteEntry();
            entry.interfaceName = parts[0];
            entry.destination = hexToIp(parts[1]);
            entry.gateway = hexToIp(parts[2]);
            entry.netmask = hexToIp(parts[7]);
            
            // Parse flags
            int flagsInt = Integer.parseInt(parts[3], 16);
            entry.flags = parseFlags(flagsInt);
            entry.usesGateway = (flagsInt & 0x0002) != 0; // RTF_GATEWAY
            entry.isHost = (flagsInt & 0x0004) != 0;      // RTF_HOST
            
            entry.refCount = Integer.parseInt(parts[4]);
            entry.useCount = Integer.parseInt(parts[5]);
            entry.metric = Integer.parseInt(parts[6]);
            
            // Check if default route
            entry.isDefault = "0.0.0.0".equals(entry.destination);
            
            return entry;
        } catch (Exception e) {
            Log.w(TAG, "Failed to parse route line: " + line, e);
            return null;
        }
    }
    
    /**
     * Convert hex IP to dotted decimal.
     */
    @NonNull
    private static String hexToIp(@NonNull String hex) {
        try {
            long ip = Long.parseLong(hex, 16);
            // Little endian byte order
            return String.format("%d.%d.%d.%d",
                    ip & 0xFF,
                    (ip >> 8) & 0xFF,
                    (ip >> 16) & 0xFF,
                    (ip >> 24) & 0xFF);
        } catch (NumberFormatException e) {
            return "0.0.0.0";
        }
    }
    
    /**
     * Parse route flags integer to list.
     */
    @NonNull
    private static List<RouteFlag> parseFlags(int flags) {
        List<RouteFlag> result = new ArrayList<>();
        
        if ((flags & 0x0001) != 0) result.add(RouteFlag.UP);
        if ((flags & 0x0002) != 0) result.add(RouteFlag.GATEWAY);
        if ((flags & 0x0004) != 0) result.add(RouteFlag.HOST);
        if ((flags & 0x0010) != 0) result.add(RouteFlag.REINSTATE);
        if ((flags & 0x0100) != 0) result.add(RouteFlag.DYNAMIC);
        if ((flags & 0x0200) != 0) result.add(RouteFlag.MODIFIED);
        if ((flags & 0x0800) != 0) result.add(RouteFlag.REJECT);
        
        return result;
    }
    
    /**
     * Parse ip route command output.
     */
    @NonNull
    private static List<RouteEntry> parseIpRouteCommand() {
        List<RouteEntry> routes = new ArrayList<>();
        
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"ip", "route", "show"});
            BufferedReader reader = new BufferedReader(
                    new java.io.InputStreamReader(process.getInputStream()));
            String line;
            
            Pattern pattern = Pattern.compile(
                    "^(default|[0-9./]+)\\s+(?:via\\s+([0-9.]+)\\s+)?dev\\s+(\\S+)(?:.*metric\\s+(\\d+))?");
            
            while ((line = reader.readLine()) != null) {
                Matcher matcher = pattern.matcher(line);
                if (matcher.find()) {
                    RouteEntry entry = new RouteEntry();
                    
                    String dest = matcher.group(1);
                    if ("default".equals(dest)) {
                        entry.destination = "0.0.0.0";
                        entry.netmask = "0.0.0.0";
                        entry.isDefault = true;
                    } else if (dest.contains("/")) {
                        String[] parts = dest.split("/");
                        entry.destination = parts[0];
                        entry.netmask = cidrToNetmask(Integer.parseInt(parts[1]));
                    } else {
                        entry.destination = dest;
                        entry.netmask = "255.255.255.255";
                        entry.isHost = true;
                    }
                    
                    entry.gateway = matcher.group(2);
                    if (entry.gateway == null) {
                        entry.gateway = "0.0.0.0";
                    } else {
                        entry.usesGateway = true;
                    }
                    
                    entry.interfaceName = matcher.group(3);
                    
                    String metricStr = matcher.group(4);
                    entry.metric = metricStr != null ? Integer.parseInt(metricStr) : 0;
                    
                    entry.flags.add(RouteFlag.UP);
                    if (entry.usesGateway) entry.flags.add(RouteFlag.GATEWAY);
                    if (entry.isHost) entry.flags.add(RouteFlag.HOST);
                    
                    routes.add(entry);
                }
            }
            
            process.waitFor();
        } catch (Exception e) {
            Log.e(TAG, "Failed to parse ip route output", e);
        }
        
        return routes;
    }
    
    /**
     * Convert CIDR prefix to netmask.
     */
    @NonNull
    public static String cidrToNetmask(int cidr) {
        int mask = 0xFFFFFFFF << (32 - cidr);
        return String.format("%d.%d.%d.%d",
                (mask >> 24) & 0xFF,
                (mask >> 16) & 0xFF,
                (mask >> 8) & 0xFF,
                mask & 0xFF);
    }
    
    /**
     * Get default gateway IP.
     */
    @Nullable
    public static String getDefaultGateway() {
        for (RouteEntry route : getRoutingTable()) {
            if (route.isDefault && route.usesGateway) {
                return route.gateway;
            }
        }
        return null;
    }
    
    /**
     * Get default route interface.
     */
    @Nullable
    public static String getDefaultInterface() {
        for (RouteEntry route : getRoutingTable()) {
            if (route.isDefault) {
                return route.interfaceName;
            }
        }
        return null;
    }
    
    /**
     * Find route for a specific destination.
     */
    @Nullable
    public static RouteEntry findRouteFor(@NonNull String destination) {
        // Check cache
        if (java.lang.System.currentTimeMillis() - lastCacheUpdate < CACHE_TTL_MS) {
            RouteEntry cached = routeCache.get(destination);
            if (cached != null) {
                return cached;
            }
        }
        
        try {
            long destIp = ipToLong(destination);
            List<RouteEntry> routes = getRoutingTable();
            RouteEntry bestMatch = null;
            int bestPrefix = -1;
            
            for (RouteEntry route : routes) {
                long routeDest = ipToLong(route.destination);
                long routeMask = ipToLong(route.netmask);
                
                if ((destIp & routeMask) == (routeDest & routeMask)) {
                    int prefix = Long.bitCount(routeMask);
                    if (prefix > bestPrefix) {
                        bestPrefix = prefix;
                        bestMatch = route;
                    }
                }
            }
            
            // Update cache
            if (bestMatch != null) {
                routeCache.put(destination, bestMatch);
                lastCacheUpdate = java.lang.System.currentTimeMillis();
            }
            
            return bestMatch;
        } catch (Exception e) {
            Log.e(TAG, "Failed to find route for " + destination, e);
            return null;
        }
    }
    
    /**
     * Convert IP string to long.
     */
    private static long ipToLong(@NonNull String ip) {
        String[] parts = ip.split("\\.");
        long result = 0;
        for (String part : parts) {
            result = (result << 8) | Integer.parseInt(part);
        }
        return result;
    }
    
    /**
     * Get routes for a specific interface.
     */
    @NonNull
    public static List<RouteEntry> getRoutesForInterface(@NonNull String interfaceName) {
        List<RouteEntry> result = new ArrayList<>();
        for (RouteEntry route : getRoutingTable()) {
            if (interfaceName.equals(route.interfaceName)) {
                result.add(route);
            }
        }
        return result;
    }
    
    /**
     * Check if destination is routable.
     */
    public static boolean isRoutable(@NonNull String destination) {
        return findRouteFor(destination) != null;
    }
    
    /**
     * Get gateway for a specific destination.
     */
    @Nullable
    public static String getGatewayFor(@NonNull String destination) {
        RouteEntry route = findRouteFor(destination);
        if (route != null && route.usesGateway) {
            return route.gateway;
        }
        return null;
    }
    
    /**
     * Get interface for a specific destination.
     */
    @Nullable
    public static String getInterfaceFor(@NonNull String destination) {
        RouteEntry route = findRouteFor(destination);
        return route != null ? route.interfaceName : null;
    }
    
    /**
     * Clear route cache.
     */
    public static void clearCache() {
        routeCache.clear();
        lastCacheUpdate = 0;
    }
    
    /**
     * Get routing table summary.
     */
    @NonNull
    public static RoutingSummary getSummary() {
        RoutingSummary summary = new RoutingSummary();
        List<RouteEntry> routes = getRoutingTable();
        
        summary.totalRoutes = routes.size();
        
        for (RouteEntry route : routes) {
            if (route.isDefault) summary.defaultRoutes++;
            if (route.isHost) summary.hostRoutes++;
            if (route.usesGateway) summary.gatewayRoutes++;
            
            if (!summary.interfaces.contains(route.interfaceName)) {
                summary.interfaces.add(route.interfaceName);
            }
        }
        
        summary.defaultGateway = getDefaultGateway();
        summary.defaultInterface = getDefaultInterface();
        
        return summary;
    }
    
    /**
     * Routing table summary.
     */
    public static class RoutingSummary {
        public int totalRoutes;
        public int defaultRoutes;
        public int hostRoutes;
        public int gatewayRoutes;
        public List<String> interfaces = new ArrayList<>();
        public String defaultGateway;
        public String defaultInterface;
        
        @NonNull
        @Override
        public String toString() {
            return String.format("RoutingSummary{total=%d, default=%s via %s, interfaces=%d}",
                    totalRoutes, defaultGateway, defaultInterface, interfaces.size());
        }
    }
}
