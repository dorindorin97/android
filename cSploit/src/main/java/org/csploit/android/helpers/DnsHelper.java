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
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * DnsHelper - DNS resolution and reverse lookup utilities.
 * 
 * Provides:
 * - Hostname resolution
 * - Reverse DNS lookup
 * - DNS caching
 * - Batch resolution
 * - Common DNS record lookups
 * 
 * Usage:
 * {@code
 * // Resolve hostname
 * String ip = DnsHelper.resolve("google.com");
 * 
 * // Reverse lookup
 * String hostname = DnsHelper.reverseLookup("8.8.8.8");
 * 
 * // Batch resolve
 * Map<String, String> results = DnsHelper.resolveBatch(hostnames);
 * }
 */
public final class DnsHelper {
    
    private static final String TAG = "DnsHelper";
    
    private static final int CACHE_SIZE = 500;
    private static final long CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
    private static final int DEFAULT_TIMEOUT_MS = 5000;
    
    private static final ConcurrentHashMap<String, CacheEntry> forwardCache = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, CacheEntry> reverseCache = new ConcurrentHashMap<>();
    private static final ExecutorService executor = Executors.newFixedThreadPool(4);
    
    /**
     * DNS record types.
     */
    public enum RecordType {
        A,      // IPv4 address
        AAAA,   // IPv6 address
        CNAME,  // Canonical name
        MX,     // Mail exchange
        NS,     // Name server
        PTR,    // Pointer (reverse)
        TXT,    // Text record
        SOA     // Start of authority
    }
    
    /**
     * Cache entry with TTL.
     */
    private static class CacheEntry {
        final String value;
        final long expiresAt;
        
        CacheEntry(String value, long ttlMs) {
            this.value = value;
            this.expiresAt = java.lang.System.currentTimeMillis() + ttlMs;
        }
        
        boolean isExpired() {
            return java.lang.System.currentTimeMillis() > expiresAt;
        }
    }
    
    private DnsHelper() {}
    
    /**
     * Resolve hostname to IP address.
     * 
     * @param hostname hostname to resolve
     * @return IP address or null if resolution failed
     */
    @Nullable
    public static String resolve(@NonNull String hostname) {
        // Check cache first
        CacheEntry cached = forwardCache.get(hostname);
        if (cached != null && !cached.isExpired()) {
            return cached.value;
        }
        
        try {
            InetAddress address = InetAddress.getByName(hostname);
            String ip = address.getHostAddress();
            
            // Cache result
            forwardCache.put(hostname, new CacheEntry(ip, CACHE_TTL_MS));
            cleanupCache(forwardCache);
            
            return ip;
        } catch (Exception e) {
            Log.w(TAG, "Failed to resolve: " + hostname, e);
            return null;
        }
    }
    
    /**
     * Resolve hostname asynchronously.
     */
    @NonNull
    public static Future<String> resolveAsync(@NonNull String hostname) {
        return executor.submit(() -> resolve(hostname));
    }
    
    /**
     * Reverse DNS lookup (IP to hostname).
     * 
     * @param ip IP address
     * @return hostname or null if lookup failed
     */
    @Nullable
    public static String reverseLookup(@NonNull String ip) {
        // Check cache first
        CacheEntry cached = reverseCache.get(ip);
        if (cached != null && !cached.isExpired()) {
            return cached.value;
        }
        
        try {
            InetAddress address = InetAddress.getByName(ip);
            String hostname = address.getCanonicalHostName();
            
            // If canonical name equals IP, lookup failed
            if (hostname.equals(ip)) {
                return null;
            }
            
            // Cache result
            reverseCache.put(ip, new CacheEntry(hostname, CACHE_TTL_MS));
            cleanupCache(reverseCache);
            
            return hostname;
        } catch (Exception e) {
            Log.w(TAG, "Reverse lookup failed for: " + ip, e);
            return null;
        }
    }
    
    /**
     * Reverse DNS lookup asynchronously.
     */
    @NonNull
    public static Future<String> reverseLookupAsync(@NonNull String ip) {
        return executor.submit(() -> reverseLookup(ip));
    }
    
    /**
     * Batch resolve hostnames.
     * 
     * @param hostnames list of hostnames
     * @return map of hostname to IP
     */
    @NonNull
    public static Map<String, String> resolveBatch(@NonNull List<String> hostnames) {
        Map<String, String> results = new HashMap<>();
        List<Future<String[]>> futures = new ArrayList<>();
        
        for (String hostname : hostnames) {
            futures.add(executor.submit(() -> new String[]{hostname, resolve(hostname)}));
        }
        
        for (Future<String[]> future : futures) {
            try {
                String[] result = future.get(DEFAULT_TIMEOUT_MS, TimeUnit.MILLISECONDS);
                if (result[1] != null) {
                    results.put(result[0], result[1]);
                }
            } catch (Exception e) {
                // Skip failed resolutions
            }
        }
        
        return results;
    }
    
    /**
     * Batch reverse lookup IPs.
     * 
     * @param ips list of IP addresses
     * @return map of IP to hostname
     */
    @NonNull
    public static Map<String, String> reverseLookupBatch(@NonNull List<String> ips) {
        Map<String, String> results = new HashMap<>();
        List<Future<String[]>> futures = new ArrayList<>();
        
        for (String ip : ips) {
            futures.add(executor.submit(() -> new String[]{ip, reverseLookup(ip)}));
        }
        
        for (Future<String[]> future : futures) {
            try {
                String[] result = future.get(DEFAULT_TIMEOUT_MS, TimeUnit.MILLISECONDS);
                if (result[1] != null) {
                    results.put(result[0], result[1]);
                }
            } catch (Exception e) {
                // Skip failed lookups
            }
        }
        
        return results;
    }
    
    /**
     * Get all IP addresses for a hostname.
     * 
     * @param hostname hostname to resolve
     * @return list of IP addresses
     */
    @NonNull
    public static List<String> resolveAll(@NonNull String hostname) {
        List<String> addresses = new ArrayList<>();
        
        try {
            InetAddress[] allAddresses = InetAddress.getAllByName(hostname);
            for (InetAddress addr : allAddresses) {
                addresses.add(addr.getHostAddress());
            }
        } catch (Exception e) {
            Log.w(TAG, "Failed to resolve all addresses for: " + hostname, e);
        }
        
        return addresses;
    }
    
    /**
     * Check if hostname is resolvable.
     */
    public static boolean isResolvable(@NonNull String hostname) {
        return resolve(hostname) != null;
    }
    
    /**
     * Get hostname without reverse lookup (from cache or quick check).
     */
    @Nullable
    public static String getHostnameQuick(@NonNull String ip) {
        CacheEntry cached = reverseCache.get(ip);
        if (cached != null && !cached.isExpired()) {
            return cached.value;
        }
        return null;
    }
    
    /**
     * Clear DNS cache.
     */
    public static void clearCache() {
        forwardCache.clear();
        reverseCache.clear();
    }
    
    /**
     * Get cache statistics.
     */
    @NonNull
    public static CacheStats getCacheStats() {
        int forwardSize = forwardCache.size();
        int reverseSize = reverseCache.size();
        int forwardExpired = 0;
        int reverseExpired = 0;
        
        for (CacheEntry entry : forwardCache.values()) {
            if (entry.isExpired()) forwardExpired++;
        }
        for (CacheEntry entry : reverseCache.values()) {
            if (entry.isExpired()) reverseExpired++;
        }
        
        return new CacheStats(forwardSize, reverseSize, forwardExpired, reverseExpired);
    }
    
    /**
     * DNS cache statistics.
     */
    public static class CacheStats {
        public final int forwardEntries;
        public final int reverseEntries;
        public final int forwardExpired;
        public final int reverseExpired;
        
        CacheStats(int forward, int reverse, int forwardExp, int reverseExp) {
            this.forwardEntries = forward;
            this.reverseEntries = reverse;
            this.forwardExpired = forwardExp;
            this.reverseExpired = reverseExp;
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("CacheStats{forward=%d (%d expired), reverse=%d (%d expired)}",
                    forwardEntries, forwardExpired, reverseEntries, reverseExpired);
        }
    }
    
    /**
     * Check if string is a valid hostname (not IP).
     */
    public static boolean isHostname(@NonNull String str) {
        // Simple check: if it doesn't look like an IP, it's probably a hostname
        if (str.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")) {
            return false; // IPv4
        }
        if (str.contains(":")) {
            return false; // IPv6
        }
        return true;
    }
    
    /**
     * Extract domain from hostname.
     */
    @NonNull
    public static String extractDomain(@NonNull String hostname) {
        String[] parts = hostname.split("\\.");
        if (parts.length >= 2) {
            return parts[parts.length - 2] + "." + parts[parts.length - 1];
        }
        return hostname;
    }
    
    /**
     * Get subdomain from full hostname.
     */
    @Nullable
    public static String getSubdomain(@NonNull String hostname) {
        String domain = extractDomain(hostname);
        if (hostname.length() > domain.length()) {
            return hostname.substring(0, hostname.length() - domain.length() - 1);
        }
        return null;
    }
    
    /**
     * Perform nslookup using system command.
     * More reliable for certain record types.
     */
    @Nullable
    public static String nslookup(@NonNull String target) {
        try {
            ProcessBuilder pb = new ProcessBuilder("nslookup", target);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            
            process.waitFor();
            return output.toString();
        } catch (Exception e) {
            Log.w(TAG, "nslookup failed for: " + target, e);
            return null;
        }
    }
    
    /**
     * Cleanup expired cache entries.
     */
    private static void cleanupCache(ConcurrentHashMap<String, CacheEntry> cache) {
        if (cache.size() > CACHE_SIZE) {
            cache.entrySet().removeIf(entry -> entry.getValue().isExpired());
            
            // If still over size, remove oldest
            while (cache.size() > CACHE_SIZE) {
                String firstKey = cache.keys().nextElement();
                cache.remove(firstKey);
            }
        }
    }
    
    /**
     * Shutdown executor.
     */
    public static void shutdown() {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
        }
    }
}
