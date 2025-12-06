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
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * GeoIPHelper - IP geolocation helper.
 * 
 * Provides:
 * - IP to country/city lookup
 * - Multiple provider support
 * - Caching of results
 * - Batch lookups
 * 
 * Usage:
 * {@code
 * GeoIPHelper geoip = GeoIPHelper.getInstance();
 * 
 * // Look up location
 * GeoInfo info = geoip.lookup("8.8.8.8");
 * String country = info.country; // "United States"
 * 
 * // Batch lookup
 * Map<String, GeoInfo> results = geoip.lookupBatch(ipList);
 * }
 */
public final class GeoIPHelper {
    
    public static final String TAG = "GeoIPHelper";
    
    private static volatile GeoIPHelper instance;
    
    // Cache for lookups
    private final Map<String, GeoInfo> cache = new HashMap<>();
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    
    // API providers
    private static final String[] PROVIDERS = {
        "http://ip-api.com/json/%s?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as",
        "https://ipapi.co/%s/json/",
        "https://freegeoip.app/json/%s"
    };
    
    private int currentProvider = 0;
    private int requestCount = 0;
    private long lastRequestTime = 0;
    private static final int RATE_LIMIT_DELAY = 1000; // 1 second between requests
    
    /**
     * Geolocation information.
     */
    public static class GeoInfo {
        public final String ip;
        public final String country;
        public final String countryCode;
        public final String region;
        public final String city;
        public final String zip;
        public final double latitude;
        public final double longitude;
        public final String timezone;
        public final String isp;
        public final String org;
        public final String asn;
        public final long lookupTime;
        
        GeoInfo(String ip, String country, String countryCode, String region,
                String city, String zip, double latitude, double longitude,
                String timezone, String isp, String org, String asn) {
            this.ip = ip;
            this.country = country;
            this.countryCode = countryCode;
            this.region = region;
            this.city = city;
            this.zip = zip;
            this.latitude = latitude;
            this.longitude = longitude;
            this.timezone = timezone;
            this.isp = isp;
            this.org = org;
            this.asn = asn;
            this.lookupTime = System.currentTimeMillis();
        }
        
        @NonNull
        @Override
        public String toString() {
            if (city != null && !city.isEmpty()) {
                return String.format("%s, %s, %s", city, region, country);
            }
            return country != null ? country : "Unknown";
        }
        
        public String getShortLocation() {
            if (city != null && !city.isEmpty() && countryCode != null) {
                return String.format("%s, %s", city, countryCode);
            }
            return countryCode != null ? countryCode : "??";
        }
    }
    
    private GeoIPHelper() {}
    
    /**
     * Get singleton instance.
     */
    public static GeoIPHelper getInstance() {
        if (instance == null) {
            synchronized (GeoIPHelper.class) {
                if (instance == null) {
                    instance = new GeoIPHelper();
                }
            }
        }
        return instance;
    }
    
    /**
     * Look up geolocation for an IP address.
     * 
     * @param ip IP address to lookup
     * @return geolocation info or null if lookup failed
     */
    @Nullable
    public GeoInfo lookup(@NonNull String ip) {
        // Check cache first
        GeoInfo cached = cache.get(ip);
        if (cached != null) {
            // Cache valid for 1 hour
            if (System.currentTimeMillis() - cached.lookupTime < 3600000) {
                return cached;
            }
        }
        
        // Skip private IPs
        if (isPrivateIP(ip)) {
            GeoInfo privateInfo = new GeoInfo(ip, "Private Network", "LAN", 
                    null, null, null, 0, 0, null, null, null, null);
            cache.put(ip, privateInfo);
            return privateInfo;
        }
        
        // Rate limiting
        enforceRateLimit();
        
        // Try each provider
        for (int attempt = 0; attempt < PROVIDERS.length; attempt++) {
            String providerUrl = PROVIDERS[(currentProvider + attempt) % PROVIDERS.length];
            GeoInfo result = lookupFromProvider(ip, providerUrl);
            if (result != null) {
                cache.put(ip, result);
                return result;
            }
        }
        
        return null;
    }
    
    /**
     * Look up geolocation asynchronously.
     */
    @NonNull
    public Future<GeoInfo> lookupAsync(@NonNull String ip) {
        return executor.submit(() -> lookup(ip));
    }
    
    /**
     * Batch lookup for multiple IPs.
     */
    @NonNull
    public Map<String, GeoInfo> lookupBatch(@NonNull List<String> ips) {
        Map<String, GeoInfo> results = new HashMap<>();
        
        for (String ip : ips) {
            GeoInfo info = lookup(ip);
            if (info != null) {
                results.put(ip, info);
            }
        }
        
        return results;
    }
    
    /**
     * Check if IP is a private address.
     */
    public boolean isPrivateIP(@NonNull String ip) {
        try {
            InetAddress addr = InetAddress.getByName(ip);
            return addr.isSiteLocalAddress() || 
                   addr.isLoopbackAddress() ||
                   addr.isLinkLocalAddress() ||
                   addr.isAnyLocalAddress();
        } catch (Exception e) {
            // Try pattern matching
            return ip.startsWith("10.") ||
                   ip.startsWith("192.168.") ||
                   ip.startsWith("172.16.") ||
                   ip.startsWith("172.17.") ||
                   ip.startsWith("172.18.") ||
                   ip.startsWith("172.19.") ||
                   ip.startsWith("172.2") ||
                   ip.startsWith("172.30.") ||
                   ip.startsWith("172.31.") ||
                   ip.startsWith("127.") ||
                   ip.equals("localhost");
        }
    }
    
    /**
     * Get country code from cached or lookup.
     */
    @Nullable
    public String getCountryCode(@NonNull String ip) {
        GeoInfo info = lookup(ip);
        return info != null ? info.countryCode : null;
    }
    
    /**
     * Get flag emoji for country code.
     */
    @NonNull
    public String getFlagEmoji(@NonNull String countryCode) {
        if (countryCode == null || countryCode.length() != 2) {
            return "\uD83C\uDFF3"; // White flag
        }
        
        // Convert country code to regional indicator symbols
        String cc = countryCode.toUpperCase();
        int first = Character.codePointAt(cc, 0) - 'A' + 0x1F1E6;
        int second = Character.codePointAt(cc, 1) - 'A' + 0x1F1E6;
        
        return new String(Character.toChars(first)) + new String(Character.toChars(second));
    }
    
    /**
     * Clear the cache.
     */
    public void clearCache() {
        cache.clear();
    }
    
    /**
     * Get cache statistics.
     */
    @NonNull
    public Map<String, Object> getCacheStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("cacheSize", cache.size());
        stats.put("totalRequests", requestCount);
        
        Map<String, Integer> countryStats = new HashMap<>();
        for (GeoInfo info : cache.values()) {
            if (info.countryCode != null) {
                countryStats.merge(info.countryCode, 1, Integer::sum);
            }
        }
        stats.put("countryCounts", countryStats);
        
        return stats;
    }
    
    // Private helper methods
    
    private void enforceRateLimit() {
        long now = System.currentTimeMillis();
        long elapsed = now - lastRequestTime;
        
        if (elapsed < RATE_LIMIT_DELAY) {
            try {
                Thread.sleep(RATE_LIMIT_DELAY - elapsed);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        
        lastRequestTime = System.currentTimeMillis();
        requestCount++;
    }
    
    @Nullable
    private GeoInfo lookupFromProvider(String ip, String providerUrlTemplate) {
        HttpURLConnection conn = null;
        try {
            String urlStr = String.format(providerUrlTemplate, ip);
            URL url = new URL(urlStr);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.setRequestProperty("User-Agent", "cSploit/1.0");
            
            int responseCode = conn.getResponseCode();
            if (responseCode != 200) {
                Log.w(TAG, "Provider returned " + responseCode);
                currentProvider = (currentProvider + 1) % PROVIDERS.length;
                return null;
            }
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();
            
            return parseResponse(ip, response.toString());
            
        } catch (Exception e) {
            Log.w(TAG, "Lookup failed: " + e.getMessage());
            currentProvider = (currentProvider + 1) % PROVIDERS.length;
            return null;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }
    
    @Nullable
    private GeoInfo parseResponse(String ip, String json) {
        try {
            // Simple JSON parsing without library dependency
            String country = extractJsonString(json, "country");
            String countryCode = extractJsonString(json, "countryCode");
            if (countryCode == null) {
                countryCode = extractJsonString(json, "country_code");
            }
            String region = extractJsonString(json, "regionName");
            if (region == null) {
                region = extractJsonString(json, "region");
            }
            String city = extractJsonString(json, "city");
            String zip = extractJsonString(json, "zip");
            if (zip == null) {
                zip = extractJsonString(json, "postal");
            }
            double lat = extractJsonDouble(json, "lat");
            if (lat == 0) {
                lat = extractJsonDouble(json, "latitude");
            }
            double lon = extractJsonDouble(json, "lon");
            if (lon == 0) {
                lon = extractJsonDouble(json, "longitude");
            }
            String timezone = extractJsonString(json, "timezone");
            String isp = extractJsonString(json, "isp");
            String org = extractJsonString(json, "org");
            String asn = extractJsonString(json, "as");
            if (asn == null) {
                asn = extractJsonString(json, "asn");
            }
            
            if (country == null && countryCode == null) {
                return null;
            }
            
            return new GeoInfo(ip, country, countryCode, region, city, zip,
                    lat, lon, timezone, isp, org, asn);
                    
        } catch (Exception e) {
            Log.w(TAG, "Failed to parse response", e);
            return null;
        }
    }
    
    @Nullable
    private String extractJsonString(String json, String key) {
        Pattern pattern = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]*?)\"");
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }
    
    private double extractJsonDouble(String json, String key) {
        Pattern pattern = Pattern.compile("\"" + key + "\"\\s*:\\s*(-?[0-9.]+)");
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            try {
                return Double.parseDouble(matcher.group(1));
            } catch (NumberFormatException e) {
                return 0;
            }
        }
        return 0;
    }
    
    /**
     * Shutdown the executor.
     */
    public void shutdown() {
        executor.shutdown();
        try {
            executor.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            executor.shutdownNow();
        }
    }
}
