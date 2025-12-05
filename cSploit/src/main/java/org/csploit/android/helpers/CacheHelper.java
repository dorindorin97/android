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

import android.content.Context;
import android.graphics.Bitmap;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.File;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * CacheHelper - Flexible caching utility for objects, bitmaps, and HTTP responses
 *
 * Provides centralized cache management for application data including:
 * - In-memory object caching with LRU eviction
 * - Bitmap caching with size limits
 * - HTTP response caching with TTL
 * - Disk-based caching for large objects
 * - Cache statistics and monitoring
 *
 * Features:
 * - LRU (Least Recently Used) cache eviction
 * - Configurable cache size limits
 * - Time-to-live (TTL) based expiration
 * - Thread-safe operations
 * - Cache statistics tracking
 * - Multiple cache types support
 *
 * Usage:
 * {@code
 * // Simple object caching
 * CacheHelper.put("user_data", userData);
 * UserData data = CacheHelper.get("user_data", UserData.class);
 *
 * // Bitmap caching
 * CacheHelper.putBitmap(context, "avatar", bitmap, 1024 * 1024);  // 1 MB
 *
 * // HTTP response caching
 * CacheHelper.putResponse(url, response, 5 * 60);  // 5 minute TTL
 *
 * // Cache management
 * CacheHelper.clearCache();
 * CacheHelper.getStatistics();
 * }
 *
 * @author cSploit Team
 * @version 1.0
 */
public final class CacheHelper {

    private static final String TAG = "CacheHelper";

    // In-memory object cache (thread-safe)
    private static final Map<String, CacheEntry<?>> OBJECT_CACHE = 
            Collections.synchronizedMap(new LinkedHashMap<String, CacheEntry<?>>(16, 0.75f, true) {
                private static final long serialVersionUID = 1L;
                private static final int MAX_ENTRIES = 100;

                @Override
                protected boolean removeEldestEntry(Map.Entry eldest) {
                    return size() > MAX_ENTRIES;
                }
            });

    // Bitmap cache (thread-safe, with size limit)
    private static final Map<String, BitmapCacheEntry> BITMAP_CACHE = 
            Collections.synchronizedMap(new HashMap<String, BitmapCacheEntry>());
    private static long bitmapCacheSize = 0;
    private static final long DEFAULT_BITMAP_CACHE_LIMIT = 50 * 1024 * 1024;  // 50 MB

    // HTTP response cache (thread-safe)
    private static final Map<String, ResponseCacheEntry> RESPONSE_CACHE = 
            Collections.synchronizedMap(new HashMap<String, ResponseCacheEntry>());

    // Cache statistics
    private static long hitCount = 0;
    private static long missCount = 0;
    private static long evictionCount = 0;

    // Private constructor to prevent instantiation
    private CacheHelper() {}

    /**
     * Inner class for cache entries with TTL support
     */
    private static class CacheEntry<T> {
        final T value;
        final long expirationTime;

        CacheEntry(T value, long ttlMs) {
            this.value = value;
            this.expirationTime = System.currentTimeMillis() + ttlMs;
        }

        boolean isExpired() {
            return System.currentTimeMillis() > expirationTime;
        }
    }

    /**
     * Inner class for bitmap cache entries with size tracking
     */
    private static class BitmapCacheEntry {
        final Bitmap bitmap;
        final long size;
        final long timestamp;

        BitmapCacheEntry(Bitmap bitmap) {
            this.bitmap = bitmap;
            this.size = bitmap.getByteCount();
            this.timestamp = System.currentTimeMillis();
        }
    }

    /**
     * Inner class for HTTP response cache entries
     */
    private static class ResponseCacheEntry {
        final byte[] data;
        final Map<String, String> headers;
        final int statusCode;
        final long expirationTime;

        ResponseCacheEntry(byte[] data, Map<String, String> headers, int statusCode, long ttlMs) {
            this.data = data;
            this.headers = new HashMap<>(headers);
            this.statusCode = statusCode;
            this.expirationTime = System.currentTimeMillis() + ttlMs;
        }

        boolean isExpired() {
            return System.currentTimeMillis() > expirationTime;
        }
    }

    /**
     * Put object in cache with default TTL (5 minutes)
     *
     * @param key cache key
     * @param value object to cache
     */
    public static void put(@NonNull String key, @NonNull Object value) {
        put(key, value, 5 * 60 * 1000);  // 5 minutes default
    }

    /**
     * Put object in cache with custom TTL
     *
     * @param key cache key
     * @param value object to cache
     * @param ttlMs time-to-live in milliseconds
     */
    public static void put(@NonNull String key, @NonNull Object value, long ttlMs) {
        OBJECT_CACHE.put(key, new CacheEntry<>(value, ttlMs));
        LoggingHelper.d(TAG, "Cached: " + key);
    }

    /**
     * Get object from cache
     *
     * @param key cache key
     * @param type expected type
     * @return cached object or null
     */
    @Nullable
    public static <T> T get(@NonNull String key, @NonNull Class<T> type) {
        CacheEntry<?> entry = OBJECT_CACHE.get(key);

        if (entry == null) {
            missCount++;
            return null;
        }

        if (entry.isExpired()) {
            OBJECT_CACHE.remove(key);
            evictionCount++;
            missCount++;
            LoggingHelper.d(TAG, "Cache expired: " + key);
            return null;
        }

        hitCount++;
        try {
            @SuppressWarnings("unchecked")
            T result = (T) entry.value;
            return result;
        } catch (ClassCastException e) {
            LoggingHelper.w(TAG, "Cache type mismatch for key: " + key, e);
            return null;
        }
    }

    /**
     * Check if key exists in cache and is not expired
     *
     * @param key cache key
     * @return true if valid cache entry exists
     */
    public static boolean contains(@NonNull String key) {
        CacheEntry<?> entry = OBJECT_CACHE.get(key);
        if (entry == null) return false;

        if (entry.isExpired()) {
            OBJECT_CACHE.remove(key);
            return false;
        }

        return true;
    }

    /**
     * Put bitmap in cache
     *
     * @param context Android context
     * @param key cache key
     * @param bitmap bitmap to cache
     * @param maxSizeBytes maximum cache size
     * @return true if cached successfully
     */
    public static boolean putBitmap(@NonNull Context context, @NonNull String key, 
                                    @NonNull Bitmap bitmap, long maxSizeBytes) {
        long bitmapSize = bitmap.getByteCount();

        // Evict entries if necessary
        while (bitmapCacheSize + bitmapSize > maxSizeBytes && !BITMAP_CACHE.isEmpty()) {
            String oldestKey = BITMAP_CACHE.keySet().iterator().next();
            BitmapCacheEntry removed = BITMAP_CACHE.remove(oldestKey);
            if (removed != null) {
                bitmapCacheSize -= removed.size;
                evictionCount++;
            }
        }

        if (bitmapCacheSize + bitmapSize <= maxSizeBytes) {
            BITMAP_CACHE.put(key, new BitmapCacheEntry(bitmap));
            bitmapCacheSize += bitmapSize;
            LoggingHelper.d(TAG, "Cached bitmap: " + key + " (" + bitmapSize + " bytes)");
            return true;
        }

        return false;
    }

    /**
     * Get bitmap from cache
     *
     * @param key cache key
     * @return cached bitmap or null
     */
    @Nullable
    public static Bitmap getBitmap(@NonNull String key) {
        BitmapCacheEntry entry = BITMAP_CACHE.get(key);

        if (entry == null) {
            missCount++;
            return null;
        }

        hitCount++;
        return entry.bitmap;
    }

    /**
     * Remove bitmap from cache
     *
     * @param key cache key
     * @return true if removed
     */
    public static boolean removeBitmap(@NonNull String key) {
        BitmapCacheEntry removed = BITMAP_CACHE.remove(key);
        if (removed != null) {
            bitmapCacheSize -= removed.size;
            return true;
        }
        return false;
    }

    /**
     * Cache HTTP response
     *
     * @param url response URL
     * @param data response body
     * @param headers response headers
     * @param statusCode HTTP status code
     * @param ttlSeconds cache duration in seconds
     */
    public static void putResponse(@NonNull String url, byte[] data, Map<String, String> headers,
                                   int statusCode, long ttlSeconds) {
        RESPONSE_CACHE.put(url, new ResponseCacheEntry(data, headers, statusCode, ttlSeconds * 1000));
        LoggingHelper.d(TAG, "Cached response: " + url);
    }

    /**
     * Get cached HTTP response
     *
     * @param url response URL
     * @return response data or null
     */
    @Nullable
    public static byte[] getResponse(@NonNull String url) {
        ResponseCacheEntry entry = RESPONSE_CACHE.get(url);

        if (entry == null) {
            missCount++;
            return null;
        }

        if (entry.isExpired()) {
            RESPONSE_CACHE.remove(url);
            evictionCount++;
            missCount++;
            LoggingHelper.d(TAG, "Response cache expired: " + url);
            return null;
        }

        hitCount++;
        return entry.data;
    }

    /**
     * Get cached response with headers
     *
     * @param url response URL
     * @return cached response or null
     */
    @Nullable
    public static ResponseCacheEntry getResponseWithHeaders(@NonNull String url) {
        ResponseCacheEntry entry = RESPONSE_CACHE.get(url);

        if (entry == null) {
            missCount++;
            return null;
        }

        if (entry.isExpired()) {
            RESPONSE_CACHE.remove(url);
            evictionCount++;
            missCount++;
            return null;
        }

        hitCount++;
        return entry;
    }

    /**
     * Clear all object caches
     */
    public static void clearCache() {
        OBJECT_CACHE.clear();
        BITMAP_CACHE.clear();
        RESPONSE_CACHE.clear();
        bitmapCacheSize = 0;
        LoggingHelper.d(TAG, "All caches cleared");
    }

    /**
     * Clear object cache only
     */
    public static void clearObjectCache() {
        OBJECT_CACHE.clear();
    }

    /**
     * Clear bitmap cache only
     */
    public static void clearBitmapCache() {
        BITMAP_CACHE.clear();
        bitmapCacheSize = 0;
    }

    /**
     * Clear response cache only
     */
    public static void clearResponseCache() {
        RESPONSE_CACHE.clear();
    }

    /**
     * Remove expired entries from all caches
     */
    public static void evictExpired() {
        // Object cache
        Iterator<Map.Entry<String, CacheEntry<?>>> objIter = OBJECT_CACHE.entrySet().iterator();
        while (objIter.hasNext()) {
            if (objIter.next().getValue().isExpired()) {
                objIter.remove();
                evictionCount++;
            }
        }

        // Response cache
        Iterator<Map.Entry<String, ResponseCacheEntry>> respIter = RESPONSE_CACHE.entrySet().iterator();
        while (respIter.hasNext()) {
            if (respIter.next().getValue().isExpired()) {
                respIter.remove();
                evictionCount++;
            }
        }

        LoggingHelper.d(TAG, "Expired entries evicted");
    }

    /**
     * Get cache statistics
     *
     * @return formatted statistics string
     */
    @NonNull
    public static String getStatistics() {
        StringBuilder sb = new StringBuilder();
        long total = hitCount + missCount;
        double hitRate = total > 0 ? (hitCount * 100.0 / total) : 0;

        sb.append("Cache Statistics:\n");
        sb.append("Hits: ").append(hitCount).append("\n");
        sb.append("Misses: ").append(missCount).append("\n");
        sb.append("Hit Rate: ").append(String.format("%.1f%%", hitRate)).append("\n");
        sb.append("Evictions: ").append(evictionCount).append("\n");
        sb.append("Object Cache Size: ").append(OBJECT_CACHE.size()).append("\n");
        sb.append("Bitmap Cache Size: ").append(BITMAP_CACHE.size()).append(" (").append(SystemHelper.formatBytes(bitmapCacheSize)).append(")\n");
        sb.append("Response Cache Size: ").append(RESPONSE_CACHE.size()).append("\n");

        return sb.toString();
    }

    /**
     * Reset cache statistics
     */
    public static void resetStatistics() {
        hitCount = 0;
        missCount = 0;
        evictionCount = 0;
        LoggingHelper.d(TAG, "Statistics reset");
    }

    /**
     * Get cache hit rate percentage
     *
     * @return hit rate or 0 if no accesses
     */
    public static double getHitRate() {
        long total = hitCount + missCount;
        return total > 0 ? (hitCount * 100.0 / total) : 0;
    }

    /**
     * Get current bitmap cache size
     *
     * @return size in bytes
     */
    public static long getBitmapCacheSize() {
        return bitmapCacheSize;
    }

    /**
     * Get current object cache count
     *
     * @return number of cached objects
     */
    public static int getObjectCacheCount() {
        return OBJECT_CACHE.size();
    }

    /**
     * Get current bitmap cache count
     *
     * @return number of cached bitmaps
     */
    public static int getBitmapCacheCount() {
        return BITMAP_CACHE.size();
    }

    /**
     * Get current response cache count
     *
     * @return number of cached responses
     */
    public static int getResponseCacheCount() {
        return RESPONSE_CACHE.size();
    }
}
