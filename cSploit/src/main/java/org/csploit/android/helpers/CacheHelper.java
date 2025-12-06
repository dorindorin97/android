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

import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantReadWriteLock;

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
    private static final int MAX_OBJECT_CACHE_ENTRIES = 100;
    private static final long DEFAULT_BITMAP_CACHE_LIMIT = 50 * 1024 * 1024;  // 50 MB

    // Locks for thread-safe operations on composite actions
    private static final ReentrantReadWriteLock objectCacheLock = new ReentrantReadWriteLock();
    private static final ReentrantReadWriteLock bitmapCacheLock = new ReentrantReadWriteLock();
    private static final ReentrantReadWriteLock responseCacheLock = new ReentrantReadWriteLock();

    // In-memory object cache with LRU eviction (protected by objectCacheLock)
    private static final LinkedHashMap<String, CacheEntry<?>> OBJECT_CACHE =
            new LinkedHashMap<String, CacheEntry<?>>(16, 0.75f, true) {
                private static final long serialVersionUID = 1L;

                @Override
                protected boolean removeEldestEntry(Map.Entry<String, CacheEntry<?>> eldest) {
                    boolean shouldRemove = size() > MAX_OBJECT_CACHE_ENTRIES;
                    if (shouldRemove) {
                        evictionCount.incrementAndGet();
                    }
                    return shouldRemove;
                }
            };

    // Bitmap cache (protected by bitmapCacheLock)
    private static final Map<String, BitmapCacheEntry> BITMAP_CACHE = new HashMap<>();
    private static final AtomicLong bitmapCacheSize = new AtomicLong(0);

    // HTTP response cache (using ConcurrentHashMap for better concurrent access)
    private static final Map<String, ResponseCacheEntry> RESPONSE_CACHE = new ConcurrentHashMap<>();

    // Cache statistics (using AtomicLong for thread-safety)
    private static final AtomicLong hitCount = new AtomicLong(0);
    private static final AtomicLong missCount = new AtomicLong(0);
    private static final AtomicLong evictionCount = new AtomicLong(0);

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
        objectCacheLock.writeLock().lock();
        try {
            OBJECT_CACHE.put(key, new CacheEntry<>(value, ttlMs));
        } finally {
            objectCacheLock.writeLock().unlock();
        }
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
        objectCacheLock.readLock().lock();
        CacheEntry<?> entry;
        try {
            entry = OBJECT_CACHE.get(key);
        } finally {
            objectCacheLock.readLock().unlock();
        }

        if (entry == null) {
            missCount.incrementAndGet();
            return null;
        }

        if (entry.isExpired()) {
            objectCacheLock.writeLock().lock();
            try {
                OBJECT_CACHE.remove(key);
            } finally {
                objectCacheLock.writeLock().unlock();
            }
            evictionCount.incrementAndGet();
            missCount.incrementAndGet();
            LoggingHelper.d(TAG, "Cache expired: " + key);
            return null;
        }

        hitCount.incrementAndGet();
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
        objectCacheLock.readLock().lock();
        CacheEntry<?> entry;
        try {
            entry = OBJECT_CACHE.get(key);
        } finally {
            objectCacheLock.readLock().unlock();
        }

        if (entry == null) return false;

        if (entry.isExpired()) {
            objectCacheLock.writeLock().lock();
            try {
                OBJECT_CACHE.remove(key);
            } finally {
                objectCacheLock.writeLock().unlock();
            }
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
        long size = bitmap.getByteCount();

        bitmapCacheLock.writeLock().lock();
        try {
            // Evict entries if necessary
            while (bitmapCacheSize.get() + size > maxSizeBytes && !BITMAP_CACHE.isEmpty()) {
                Iterator<Map.Entry<String, BitmapCacheEntry>> it = BITMAP_CACHE.entrySet().iterator();
                if (it.hasNext()) {
                    Map.Entry<String, BitmapCacheEntry> entry = it.next();
                    it.remove();
                    bitmapCacheSize.addAndGet(-entry.getValue().size);
                    evictionCount.incrementAndGet();
                }
            }

            if (bitmapCacheSize.get() + size <= maxSizeBytes) {
                BITMAP_CACHE.put(key, new BitmapCacheEntry(bitmap));
                bitmapCacheSize.addAndGet(size);
                LoggingHelper.d(TAG, "Cached bitmap: " + key + " (" + size + " bytes)");
                return true;
            }
        } finally {
            bitmapCacheLock.writeLock().unlock();
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
        bitmapCacheLock.readLock().lock();
        try {
            BitmapCacheEntry entry = BITMAP_CACHE.get(key);

            if (entry == null) {
                missCount.incrementAndGet();
                return null;
            }

            hitCount.incrementAndGet();
            return entry.bitmap;
        } finally {
            bitmapCacheLock.readLock().unlock();
        }
    }

    /**
     * Remove bitmap from cache
     *
     * @param key cache key
     * @return true if removed
     */
    public static boolean removeBitmap(@NonNull String key) {
        bitmapCacheLock.writeLock().lock();
        try {
            BitmapCacheEntry removed = BITMAP_CACHE.remove(key);
            if (removed != null) {
                bitmapCacheSize.addAndGet(-removed.size);
                return true;
            }
            return false;
        } finally {
            bitmapCacheLock.writeLock().unlock();
        }
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
            missCount.incrementAndGet();
            return null;
        }

        if (entry.isExpired()) {
            RESPONSE_CACHE.remove(url);
            evictionCount.incrementAndGet();
            missCount.incrementAndGet();
            LoggingHelper.d(TAG, "Response cache expired: " + url);
            return null;
        }

        hitCount.incrementAndGet();
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
            missCount.incrementAndGet();
            return null;
        }

        if (entry.isExpired()) {
            RESPONSE_CACHE.remove(url);
            evictionCount.incrementAndGet();
            missCount.incrementAndGet();
            return null;
        }

        hitCount.incrementAndGet();
        return entry;
    }

    /**
     * Clear all object caches
     */
    public static void clearCache() {
        objectCacheLock.writeLock().lock();
        try {
            OBJECT_CACHE.clear();
        } finally {
            objectCacheLock.writeLock().unlock();
        }

        bitmapCacheLock.writeLock().lock();
        try {
            BITMAP_CACHE.clear();
            bitmapCacheSize.set(0);
        } finally {
            bitmapCacheLock.writeLock().unlock();
        }

        RESPONSE_CACHE.clear();
        LoggingHelper.d(TAG, "All caches cleared");
    }

    /**
     * Clear object cache only
     */
    public static void clearObjectCache() {
        objectCacheLock.writeLock().lock();
        try {
            OBJECT_CACHE.clear();
        } finally {
            objectCacheLock.writeLock().unlock();
        }
    }

    /**
     * Clear bitmap cache only
     */
    public static void clearBitmapCache() {
        bitmapCacheLock.writeLock().lock();
        try {
            BITMAP_CACHE.clear();
            bitmapCacheSize.set(0);
        } finally {
            bitmapCacheLock.writeLock().unlock();
        }
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
        objectCacheLock.writeLock().lock();
        try {
            Iterator<Map.Entry<String, CacheEntry<?>>> objIter = OBJECT_CACHE.entrySet().iterator();
            while (objIter.hasNext()) {
                if (objIter.next().getValue().isExpired()) {
                    objIter.remove();
                    evictionCount.incrementAndGet();
                }
            }
        } finally {
            objectCacheLock.writeLock().unlock();
        }

        // Response cache (ConcurrentHashMap handles concurrent modification)
        Iterator<Map.Entry<String, ResponseCacheEntry>> respIter = RESPONSE_CACHE.entrySet().iterator();
        while (respIter.hasNext()) {
            if (respIter.next().getValue().isExpired()) {
                respIter.remove();
                evictionCount.incrementAndGet();
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
        long hits = hitCount.get();
        long misses = missCount.get();
        long total = hits + misses;
        double hitRate = total > 0 ? (hits * 100.0 / total) : 0;

        int objectSize;
        objectCacheLock.readLock().lock();
        try {
            objectSize = OBJECT_CACHE.size();
        } finally {
            objectCacheLock.readLock().unlock();
        }

        int bitmapCount;
        long bitmapSize;
        bitmapCacheLock.readLock().lock();
        try {
            bitmapCount = BITMAP_CACHE.size();
            bitmapSize = bitmapCacheSize.get();
        } finally {
            bitmapCacheLock.readLock().unlock();
        }

        sb.append("Cache Statistics:\n");
        sb.append("Hits: ").append(hits).append("\n");
        sb.append("Misses: ").append(misses).append("\n");
        sb.append("Hit Rate: ").append(String.format("%.1f%%", hitRate)).append("\n");
        sb.append("Evictions: ").append(evictionCount.get()).append("\n");
        sb.append("Object Cache Size: ").append(objectSize).append("\n");
        sb.append("Bitmap Cache Size: ").append(bitmapCount).append(" (").append(SystemHelper.formatBytes(bitmapSize)).append(")\n");
        sb.append("Response Cache Size: ").append(RESPONSE_CACHE.size()).append("\n");

        return sb.toString();
    }

    /**
     * Reset cache statistics
     */
    public static void resetStatistics() {
        hitCount.set(0);
        missCount.set(0);
        evictionCount.set(0);
        LoggingHelper.d(TAG, "Statistics reset");
    }

    /**
     * Get cache hit rate percentage
     *
     * @return hit rate or 0 if no accesses
     */
    public static double getHitRate() {
        long hits = hitCount.get();
        long misses = missCount.get();
        long total = hits + misses;
        return total > 0 ? (hits * 100.0 / total) : 0;
    }

    /**
     * Get current bitmap cache size
     *
     * @return size in bytes
     */
    public static long getBitmapCacheSize() {
        return bitmapCacheSize.get();
    }

    /**
     * Get current object cache count
     *
     * @return number of cached objects
     */
    public static int getObjectCacheCount() {
        objectCacheLock.readLock().lock();
        try {
            return OBJECT_CACHE.size();
        } finally {
            objectCacheLock.readLock().unlock();
        }
    }

    /**
     * Get current bitmap cache count
     *
     * @return number of cached bitmaps
     */
    public static int getBitmapCacheCount() {
        bitmapCacheLock.readLock().lock();
        try {
            return BITMAP_CACHE.size();
        } finally {
            bitmapCacheLock.readLock().unlock();
        }
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
