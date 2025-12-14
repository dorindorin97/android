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
import androidx.annotation.Nullable;

import java.io.Closeable;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

/**
 * Comprehensive resource lifecycle manager for cSploit.
 *
 * Features:
 * - Automatic resource tracking and cleanup
 * - Resource pooling for expensive objects
 * - Leak detection and monitoring
 * - Scoped resource management
 * - Statistics and monitoring
 */
public final class ResourceManager {

    private static final String TAG = "ResourceManager";

    // Resource tracking
    private static final Map<String, List<WeakReference<AutoCloseable>>> trackedResources = new ConcurrentHashMap<>();
    private static final Map<String, ResourcePool<?>> resourcePools = new ConcurrentHashMap<>();

    // Statistics
    private static final AtomicLong totalAllocations = new AtomicLong(0);
    private static final AtomicLong totalReleases = new AtomicLong(0);
    private static final AtomicLong leaksDetected = new AtomicLong(0);

    // Background cleanup
    private static ScheduledExecutorService cleanupExecutor = null;
    private static final AtomicBoolean cleanupScheduled = new AtomicBoolean(false);

    private ResourceManager() {}

    // ===================== Scoped Resource Management =====================

    /**
     * Resource scope for automatic cleanup.
     * Use with try-with-resources for automatic resource cleanup.
     */
    public static class Scope implements AutoCloseable {
        private final String name;
        private final List<AutoCloseable> resources = new ArrayList<>();
        private final AtomicBoolean closed = new AtomicBoolean(false);

        public Scope(@NonNull String name) {
            this.name = name;
            LoggingHelper.v(TAG, "Created scope: " + name);
        }

        /**
         * Register a resource with this scope.
         * Will be closed when scope closes.
         */
        @NonNull
        public <T extends AutoCloseable> T register(@NonNull T resource) {
            if (closed.get()) {
                throw new IllegalStateException("Scope already closed: " + name);
            }
            synchronized (resources) {
                resources.add(resource);
            }
            totalAllocations.incrementAndGet();
            return resource;
        }

        /**
         * Register a closeable resource with this scope.
         */
        @NonNull
        public <T extends Closeable> T registerCloseable(@NonNull T resource) {
            return register(resource);
        }

        @Override
        public void close() {
            if (closed.compareAndSet(false, true)) {
                List<AutoCloseable> toClose;
                synchronized (resources) {
                    toClose = new ArrayList<>(resources);
                    resources.clear();
                }

                // Close in reverse order
                for (int i = toClose.size() - 1; i >= 0; i--) {
                    try {
                        toClose.get(i).close();
                        totalReleases.incrementAndGet();
                    } catch (Exception e) {
                        LoggingHelper.w(TAG, "Error closing resource in scope " + name + ": " + e.getMessage());
                    }
                }
                LoggingHelper.v(TAG, "Closed scope: " + name + " (" + toClose.size() + " resources)");
            }
        }

        /**
         * Check if scope is closed.
         */
        public boolean isClosed() {
            return closed.get();
        }

        /**
         * Get count of registered resources.
         */
        public int getResourceCount() {
            synchronized (resources) {
                return resources.size();
            }
        }
    }

    /**
     * Create a new resource scope.
     */
    @NonNull
    public static Scope newScope(@NonNull String name) {
        return new Scope(name);
    }

    // ===================== Resource Tracking =====================

    /**
     * Track a resource for monitoring (does not auto-close).
     */
    public static void track(@NonNull String category, @NonNull AutoCloseable resource) {
        List<WeakReference<AutoCloseable>> list = trackedResources.computeIfAbsent(
                category, k -> new ArrayList<>());

        synchronized (list) {
            list.add(new WeakReference<>(resource));
        }
        totalAllocations.incrementAndGet();
        LoggingHelper.v(TAG, "Tracking resource in category: " + category);
    }

    /**
     * Untrack a resource.
     */
    public static void untrack(@NonNull String category, @NonNull AutoCloseable resource) {
        List<WeakReference<AutoCloseable>> list = trackedResources.get(category);
        if (list != null) {
            synchronized (list) {
                Iterator<WeakReference<AutoCloseable>> it = list.iterator();
                while (it.hasNext()) {
                    AutoCloseable tracked = it.next().get();
                    if (tracked == null || tracked == resource) {
                        it.remove();
                        if (tracked != null) {
                            totalReleases.incrementAndGet();
                        }
                    }
                }
            }
        }
    }

    /**
     * Get count of tracked resources in a category.
     */
    public static int getTrackedCount(@NonNull String category) {
        List<WeakReference<AutoCloseable>> list = trackedResources.get(category);
        if (list == null) return 0;

        int count = 0;
        synchronized (list) {
            for (WeakReference<AutoCloseable> ref : list) {
                if (ref.get() != null) count++;
            }
        }
        return count;
    }

    // ===================== Resource Pooling =====================

    /**
     * Generic resource pool for expensive objects.
     */
    public static class ResourcePool<T extends AutoCloseable> {
        private final String name;
        private final Supplier<T> factory;
        private final List<T> available = new ArrayList<>();
        private final List<T> inUse = new ArrayList<>();
        private final int maxSize;
        private final AtomicLong creates = new AtomicLong(0);
        private final AtomicLong borrows = new AtomicLong(0);
        private final AtomicLong returns = new AtomicLong(0);

        public ResourcePool(@NonNull String name, @NonNull Supplier<T> factory, int maxSize) {
            this.name = name;
            this.factory = factory;
            this.maxSize = maxSize;
        }

        /**
         * Borrow a resource from the pool.
         */
        @Nullable
        public synchronized T borrow() {
            T resource;

            if (!available.isEmpty()) {
                resource = available.remove(available.size() - 1);
            } else if (inUse.size() < maxSize) {
                resource = factory.get();
                if (resource == null) {
                    return null;
                }
                creates.incrementAndGet();
            } else {
                LoggingHelper.w(TAG, "Pool " + name + " exhausted");
                return null;
            }

            inUse.add(resource);
            borrows.incrementAndGet();
            return resource;
        }

        /**
         * Return a resource to the pool.
         */
        public synchronized void release(@NonNull T resource) {
            if (inUse.remove(resource)) {
                available.add(resource);
                returns.incrementAndGet();
            }
        }

        /**
         * Close all resources and clear the pool.
         */
        public synchronized void shutdown() {
            for (T resource : available) {
                CloseableHelper.closeQuietly(resource);
            }
            for (T resource : inUse) {
                CloseableHelper.closeQuietly(resource);
            }
            available.clear();
            inUse.clear();
            LoggingHelper.i(TAG, "Pool " + name + " shutdown");
        }

        /**
         * Get pool statistics.
         */
        public String getStats() {
            return String.format("Pool[%s]: available=%d, inUse=%d, creates=%d, borrows=%d, returns=%d",
                    name, available.size(), inUse.size(),
                    creates.get(), borrows.get(), returns.get());
        }
    }

    /**
     * Create and register a resource pool.
     */
    @NonNull
    public static <T extends AutoCloseable> ResourcePool<T> createPool(
            @NonNull String name, @NonNull Supplier<T> factory, int maxSize) {
        ResourcePool<T> pool = new ResourcePool<>(name, factory, maxSize);
        resourcePools.put(name, pool);
        LoggingHelper.i(TAG, "Created resource pool: " + name + " (max=" + maxSize + ")");
        return pool;
    }

    /**
     * Get a registered pool by name.
     */
    @SuppressWarnings("unchecked")
    @Nullable
    public static <T extends AutoCloseable> ResourcePool<T> getPool(@NonNull String name) {
        return (ResourcePool<T>) resourcePools.get(name);
    }

    // ===================== Cleanup and Monitoring =====================

    /**
     * Start background cleanup task.
     */
    public static void startBackgroundCleanup(long intervalMinutes) {
        if (cleanupScheduled.compareAndSet(false, true)) {
            cleanupExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "ResourceManager-Cleanup");
                t.setDaemon(true);
                return t;
            });

            cleanupExecutor.scheduleAtFixedRate(
                    ResourceManager::performCleanup,
                    intervalMinutes,
                    intervalMinutes,
                    TimeUnit.MINUTES
            );

            LoggingHelper.i(TAG, "Started background cleanup (interval=" + intervalMinutes + "min)");
        }
    }

    /**
     * Stop background cleanup task.
     */
    public static void stopBackgroundCleanup() {
        if (cleanupScheduled.compareAndSet(true, false)) {
            if (cleanupExecutor != null) {
                cleanupExecutor.shutdown();
                cleanupExecutor = null;
            }
            LoggingHelper.i(TAG, "Stopped background cleanup");
        }
    }

    /**
     * Perform cleanup of garbage-collected tracked resources.
     */
    public static void performCleanup() {
        int cleaned = 0;

        for (Map.Entry<String, List<WeakReference<AutoCloseable>>> entry : trackedResources.entrySet()) {
            List<WeakReference<AutoCloseable>> list = entry.getValue();
            synchronized (list) {
                Iterator<WeakReference<AutoCloseable>> it = list.iterator();
                while (it.hasNext()) {
                    if (it.next().get() == null) {
                        it.remove();
                        cleaned++;
                        leaksDetected.incrementAndGet();
                    }
                }
            }
        }

        if (cleaned > 0) {
            LoggingHelper.w(TAG, "Cleanup: removed " + cleaned + " garbage-collected resources (potential leaks)");
        }
    }

    /**
     * Get resource manager statistics.
     */
    @NonNull
    public static String getStatistics() {
        StringBuilder sb = new StringBuilder();
        sb.append("ResourceManager Statistics:\n");
        sb.append("  Total allocations: ").append(totalAllocations.get()).append("\n");
        sb.append("  Total releases: ").append(totalReleases.get()).append("\n");
        sb.append("  Potential leaks detected: ").append(leaksDetected.get()).append("\n");
        sb.append("  Active: ").append(totalAllocations.get() - totalReleases.get()).append("\n");

        sb.append("Tracked categories:\n");
        for (String category : trackedResources.keySet()) {
            sb.append("  ").append(category).append(": ").append(getTrackedCount(category)).append("\n");
        }

        sb.append("Resource pools:\n");
        for (ResourcePool<?> pool : resourcePools.values()) {
            sb.append("  ").append(pool.getStats()).append("\n");
        }

        return sb.toString();
    }

    /**
     * Check for potential resource leaks.
     * Returns the number of resources that appear to be leaked.
     */
    public static long checkForLeaks() {
        long currentActive = totalAllocations.get() - totalReleases.get();
        if (currentActive > 100) {
            LoggingHelper.w(TAG, "High number of active resources: " + currentActive);
        }
        return leaksDetected.get();
    }

    /**
     * Reset all statistics (for testing).
     */
    public static void resetStatistics() {
        totalAllocations.set(0);
        totalReleases.set(0);
        leaksDetected.set(0);
    }

    /**
     * Shutdown all resource pools and cleanup.
     */
    public static void shutdown() {
        stopBackgroundCleanup();

        for (ResourcePool<?> pool : resourcePools.values()) {
            pool.shutdown();
        }
        resourcePools.clear();
        trackedResources.clear();

        LoggingHelper.i(TAG, "ResourceManager shutdown complete");
    }
}
