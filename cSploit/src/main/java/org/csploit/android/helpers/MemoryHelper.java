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

import android.app.ActivityManager;
import android.content.Context;
import android.os.Debug;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

/**
 * Memory monitoring and management utilities.
 * Provides methods to track memory usage, detect low memory conditions,
 * and optimize memory consumption.
 */
public final class MemoryHelper {

    private static final String TAG = "MemoryHelper";

    // Memory thresholds
    private static final float LOW_MEMORY_THRESHOLD = 0.15f;  // 15% free
    private static final float CRITICAL_MEMORY_THRESHOLD = 0.05f;  // 5% free
    private static final long MIN_AVAILABLE_MEMORY_MB = 50;  // 50 MB minimum

    /**
     * Memory information container
     */
    public static class MemoryInfo {
        public final long totalMemory;
        public final long availableMemory;
        public final long usedMemory;
        public final float usedPercent;
        public final boolean lowMemory;
        public final boolean criticalMemory;

        public MemoryInfo(long total, long available) {
            this.totalMemory = total;
            this.availableMemory = available;
            this.usedMemory = total - available;
            this.usedPercent = total > 0 ? (usedMemory * 100.0f / total) : 0;
            this.lowMemory = available < (total * LOW_MEMORY_THRESHOLD);
            this.criticalMemory = available < (total * CRITICAL_MEMORY_THRESHOLD);
        }

        @Override
        public String toString() {
            return String.format("Memory: %s / %s (%.1f%% used)%s",
                    SystemHelper.formatBytes(usedMemory),
                    SystemHelper.formatBytes(totalMemory),
                    usedPercent,
                    lowMemory ? " [LOW]" : "");
        }
    }

    /**
     * Get current memory information for the device
     *
     * @param context Android context
     * @return MemoryInfo object with current memory status
     */
    @NonNull
    public static MemoryInfo getDeviceMemoryInfo(@NonNull Context context) {
        ActivityManager activityManager =
                (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        ActivityManager.MemoryInfo memInfo = new ActivityManager.MemoryInfo();
        activityManager.getMemoryInfo(memInfo);

        return new MemoryInfo(memInfo.totalMem, memInfo.availMem);
    }

    /**
     * Get memory info for the current app
     *
     * @return MemoryInfo for app heap
     */
    @NonNull
    public static MemoryInfo getAppMemoryInfo() {
        Runtime runtime = Runtime.getRuntime();
        long maxMemory = runtime.maxMemory();
        long usedMemory = runtime.totalMemory() - runtime.freeMemory();
        long available = maxMemory - usedMemory;

        return new MemoryInfo(maxMemory, available);
    }

    /**
     * Get native heap memory usage
     *
     * @return allocated native heap in bytes
     */
    public static long getNativeHeapAllocatedSize() {
        return Debug.getNativeHeapAllocatedSize();
    }

    /**
     * Get native heap free size
     *
     * @return free native heap in bytes
     */
    public static long getNativeHeapFreeSize() {
        return Debug.getNativeHeapFreeSize();
    }

    /**
     * Check if device is in low memory condition
     *
     * @param context Android context
     * @return true if memory is low
     */
    public static boolean isLowMemory(@NonNull Context context) {
        ActivityManager activityManager =
                (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        ActivityManager.MemoryInfo memInfo = new ActivityManager.MemoryInfo();
        activityManager.getMemoryInfo(memInfo);
        return memInfo.lowMemory;
    }

    /**
     * Check if app is running low on heap memory
     *
     * @return true if app heap is getting full
     */
    public static boolean isAppMemoryLow() {
        MemoryInfo info = getAppMemoryInfo();
        return info.lowMemory;
    }

    /**
     * Get available memory in MB
     *
     * @param context Android context
     * @return available memory in megabytes
     */
    public static long getAvailableMemoryMB(@NonNull Context context) {
        MemoryInfo info = getDeviceMemoryInfo(context);
        return info.availableMemory / (1024 * 1024);
    }

    /**
     * Check if there's enough memory for an operation
     *
     * @param context Android context
     * @param requiredMB memory required in MB
     * @return true if enough memory is available
     */
    public static boolean hasEnoughMemory(@NonNull Context context, long requiredMB) {
        return getAvailableMemoryMB(context) >= requiredMB + MIN_AVAILABLE_MEMORY_MB;
    }

    /**
     * Request garbage collection (hint to JVM)
     */
    public static void requestGarbageCollection() {
        Runtime.getRuntime().gc();
        LoggingHelper.debug("Garbage collection requested");
    }

    /**
     * Get memory class of the device (max heap per app in MB)
     *
     * @param context Android context
     * @return memory class in MB
     */
    public static int getMemoryClass(@NonNull Context context) {
        ActivityManager activityManager =
                (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        return activityManager.getMemoryClass();
    }

    /**
     * Get large memory class (for apps with large heap enabled)
     *
     * @param context Android context
     * @return large memory class in MB
     */
    public static int getLargeMemoryClass(@NonNull Context context) {
        ActivityManager activityManager =
                (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        return activityManager.getLargeMemoryClass();
    }

    /**
     * Get formatted memory status string
     *
     * @param context Android context
     * @return formatted memory status
     */
    @NonNull
    public static String getMemoryStatus(@NonNull Context context) {
        StringBuilder sb = new StringBuilder();
        MemoryInfo deviceMem = getDeviceMemoryInfo(context);
        MemoryInfo appMem = getAppMemoryInfo();

        sb.append("Device: ").append(deviceMem.toString()).append("\n");
        sb.append("App: ").append(appMem.toString()).append("\n");
        sb.append("Native Heap: ").append(SystemHelper.formatBytes(getNativeHeapAllocatedSize()));
        sb.append(" / ").append(SystemHelper.formatBytes(getNativeHeapAllocatedSize() + getNativeHeapFreeSize()));

        return sb.toString();
    }

    /**
     * Trim memory based on level
     *
     * @param level memory trim level from onTrimMemory callback
     */
    public static void onTrimMemory(int level) {
        LoggingHelper.d(TAG, "onTrimMemory level: " + level);

        // Clear caches based on trim level
        switch (level) {
            case android.content.ComponentCallbacks2.TRIM_MEMORY_RUNNING_CRITICAL:
            case android.content.ComponentCallbacks2.TRIM_MEMORY_COMPLETE:
                // Aggressive cleanup
                CacheHelper.clearCache();
                requestGarbageCollection();
                LoggingHelper.w(TAG, "Critical memory - cleared all caches");
                break;

            case android.content.ComponentCallbacks2.TRIM_MEMORY_RUNNING_LOW:
            case android.content.ComponentCallbacks2.TRIM_MEMORY_MODERATE:
                // Moderate cleanup
                CacheHelper.clearBitmapCache();
                CacheHelper.evictExpired();
                LoggingHelper.d(TAG, "Low memory - cleared bitmap cache and expired entries");
                break;

            case android.content.ComponentCallbacks2.TRIM_MEMORY_RUNNING_MODERATE:
            case android.content.ComponentCallbacks2.TRIM_MEMORY_BACKGROUND:
            case android.content.ComponentCallbacks2.TRIM_MEMORY_UI_HIDDEN:
                // Light cleanup
                CacheHelper.evictExpired();
                break;
        }
    }

    /**
     * Read /proc/meminfo for detailed memory statistics
     *
     * @return memory info string or null on error
     */
    @Nullable
    public static String getProcMemInfo() {
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/meminfo"))) {
            StringBuilder sb = new StringBuilder();
            String line;
            int lineCount = 0;
            while ((line = reader.readLine()) != null && lineCount < 10) {
                sb.append(line).append("\n");
                lineCount++;
            }
            return sb.toString();
        } catch (IOException e) {
            LoggingHelper.e(TAG, "Failed to read /proc/meminfo", e);
            return null;
        }
    }

    private MemoryHelper() {
        // Prevent instantiation
    }
}
