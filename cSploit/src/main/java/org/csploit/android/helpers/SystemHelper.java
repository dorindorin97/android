package org.csploit.android.helpers;

import android.app.ActivityManager;
import android.content.Context;
import android.os.Debug;
import android.os.Environment;
import android.os.StatFs;

import androidx.annotation.NonNull;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.text.DecimalFormat;

/**
 * System information utility helper for device resources and memory management.
 * 
 * Features:
 * - Memory usage (heap, native, total)
 * - Storage information (internal, external, free space)
 * - CPU information
 * - Runtime statistics
 * - Memory pressure detection
 * - Low memory warnings
 * 
 * Example:
 * <pre>
 * long freeMemory = SystemHelper.getFreeMemory(context);
 * long totalStorage = SystemHelper.getTotalInternalStorage();
 * if (SystemHelper.isLowMemory(context)) {
 *     // Free resources or show warning
 * }
 * String formatted = SystemHelper.formatBytes(freeMemory); // "256.5 MB"
 * </pre>
 */
public final class SystemHelper {
    private static final String TAG = "SystemHelper";
    
    // Memory thresholds
    private static final long CRITICAL_MEMORY_THRESHOLD = 10 * 1024 * 1024;  // 10 MB
    private static final long LOW_MEMORY_THRESHOLD = 50 * 1024 * 1024;       // 50 MB
    
    /**
     * Get total device RAM
     * 
     * @param context Android context
     * @return total RAM in bytes
     */
    public static long getTotalMemory(@NonNull Context context) {
        ActivityManager.MemoryInfo memInfo = new ActivityManager.MemoryInfo();
        ActivityManager am = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        
        if (am == null) {
            return 0;
        }
        
        am.getMemoryInfo(memInfo);
        return memInfo.totalMem;
    }
    
    /**
     * Get available device RAM
     * 
     * @param context Android context
     * @return available RAM in bytes
     */
    public static long getAvailableMemory(@NonNull Context context) {
        ActivityManager.MemoryInfo memInfo = new ActivityManager.MemoryInfo();
        ActivityManager am = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        
        if (am == null) {
            return 0;
        }
        
        am.getMemoryInfo(memInfo);
        return memInfo.availMem;
    }
    
    /**
     * Get used device RAM
     * 
     * @param context Android context
     * @return used RAM in bytes
     */
    public static long getUsedMemory(@NonNull Context context) {
        return getTotalMemory(context) - getAvailableMemory(context);
    }
    
    /**
     * Get free device RAM
     * 
     * @param context Android context
     * @return free RAM in bytes
     */
    public static long getFreeMemory(@NonNull Context context) {
        return getAvailableMemory(context);
    }
    
    /**
     * Get native heap size
     * 
     * @return native heap size in bytes
     */
    public static long getNativeHeapSize() {
        return Debug.getNativeHeapAllocated();
    }
    
    /**
     * Get Java heap size
     * 
     * @return Java heap size in bytes
     */
    public static long getJavaHeapSize() {
        Runtime rt = Runtime.getRuntime();
        return rt.totalMemory() - rt.freeMemory();
    }
    
    /**
     * Get max available heap size
     * 
     * @return max heap size in bytes
     */
    public static long getMaxHeapSize() {
        return Runtime.getRuntime().maxMemory();
    }
    
    /**
     * Check if device is low on memory
     * 
     * @param context Android context
     * @return true if available memory is below threshold
     */
    public static boolean isLowMemory(@NonNull Context context) {
        return getAvailableMemory(context) < LOW_MEMORY_THRESHOLD;
    }
    
    /**
     * Check if device is critically low on memory
     * 
     * @param context Android context
     * @return true if available memory is critically low
     */
    public static boolean isCriticalMemory(@NonNull Context context) {
        return getAvailableMemory(context) < CRITICAL_MEMORY_THRESHOLD;
    }
    
    /**
     * Get memory usage percentage
     * 
     * @param context Android context
     * @return percentage 0-100
     */
    public static int getMemoryUsagePercent(@NonNull Context context) {
        long total = getTotalMemory(context);
        if (total == 0) return 0;
        long used = getUsedMemory(context);
        return (int) ((used * 100) / total);
    }
    
    /**
     * Get total internal storage space
     * 
     * @return total internal storage in bytes
     */
    public static long getTotalInternalStorage() {
        try {
            StatFs stat = new StatFs(Environment.getDataDirectory().getAbsolutePath());
            return stat.getTotalBytes();
        } catch (Exception e) {
            LoggingHelper.w(TAG, "Error getting total internal storage", e);
            return 0;
        }
    }
    
    /**
     * Get free internal storage space
     * 
     * @return free internal storage in bytes
     */
    public static long getFreeInternalStorage() {
        try {
            StatFs stat = new StatFs(Environment.getDataDirectory().getAbsolutePath());
            return stat.getFreeBytes();
        } catch (Exception e) {
            LoggingHelper.w(TAG, "Error getting free internal storage", e);
            return 0;
        }
    }
    
    /**
     * Get used internal storage space
     * 
     * @return used internal storage in bytes
     */
    public static long getUsedInternalStorage() {
        long total = getTotalInternalStorage();
        long free = getFreeInternalStorage();
        return Math.max(0, total - free);
    }
    
    /**
     * Get total external storage space
     * 
     * @return total external storage in bytes
     */
    public static long getTotalExternalStorage() {
        try {
            if (!isExternalStorageAvailable()) {
                return 0;
            }
            StatFs stat = new StatFs(Environment.getExternalStorageDirectory().getAbsolutePath());
            return stat.getTotalBytes();
        } catch (Exception e) {
            LoggingHelper.w(TAG, "Error getting total external storage", e);
            return 0;
        }
    }
    
    /**
     * Get free external storage space
     * 
     * @return free external storage in bytes
     */
    public static long getFreeExternalStorage() {
        try {
            if (!isExternalStorageAvailable()) {
                return 0;
            }
            StatFs stat = new StatFs(Environment.getExternalStorageDirectory().getAbsolutePath());
            return stat.getFreeBytes();
        } catch (Exception e) {
            LoggingHelper.w(TAG, "Error getting free external storage", e);
            return 0;
        }
    }
    
    /**
     * Check if external storage is available
     * 
     * @return true if external storage is mounted and accessible
     */
    public static boolean isExternalStorageAvailable() {
        String state = Environment.getExternalStorageState();
        return Environment.MEDIA_MOUNTED.equals(state);
    }
    
    /**
     * Check if external storage is writable
     * 
     * @return true if external storage can be written to
     */
    public static boolean isExternalStorageWritable() {
        return isExternalStorageAvailable();
    }
    
    /**
     * Check if external storage is readable
     * 
     * @return true if external storage can be read from
     */
    public static boolean isExternalStorageReadable() {
        String state = Environment.getExternalStorageState();
        return Environment.MEDIA_MOUNTED.equals(state) || 
               Environment.MEDIA_MOUNTED_READ_ONLY.equals(state);
    }
    
    /**
     * Get internal storage usage percentage
     * 
     * @return percentage 0-100
     */
    public static int getInternalStorageUsagePercent() {
        long total = getTotalInternalStorage();
        if (total == 0) return 0;
        long used = getUsedInternalStorage();
        return (int) ((used * 100) / total);
    }
    
    /**
     * Get external storage usage percentage
     * 
     * @return percentage 0-100
     */
    public static int getExternalStorageUsagePercent() {
        long total = getTotalExternalStorage();
        if (total == 0) return 0;
        long free = getFreeExternalStorage();
        long used = total - free;
        return (int) ((used * 100) / total);
    }
    
    /**
     * Get number of CPU cores
     * 
     * @return number of available CPU cores
     */
    public static int getCpuCoreCount() {
        return Runtime.getRuntime().availableProcessors();
    }
    
    /**
     * Get CPU frequency in MHz
     * 
     * @return CPU frequency, or 0 if unavailable
     */
    public static long getCpuFrequency() {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(new java.io.FileInputStream(
                        "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq")))) {
            String line = reader.readLine();

            if (line != null) {
                return Long.parseLong(line.trim()) / 1000;  // Convert to MHz
            }
        } catch (IOException e) {
            LoggingHelper.d(TAG, "CPU frequency not available", e);
        }

        return 0;
    }
    
    /**
     * Format bytes to human-readable format
     * 
     * @param bytes number of bytes
     * @return formatted string (e.g., "256.5 MB")
     */
    public static String formatBytes(long bytes) {
        if (bytes <= 0) return "0 B";
        
        final String[] units = new String[]{"B", "KB", "MB", "GB", "TB"};
        int digitGroups = (int) (Math.log10(bytes) / Math.log10(1024));
        
        if (digitGroups >= units.length) {
            digitGroups = units.length - 1;
        }
        
        return new DecimalFormat("#,##0.#").format(bytes / Math.pow(1024, digitGroups)) 
                + " " + units[digitGroups];
    }
    
    /**
     * Get system memory info as formatted string
     * 
     * @param context Android context
     * @return formatted memory info
     */
    public static String getMemoryInfo(@NonNull Context context) {
        return String.format(
            "Total: %s | Used: %s | Free: %s | Usage: %d%%",
            formatBytes(getTotalMemory(context)),
            formatBytes(getUsedMemory(context)),
            formatBytes(getFreeMemory(context)),
            getMemoryUsagePercent(context)
        );
    }
    
    /**
     * Get system storage info as formatted string
     * 
     * @return formatted storage info
     */
    public static String getStorageInfo() {
        return String.format(
            "Internal - Total: %s | Free: %s | Usage: %d%% | External - Total: %s | Free: %s | Usage: %d%%",
            formatBytes(getTotalInternalStorage()),
            formatBytes(getFreeInternalStorage()),
            getInternalStorageUsagePercent(),
            formatBytes(getTotalExternalStorage()),
            formatBytes(getFreeExternalStorage()),
            getExternalStorageUsagePercent()
        );
    }
    
    /**
     * Get system info summary
     * 
     * @param context Android context
     * @return formatted system info
     */
    public static String getSystemInfo(@NonNull Context context) {
        return String.format(
            "CPU Cores: %d | Memory: %s | Storage: %s",
            getCpuCoreCount(),
            getMemoryInfo(context),
            getStorageInfo()
        );
    }
}
