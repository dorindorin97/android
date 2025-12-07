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
import org.csploit.android.helpers.LoggingHelper;
import org.csploit.android.BuildConfig;
import org.csploit.android.helpers.LoggingHelper;

import java.util.HashMap;
import org.csploit.android.helpers.LoggingHelper;
import java.util.Map;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.ConcurrentHashMap;
import org.csploit.android.helpers.LoggingHelper;

/**
 * Performance monitoring helper to track operation durations and identify bottlenecks.
 * Useful for profiling network scans, exploit detection, and other time-consuming operations.
 */
public class PerformanceMonitor {
    
    private static final String TAG = "PerformanceMonitor";
    private static final boolean ENABLED = BuildConfig.DEBUG; // Only in debug builds
    
    // Store operation start times
    private static final Map<String, Long> operationStartTimes = new ConcurrentHashMap<>();
    
    // Store operation statistics
    private static final Map<String, OperationStats> operationStats = new ConcurrentHashMap<>();
    
    /**
     * Start monitoring an operation.
     * 
     * @param operationName Unique name for the operation
     */
    public static void startOperation(@NonNull String operationName) {
        if (!ENABLED) return;
        
        operationStartTimes.put(operationName, System.currentTimeMillis());
        LoggingHelper.d(TAG, "Started: " + operationName);
    }
    
    /**
     * End monitoring an operation and log its duration.
     * 
     * @param operationName Name of the operation (must match startOperation call)
     */
    public static void endOperation(@NonNull String operationName) {
        if (!ENABLED) return;
        
        Long startTime = operationStartTimes.remove(operationName);
        if (startTime == null) {
            LoggingHelper.w(TAG, "No start time found for operation: " + operationName);
            return;
        }
        
        long duration = System.currentTimeMillis() - startTime;
        updateStats(operationName, duration);
        
        LoggingHelper.d(TAG, String.format("Completed: %s in %dms", operationName, duration));
        
        // Warn if operation took too long
        if (duration > 5000) {
            LoggingHelper.w(TAG, String.format("Slow operation detected: %s took %dms", 
                    operationName, duration));
        }
    }
    
    /**
     * Measure a runnable's execution time.
     * 
     * @param operationName Name for the operation
     * @param runnable Runnable to measure
     */
    public static void measure(@NonNull String operationName, @NonNull Runnable runnable) {
        if (!ENABLED) {
            runnable.run();
            return;
        }
        
        startOperation(operationName);
        try {
            runnable.run();
        } finally {
            endOperation(operationName);
        }
    }
    
    /**
     * Get statistics for an operation.
     * 
     * @param operationName Name of the operation
     * @return OperationStats or null if not found
     */
    public static OperationStats getStats(@NonNull String operationName) {
        return operationStats.get(operationName);
    }
    
    /**
     * Get all operation statistics.
     * 
     * @return Map of operation names to statistics
     */
    public static Map<String, OperationStats> getAllStats() {
        return new HashMap<>(operationStats);
    }
    
    /**
     * Clear all statistics.
     */
    public static void clearStats() {
        operationStats.clear();
        operationStartTimes.clear();
        LoggingHelper.d(TAG, "Performance statistics cleared");
    }
    
    /**
     * Print performance summary to log.
     */
    public static void printSummary() {
        if (!ENABLED || operationStats.isEmpty()) return;
        
        LoggingHelper.i(TAG, "=== Performance Summary ===");
        for (Map.Entry<String, OperationStats> entry : operationStats.entrySet()) {
            OperationStats stats = entry.getValue();
            LoggingHelper.i(TAG, String.format("%s: count=%d, avg=%dms, min=%dms, max=%dms",
                    entry.getKey(), stats.count, stats.getAverage(), 
                    stats.minDuration, stats.maxDuration));
        }
        LoggingHelper.i(TAG, "=========================");
    }
    
    /**
     * Update statistics for an operation.
     * 
     * @param operationName Name of the operation
     * @param duration Duration in milliseconds
     */
    private static void updateStats(@NonNull String operationName, long duration) {
        OperationStats stats = operationStats.computeIfAbsent(operationName, 
                k -> new OperationStats());
        stats.update(duration);
    }
    
    /**
     * Statistics for a monitored operation.
     */
    public static class OperationStats {
        private long count = 0;
        private long totalDuration = 0;
        private long minDuration = Long.MAX_VALUE;
        private long maxDuration = 0;
        
        synchronized void update(long duration) {
            count++;
            totalDuration += duration;
            minDuration = Math.min(minDuration, duration);
            maxDuration = Math.max(maxDuration, duration);
        }
        
        public long getCount() {
            return count;
        }
        
        public long getAverage() {
            return count > 0 ? totalDuration / count : 0;
        }
        
        public long getMinDuration() {
            return minDuration == Long.MAX_VALUE ? 0 : minDuration;
        }
        
        public long getMaxDuration() {
            return maxDuration;
        }
        
        public long getTotalDuration() {
            return totalDuration;
        }
    }
    
    private PerformanceMonitor() {
        // Prevent instantiation
    }
}
