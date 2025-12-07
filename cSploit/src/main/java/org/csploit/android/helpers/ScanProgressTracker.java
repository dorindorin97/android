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
import org.csploit.android.helpers.LoggingHelper;
import android.os.Handler;
import org.csploit.android.helpers.LoggingHelper;
import android.os.Looper;
import org.csploit.android.helpers.LoggingHelper;

import androidx.annotation.NonNull;
import org.csploit.android.helpers.LoggingHelper;
import androidx.annotation.Nullable;
import org.csploit.android.helpers.LoggingHelper;

import java.util.ArrayList;
import org.csploit.android.helpers.LoggingHelper;
import java.util.List;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.CopyOnWriteArrayList;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.ExecutorService;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.Executors;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.atomic.AtomicBoolean;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.atomic.AtomicInteger;
import org.csploit.android.helpers.LoggingHelper;

/**
 * ScanProgressTracker - Track and report progress for multi-target scanning operations.
 * 
 * Provides:
 * - Progress tracking with percentage calculation
 * - Time estimation (ETA)
 * - Scan statistics collection
 * - Progress callbacks for UI updates
 * - Pause/resume support
 * - Cancel functionality
 * 
 * Usage:
 * {@code
 * ScanProgressTracker tracker = new ScanProgressTracker(totalTargets);
 * tracker.setProgressListener(progress -> {
 *     updateProgressBar(progress.getPercentage());
 *     updateEta(progress.getEstimatedTimeRemaining());
 * });
 * tracker.start();
 * 
 * // For each target scanned
 * tracker.incrementProgress();
 * 
 * // On completion
 * tracker.complete();
 * }
 */
public final class ScanProgressTracker {
    
    public static final String TAG = "ScanProgressTracker";
    
    private final int totalItems;
    private final AtomicInteger completedItems;
    private final AtomicInteger successCount;
    private final AtomicInteger failureCount;
    private final AtomicBoolean isRunning;
    private final AtomicBoolean isPaused;
    private final AtomicBoolean isCancelled;
    
    private long startTimeMs;
    private long pauseStartMs;
    private long totalPausedMs;
    
    private final List<ProgressListener> listeners;
    private final Handler mainHandler;
    private final ExecutorService executor;
    
    private String currentTask;
    private final List<ScanResult> results;
    
    /**
     * Progress listener interface.
     */
    public interface ProgressListener {
        void onProgressUpdate(ProgressInfo progress);
        void onComplete(ScanSummary summary);
        void onError(String error);
    }
    
    /**
     * Progress information snapshot.
     */
    public static class ProgressInfo {
        public final int completed;
        public final int total;
        public final int percentage;
        public final long elapsedMs;
        public final long estimatedRemainingMs;
        public final int successCount;
        public final int failureCount;
        public final String currentTask;
        public final double itemsPerSecond;
        
        public ProgressInfo(int completed, int total, long elapsedMs, long estimatedRemainingMs,
                           int successCount, int failureCount, String currentTask) {
            this.completed = completed;
            this.total = total;
            this.percentage = total > 0 ? (int) ((completed * 100L) / total) : 0;
            this.elapsedMs = elapsedMs;
            this.estimatedRemainingMs = estimatedRemainingMs;
            this.successCount = successCount;
            this.failureCount = failureCount;
            this.currentTask = currentTask;
            this.itemsPerSecond = elapsedMs > 0 ? (completed * 1000.0) / elapsedMs : 0;
        }
        
        public int getPercentage() {
            return percentage;
        }
        
        public String getEstimatedTimeRemaining() {
            return formatDuration(estimatedRemainingMs);
        }
        
        public String getElapsedTime() {
            return formatDuration(elapsedMs);
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("%d/%d (%d%%) - ETA: %s", 
                    completed, total, percentage, getEstimatedTimeRemaining());
        }
    }
    
    /**
     * Scan result for a single item.
     */
    public static class ScanResult {
        public final String target;
        public final boolean success;
        public final String message;
        public final long durationMs;
        
        public ScanResult(String target, boolean success, String message, long durationMs) {
            this.target = target;
            this.success = success;
            this.message = message;
            this.durationMs = durationMs;
        }
    }
    
    /**
     * Summary of completed scan.
     */
    public static class ScanSummary {
        public final int totalScanned;
        public final int successCount;
        public final int failureCount;
        public final long totalDurationMs;
        public final double averageItemTimeMs;
        public final List<ScanResult> results;
        public final boolean wasCancelled;
        
        public ScanSummary(int totalScanned, int successCount, int failureCount,
                         long totalDurationMs, List<ScanResult> results, boolean wasCancelled) {
            this.totalScanned = totalScanned;
            this.successCount = successCount;
            this.failureCount = failureCount;
            this.totalDurationMs = totalDurationMs;
            this.averageItemTimeMs = totalScanned > 0 ? (double) totalDurationMs / totalScanned : 0;
            this.results = results;
            this.wasCancelled = wasCancelled;
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("Scan Summary: %d scanned (%d success, %d failed) in %s",
                    totalScanned, successCount, failureCount, formatDuration(totalDurationMs));
        }
    }
    
    /**
     * Create a new progress tracker.
     * 
     * @param totalItems total number of items to process
     */
    public ScanProgressTracker(int totalItems) {
        this.totalItems = totalItems;
        this.completedItems = new AtomicInteger(0);
        this.successCount = new AtomicInteger(0);
        this.failureCount = new AtomicInteger(0);
        this.isRunning = new AtomicBoolean(false);
        this.isPaused = new AtomicBoolean(false);
        this.isCancelled = new AtomicBoolean(false);
        this.listeners = new CopyOnWriteArrayList<>();
        this.mainHandler = new Handler(Looper.getMainLooper());
        this.executor = Executors.newSingleThreadExecutor();
        this.results = new ArrayList<>();
    }
    
    /**
     * Add a progress listener.
     * 
     * @param listener listener to add
     */
    public void addProgressListener(@NonNull ProgressListener listener) {
        listeners.add(listener);
    }
    
    /**
     * Remove a progress listener.
     * 
     * @param listener listener to remove
     */
    public void removeProgressListener(@NonNull ProgressListener listener) {
        listeners.remove(listener);
    }
    
    /**
     * Start the scan tracking.
     */
    public void start() {
        if (isRunning.compareAndSet(false, true)) {
            startTimeMs = System.currentTimeMillis();
            totalPausedMs = 0;
            LoggingHelper.i(TAG, "Scan tracking started for " + totalItems + " items");
        }
    }
    
    /**
     * Pause the scan.
     */
    public void pause() {
        if (isRunning.get() && isPaused.compareAndSet(false, true)) {
            pauseStartMs = System.currentTimeMillis();
            LoggingHelper.i(TAG, "Scan paused");
        }
    }
    
    /**
     * Resume the scan.
     */
    public void resume() {
        if (isRunning.get() && isPaused.compareAndSet(true, false)) {
            totalPausedMs += System.currentTimeMillis() - pauseStartMs;
            LoggingHelper.i(TAG, "Scan resumed");
        }
    }
    
    /**
     * Cancel the scan.
     */
    public void cancel() {
        if (isCancelled.compareAndSet(false, true)) {
            LoggingHelper.i(TAG, "Scan cancelled");
            notifyComplete();
        }
    }
    
    /**
     * Check if scan is cancelled.
     */
    public boolean isCancelled() {
        return isCancelled.get();
    }
    
    /**
     * Check if scan is paused.
     */
    public boolean isPaused() {
        return isPaused.get();
    }
    
    /**
     * Check if scan is running.
     */
    public boolean isRunning() {
        return isRunning.get() && !isCancelled.get();
    }
    
    /**
     * Set current task description.
     * 
     * @param task task description
     */
    public void setCurrentTask(@Nullable String task) {
        this.currentTask = task;
    }
    
    /**
     * Increment progress by one (success).
     */
    public void incrementProgress() {
        incrementProgress(true);
    }
    
    /**
     * Increment progress by one with success/failure flag.
     * 
     * @param success whether the item was processed successfully
     */
    public void incrementProgress(boolean success) {
        if (!isRunning.get() || isCancelled.get()) return;
        
        int completed = completedItems.incrementAndGet();
        if (success) {
            successCount.incrementAndGet();
        } else {
            failureCount.incrementAndGet();
        }
        
        notifyProgress();
        
        if (completed >= totalItems) {
            complete();
        }
    }
    
    /**
     * Add a scan result.
     * 
     * @param result scan result to add
     */
    public void addResult(@NonNull ScanResult result) {
        synchronized (results) {
            results.add(result);
        }
        incrementProgress(result.success);
    }
    
    /**
     * Mark scan as complete.
     */
    public void complete() {
        if (isRunning.compareAndSet(true, false)) {
            LoggingHelper.i(TAG, "Scan tracking completed");
            notifyComplete();
        }
    }
    
    /**
     * Get current progress info.
     */
    @NonNull
    public ProgressInfo getProgressInfo() {
        int completed = completedItems.get();
        long elapsedMs = getElapsedMs();
        long estimatedRemaining = calculateEstimatedRemaining(completed, elapsedMs);
        
        return new ProgressInfo(
                completed, totalItems, elapsedMs, estimatedRemaining,
                successCount.get(), failureCount.get(), currentTask
        );
    }
    
    /**
     * Get elapsed time in milliseconds (excluding paused time).
     */
    private long getElapsedMs() {
        if (!isRunning.get() && startTimeMs == 0) return 0;
        
        long elapsed = System.currentTimeMillis() - startTimeMs - totalPausedMs;
        if (isPaused.get()) {
            elapsed -= (System.currentTimeMillis() - pauseStartMs);
        }
        return Math.max(0, elapsed);
    }
    
    /**
     * Calculate estimated time remaining.
     */
    private long calculateEstimatedRemaining(int completed, long elapsedMs) {
        if (completed == 0 || elapsedMs == 0) {
            return -1; // Unknown
        }
        
        int remaining = totalItems - completed;
        double msPerItem = (double) elapsedMs / completed;
        return (long) (remaining * msPerItem);
    }
    
    /**
     * Notify listeners of progress update.
     */
    private void notifyProgress() {
        ProgressInfo info = getProgressInfo();
        mainHandler.post(() -> {
            for (ProgressListener listener : listeners) {
                try {
                    listener.onProgressUpdate(info);
                } catch (Exception e) {
                    LoggingHelper.e(TAG, "Error in progress listener", e);
                }
            }
        });
    }
    
    /**
     * Notify listeners of completion.
     */
    private void notifyComplete() {
        List<ScanResult> resultsCopy;
        synchronized (results) {
            resultsCopy = new ArrayList<>(results);
        }
        
        ScanSummary summary = new ScanSummary(
                completedItems.get(),
                successCount.get(),
                failureCount.get(),
                getElapsedMs(),
                resultsCopy,
                isCancelled.get()
        );
        
        mainHandler.post(() -> {
            for (ProgressListener listener : listeners) {
                try {
                    listener.onComplete(summary);
                } catch (Exception e) {
                    LoggingHelper.e(TAG, "Error in completion listener", e);
                }
            }
        });
    }
    
    /**
     * Format duration in human-readable format.
     */
    @NonNull
    private static String formatDuration(long ms) {
        if (ms < 0) return "Unknown";
        if (ms < 1000) return ms + "ms";
        
        long seconds = ms / 1000;
        long minutes = seconds / 60;
        long hours = minutes / 60;
        
        seconds %= 60;
        minutes %= 60;
        
        if (hours > 0) {
            return String.format("%dh %dm %ds", hours, minutes, seconds);
        } else if (minutes > 0) {
            return String.format("%dm %ds", minutes, seconds);
        } else {
            return String.format("%ds", seconds);
        }
    }
    
    /**
     * Reset the tracker for reuse.
     */
    public void reset() {
        completedItems.set(0);
        successCount.set(0);
        failureCount.set(0);
        isRunning.set(false);
        isPaused.set(false);
        isCancelled.set(false);
        startTimeMs = 0;
        totalPausedMs = 0;
        currentTask = null;
        synchronized (results) {
            results.clear();
        }
    }
    
    /**
     * Shutdown the executor.
     */
    public void shutdown() {
        executor.shutdownNow();
    }
}
