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

import android.os.Handler;
import android.os.Looper;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * TimeoutHelper - Centralized timeout management and execution utilities.
 *
 * Provides:
 * - Configurable timeout presets
 * - Timeout-wrapped execution
 * - Delayed task scheduling
 * - Debouncing and throttling
 * - Timeout monitoring and cancellation
 *
 * Usage:
 * {@code
 * // Execute with timeout
 * String result = TimeoutHelper.executeWithTimeout(() -> {
 *     return fetchData();
 * }, 5000);
 *
 * // Schedule delayed task
 * TimeoutHelper.scheduleDelayed(() -> refreshUI(), 2000);
 *
 * // Debounce rapid calls
 * Runnable debounced = TimeoutHelper.debounce(() -> search(query), 300);
 * }
 */
public final class TimeoutHelper {

    private static final String TAG = "TimeoutHelper";

    // Timeout presets (in milliseconds)
    public static final int TIMEOUT_IMMEDIATE = 100;
    public static final int TIMEOUT_QUICK = 1000;
    public static final int TIMEOUT_SHORT = 3000;
    public static final int TIMEOUT_NORMAL = 5000;
    public static final int TIMEOUT_MEDIUM = 10000;
    public static final int TIMEOUT_LONG = 30000;
    public static final int TIMEOUT_VERY_LONG = 60000;
    public static final int TIMEOUT_EXTENDED = 120000;

    // Network-specific timeouts
    public static final int CONNECT_TIMEOUT = 5000;
    public static final int READ_TIMEOUT = 10000;
    public static final int WRITE_TIMEOUT = 10000;
    public static final int PING_TIMEOUT = 3000;
    public static final int DNS_TIMEOUT = 5000;
    public static final int PORT_SCAN_TIMEOUT = 2000;
    public static final int BANNER_GRAB_TIMEOUT = 5000;

    // Thread pools
    private static final ExecutorService executor = Executors.newCachedThreadPool();
    private static final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);
    private static final Handler mainHandler = new Handler(Looper.getMainLooper());

    // Tracking for debounce/throttle
    private static final Map<String, ScheduledFuture<?>> debounceMap = new ConcurrentHashMap<>();
    private static final Map<String, Long> throttleMap = new ConcurrentHashMap<>();
    private static final AtomicInteger taskCounter = new AtomicInteger(0);

    private TimeoutHelper() {}

    /**
     * Result wrapper for timeout operations.
     */
    public static class TimeoutResult<T> {
        public final T value;
        public final boolean timedOut;
        public final boolean success;
        public final Exception error;
        public final long executionTimeMs;

        private TimeoutResult(T value, boolean timedOut, boolean success, Exception error, long executionTimeMs) {
            this.value = value;
            this.timedOut = timedOut;
            this.success = success;
            this.error = error;
            this.executionTimeMs = executionTimeMs;
        }

        public static <T> TimeoutResult<T> success(T value, long timeMs) {
            return new TimeoutResult<>(value, false, true, null, timeMs);
        }

        public static <T> TimeoutResult<T> timeout(long timeMs) {
            return new TimeoutResult<>(null, true, false, null, timeMs);
        }

        public static <T> TimeoutResult<T> error(Exception e, long timeMs) {
            return new TimeoutResult<>(null, false, false, e, timeMs);
        }
    }

    /**
     * Execute a callable with timeout, returning the result or null on timeout.
     */
    @Nullable
    public static <T> T executeWithTimeout(@NonNull Callable<T> callable, int timeoutMs) throws Exception {
        TimeoutResult<T> result = executeWithTimeoutResult(callable, timeoutMs);
        if (result.timedOut) {
            throw new TimeoutException("Operation timed out after " + timeoutMs + "ms");
        }
        if (result.error != null) {
            throw result.error;
        }
        return result.value;
    }

    /**
     * Execute a callable with timeout, returning a result wrapper.
     */
    @NonNull
    public static <T> TimeoutResult<T> executeWithTimeoutResult(@NonNull Callable<T> callable, int timeoutMs) {
        long startTime = java.lang.System.currentTimeMillis();
        Future<T> future = executor.submit(callable);

        try {
            T result = future.get(timeoutMs, TimeUnit.MILLISECONDS);
            return TimeoutResult.success(result, java.lang.System.currentTimeMillis() - startTime);
        } catch (TimeoutException e) {
            future.cancel(true);
            return TimeoutResult.timeout(java.lang.System.currentTimeMillis() - startTime);
        } catch (Exception e) {
            future.cancel(true);
            return TimeoutResult.error(e, java.lang.System.currentTimeMillis() - startTime);
        }
    }

    /**
     * Execute a runnable with timeout.
     */
    public static boolean executeWithTimeout(@NonNull Runnable runnable, int timeoutMs) {
        Future<?> future = executor.submit(runnable);
        try {
            future.get(timeoutMs, TimeUnit.MILLISECONDS);
            return true;
        } catch (TimeoutException e) {
            future.cancel(true);
            return false;
        } catch (Exception e) {
            future.cancel(true);
            LoggingHelper.w(TAG, "Task execution failed", e);
            return false;
        }
    }

    /**
     * Schedule a task to run after a delay.
     */
    @NonNull
    public static ScheduledFuture<?> scheduleDelayed(@NonNull Runnable runnable, int delayMs) {
        return scheduler.schedule(runnable, delayMs, TimeUnit.MILLISECONDS);
    }

    /**
     * Schedule a task to run on the main thread after a delay.
     */
    public static void scheduleOnMainThread(@NonNull Runnable runnable, int delayMs) {
        mainHandler.postDelayed(runnable, delayMs);
    }

    /**
     * Post a task to run on the main thread immediately.
     */
    public static void postOnMainThread(@NonNull Runnable runnable) {
        mainHandler.post(runnable);
    }

    /**
     * Schedule a task to run repeatedly.
     */
    @NonNull
    public static ScheduledFuture<?> scheduleRepeating(@NonNull Runnable runnable, int initialDelayMs, int periodMs) {
        return scheduler.scheduleAtFixedRate(runnable, initialDelayMs, periodMs, TimeUnit.MILLISECONDS);
    }

    /**
     * Create a debounced version of a runnable.
     * Only executes after the specified delay if no new calls are made.
     */
    @NonNull
    public static Runnable debounce(@NonNull String key, @NonNull Runnable runnable, int delayMs) {
        return () -> {
            // Cancel previous scheduled execution
            ScheduledFuture<?> previous = debounceMap.get(key);
            if (previous != null && !previous.isDone()) {
                previous.cancel(false);
            }

            // Schedule new execution
            ScheduledFuture<?> future = scheduler.schedule(runnable, delayMs, TimeUnit.MILLISECONDS);
            debounceMap.put(key, future);
        };
    }

    /**
     * Create a debounced runnable with auto-generated key.
     */
    @NonNull
    public static Runnable debounce(@NonNull Runnable runnable, int delayMs) {
        String key = "debounce_" + taskCounter.incrementAndGet();
        return debounce(key, runnable, delayMs);
    }

    /**
     * Create a throttled version of a runnable.
     * Executes at most once per specified interval.
     */
    @NonNull
    public static Runnable throttle(@NonNull String key, @NonNull Runnable runnable, int intervalMs) {
        return () -> {
            long now = java.lang.System.currentTimeMillis();
            Long lastExecution = throttleMap.get(key);

            if (lastExecution == null || (now - lastExecution) >= intervalMs) {
                throttleMap.put(key, now);
                runnable.run();
            }
        };
    }

    /**
     * Create a throttled runnable with auto-generated key.
     */
    @NonNull
    public static Runnable throttle(@NonNull Runnable runnable, int intervalMs) {
        String key = "throttle_" + taskCounter.incrementAndGet();
        return throttle(key, runnable, intervalMs);
    }

    /**
     * Cancel all pending debounced tasks for a key.
     */
    public static void cancelDebounce(@NonNull String key) {
        ScheduledFuture<?> future = debounceMap.remove(key);
        if (future != null && !future.isDone()) {
            future.cancel(false);
        }
    }

    /**
     * Reset throttle for a key, allowing immediate execution.
     */
    public static void resetThrottle(@NonNull String key) {
        throttleMap.remove(key);
    }

    /**
     * Execute with retry on failure.
     */
    @Nullable
    public static <T> T executeWithRetry(@NonNull Callable<T> callable, int maxRetries, int timeoutMs) {
        return executeWithRetry(callable, maxRetries, timeoutMs, 0);
    }

    /**
     * Execute with retry and delay between retries.
     */
    @Nullable
    public static <T> T executeWithRetry(@NonNull Callable<T> callable, int maxRetries, int timeoutMs, int retryDelayMs) {
        Exception lastError = null;

        for (int attempt = 0; attempt <= maxRetries; attempt++) {
            try {
                TimeoutResult<T> result = executeWithTimeoutResult(callable, timeoutMs);
                if (result.success) {
                    return result.value;
                }
                if (result.error != null) {
                    lastError = result.error;
                }
            } catch (Exception e) {
                lastError = e;
            }

            if (attempt < maxRetries && retryDelayMs > 0) {
                try {
                    Thread.sleep(retryDelayMs);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }

        LoggingHelper.w(TAG, "All retry attempts failed", lastError);
        return null;
    }

    /**
     * Execute with exponential backoff retry.
     */
    @Nullable
    public static <T> T executeWithExponentialBackoff(@NonNull Callable<T> callable, int maxRetries,
            int timeoutMs, int initialDelayMs, int maxDelayMs) {
        Exception lastError = null;
        int delay = initialDelayMs;

        for (int attempt = 0; attempt <= maxRetries; attempt++) {
            try {
                TimeoutResult<T> result = executeWithTimeoutResult(callable, timeoutMs);
                if (result.success) {
                    return result.value;
                }
                if (result.error != null) {
                    lastError = result.error;
                }
            } catch (Exception e) {
                lastError = e;
            }

            if (attempt < maxRetries) {
                try {
                    Thread.sleep(delay);
                    delay = Math.min(delay * 2, maxDelayMs);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }

        LoggingHelper.w(TAG, "Exponential backoff retry failed", lastError);
        return null;
    }

    /**
     * Wait for condition with timeout.
     */
    public static boolean waitForCondition(@NonNull Callable<Boolean> condition, int timeoutMs, int pollIntervalMs) {
        long deadline = java.lang.System.currentTimeMillis() + timeoutMs;

        while (java.lang.System.currentTimeMillis() < deadline) {
            try {
                if (Boolean.TRUE.equals(condition.call())) {
                    return true;
                }
                Thread.sleep(pollIntervalMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            } catch (Exception e) {
                LoggingHelper.d(TAG, "Condition check failed: " + e.getMessage());
            }
        }

        return false;
    }

    /**
     * Create a timeout watchdog that calls a callback if operation exceeds time limit.
     */
    @NonNull
    public static ScheduledFuture<?> createWatchdog(int timeoutMs, @NonNull Runnable onTimeout) {
        return scheduler.schedule(onTimeout, timeoutMs, TimeUnit.MILLISECONDS);
    }

    /**
     * Get appropriate timeout based on network conditions.
     */
    public static int getAdaptiveTimeout(int baseTimeoutMs, @NonNull NetworkQuality quality) {
        switch (quality) {
            case EXCELLENT:
                return baseTimeoutMs;
            case GOOD:
                return (int) (baseTimeoutMs * 1.5);
            case MODERATE:
                return baseTimeoutMs * 2;
            case POOR:
                return baseTimeoutMs * 3;
            case VERY_POOR:
                return baseTimeoutMs * 5;
            default:
                return baseTimeoutMs * 2;
        }
    }

    /**
     * Network quality levels for adaptive timeouts.
     */
    public enum NetworkQuality {
        EXCELLENT,  // < 50ms latency
        GOOD,       // 50-100ms
        MODERATE,   // 100-200ms
        POOR,       // 200-500ms
        VERY_POOR   // > 500ms
    }

    /**
     * Cleanup resources. Call on app shutdown.
     */
    public static void shutdown() {
        executor.shutdown();
        scheduler.shutdown();
        debounceMap.clear();
        throttleMap.clear();
    }
}
