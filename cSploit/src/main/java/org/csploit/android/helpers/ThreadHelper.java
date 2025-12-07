/*
 * This file is part of the cSploit.
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

import android.os.Handler;
import org.csploit.android.helpers.LoggingHelper;
import android.os.Looper;
import org.csploit.android.helpers.LoggingHelper;

import java.util.concurrent.Callable;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.CountDownLatch;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.Executor;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.ExecutorService;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.Executors;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.Future;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.ScheduledExecutorService;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.ScheduledFuture;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.TimeUnit;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.atomic.AtomicBoolean;
import org.csploit.android.helpers.LoggingHelper;

/**
 * Unified thread management utilities for cSploit.
 *
 * Provides:
 * - Shared thread pool for background tasks
 * - Scheduled/periodic task execution
 * - Main thread posting with delays
 * - Safe thread lifecycle management (stop, join, interrupt)
 * - Thread state utilities
 */
public final class ThreadHelper {

    private static final String TAG = "ThreadHelper";

    private static final ExecutorService EXECUTOR = Executors.newCachedThreadPool();
    private static final ScheduledExecutorService SCHEDULED_EXECUTOR =
        Executors.newScheduledThreadPool(4);
    private static final Handler MAIN_HANDLER = new Handler(Looper.getMainLooper());

    private static final long DEFAULT_STOP_TIMEOUT_MS = 5000;

    private ThreadHelper() {}

    // ==================== Executor Services ====================

    /**
     * Share an Executor among all cSploit components
     * @return an Executor for running background stuff
     */
    public static Executor getSharedExecutor() {
        return EXECUTOR;
    }

    /**
     * Get the scheduled executor for delayed/periodic tasks
     * @return ScheduledExecutorService instance
     */
    public static ScheduledExecutorService getScheduledExecutor() {
        return SCHEDULED_EXECUTOR;
    }

    /**
     * Execute a background task using the shared executor
     * @param runnable task to execute
     */
    public static void executeBackground(Runnable runnable) {
        EXECUTOR.execute(runnable);
    }

    /**
     * Submit a callable task and get a Future
     * @param callable task to submit
     * @param <T> return type
     * @return Future representing pending completion
     */
    public static <T> Future<T> submit(Callable<T> callable) {
        return EXECUTOR.submit(callable);
    }

    /**
     * Submit a runnable task and get a Future
     * @param runnable task to submit
     * @return Future representing pending completion
     */
    public static Future<?> submit(Runnable runnable) {
        return EXECUTOR.submit(runnable);
    }

    // ==================== Main Thread Operations ====================

    /**
     * Check if current thread is the main UI thread
     * @return true if on main thread
     */
    public static boolean isOnMainThread() {
        return Looper.myLooper() == Looper.getMainLooper();
    }

    /**
     * Run a task on the main UI thread
     * @param runnable task to run
     */
    public static void runOnMainThread(Runnable runnable) {
        if (isOnMainThread()) {
            runnable.run();
        } else {
            MAIN_HANDLER.post(runnable);
        }
    }

    /**
     * Run a task on the main UI thread with a delay
     * @param runnable task to run
     * @param delayMillis delay in milliseconds
     */
    public static void runOnMainThreadDelayed(Runnable runnable, long delayMillis) {
        MAIN_HANDLER.postDelayed(runnable, delayMillis);
    }

    /**
     * Cancel all pending main thread tasks
     */
    public static void cancelMainThreadTasks() {
        MAIN_HANDLER.removeCallbacksAndMessages(null);
    }

    /**
     * Remove a specific runnable from the main thread queue
     * @param runnable the runnable to remove
     */
    public static void removeFromMainThread(Runnable runnable) {
        MAIN_HANDLER.removeCallbacks(runnable);
    }

    // ==================== Scheduled Tasks ====================

    /**
     * Schedule a task to run after a delay
     * @param runnable task to run
     * @param delay delay before execution
     * @param unit time unit for delay
     * @return ScheduledFuture representing pending completion
     */
    public static ScheduledFuture<?> schedule(Runnable runnable, long delay, TimeUnit unit) {
        return SCHEDULED_EXECUTOR.schedule(runnable, delay, unit);
    }

    /**
     * Schedule a callable task to run after a delay
     * @param callable task to run
     * @param delay delay before execution
     * @param unit time unit for delay
     * @param <T> return type
     * @return ScheduledFuture representing pending completion
     */
    public static <T> ScheduledFuture<T> schedule(Callable<T> callable, long delay, TimeUnit unit) {
        return SCHEDULED_EXECUTOR.schedule(callable, delay, unit);
    }

    /**
     * Schedule a task to run periodically
     * @param runnable task to run
     * @param initialDelay initial delay before first execution
     * @param period period between executions
     * @param unit time unit for delays
     * @return ScheduledFuture representing pending completion
     */
    public static ScheduledFuture<?> scheduleAtFixedRate(Runnable runnable, long initialDelay,
                                                          long period, TimeUnit unit) {
        return SCHEDULED_EXECUTOR.scheduleAtFixedRate(runnable, initialDelay, period, unit);
    }

    /**
     * Schedule a task with fixed delay between end of one execution and start of next
     * @param runnable task to run
     * @param initialDelay initial delay before first execution
     * @param delay delay between end and start
     * @param unit time unit for delays
     * @return ScheduledFuture representing pending completion
     */
    public static ScheduledFuture<?> scheduleWithFixedDelay(Runnable runnable, long initialDelay,
                                                             long delay, TimeUnit unit) {
        return SCHEDULED_EXECUTOR.scheduleWithFixedDelay(runnable, initialDelay, delay, unit);
    }

    // ==================== Thread Lifecycle Management ====================

    /**
     * Safely stop a thread with interrupt and join.
     * Never use Thread.stop() - it's deprecated and unsafe.
     *
     * @param thread Thread to stop
     * @param timeoutMs Timeout in milliseconds for join
     * @return True if thread stopped cleanly, false if timeout occurred
     */
    public static boolean stopThread(Thread thread, long timeoutMs) {
        if (thread == null || !thread.isAlive()) {
            return true;
        }

        try {
            thread.interrupt();
            thread.join(timeoutMs);

            if (thread.isAlive()) {
                LoggingHelper.w(TAG, "Thread " + thread.getName() + " did not stop within timeout");
                return false;
            }
            return true;
        } catch (InterruptedException e) {
            LoggingHelper.d(TAG, "Thread stop interrupted: " + e.getMessage());
            Thread.currentThread().interrupt();
            return false;
        }
    }

    /**
     * Safely stop a thread with default timeout (5 seconds)
     *
     * @param thread Thread to stop
     * @return True if thread stopped cleanly
     */
    public static boolean stopThread(Thread thread) {
        return stopThread(thread, DEFAULT_STOP_TIMEOUT_MS);
    }

    /**
     * Stop multiple threads concurrently
     *
     * @param threads Threads to stop
     * @param timeoutMs Timeout for each thread
     * @return True if all threads stopped cleanly
     */
    public static boolean stopThreads(Thread[] threads, long timeoutMs) {
        if (threads == null || threads.length == 0) {
            return true;
        }

        for (Thread thread : threads) {
            if (thread != null && thread.isAlive()) {
                thread.interrupt();
            }
        }

        boolean allStopped = true;
        for (Thread thread : threads) {
            if (thread != null && thread.isAlive()) {
                try {
                    thread.join(timeoutMs);
                    if (thread.isAlive()) {
                        allStopped = false;
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
        }
        return allStopped;
    }

    // ==================== Task Execution Utilities ====================

    /**
     * Run a task on a new thread and wait for completion
     *
     * @param task Task to run
     * @param timeoutMs Timeout in milliseconds
     * @return True if task completed within timeout
     */
    public static boolean runAndWait(Runnable task, long timeoutMs) {
        if (task == null) {
            return false;
        }

        CountDownLatch latch = new CountDownLatch(1);

        Thread thread = new Thread(() -> {
            try {
                task.run();
            } finally {
                latch.countDown();
            }
        });

        thread.start();

        try {
            return latch.await(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            LoggingHelper.d(TAG, "Wait interrupted: " + e.getMessage());
            Thread.currentThread().interrupt();
            return false;
        }
    }

    /**
     * Run a task with a timeout, cancelling if it takes too long
     *
     * @param task Task to run
     * @param timeoutMs Timeout in milliseconds
     * @return True if task completed successfully within timeout
     */
    public static boolean runWithTimeout(Runnable task, long timeoutMs) {
        if (task == null) {
            return false;
        }

        AtomicBoolean completed = new AtomicBoolean(false);
        CountDownLatch latch = new CountDownLatch(1);

        Thread thread = new Thread(() -> {
            try {
                task.run();
                completed.set(true);
            } finally {
                latch.countDown();
            }
        });

        thread.start();

        try {
            if (!latch.await(timeoutMs, TimeUnit.MILLISECONDS)) {
                thread.interrupt();
                return false;
            }
            return completed.get();
        } catch (InterruptedException e) {
            thread.interrupt();
            Thread.currentThread().interrupt();
            return false;
        }
    }

    // ==================== Thread State Utilities ====================

    /**
     * Check if current thread was interrupted
     *
     * @return True if thread is interrupted
     */
    public static boolean isInterrupted() {
        return Thread.currentThread().isInterrupted();
    }

    /**
     * Check if a specific thread is alive
     *
     * @param thread Thread to check
     * @return True if thread is alive
     */
    public static boolean isAlive(Thread thread) {
        return thread != null && thread.isAlive();
    }

    /**
     * Sleep safely without throwing checked exception
     *
     * @param durationMs Duration to sleep in milliseconds
     * @return True if sleep completed, false if interrupted
     */
    public static boolean sleepSafely(long durationMs) {
        try {
            Thread.sleep(durationMs);
            return true;
        } catch (InterruptedException e) {
            LoggingHelper.d(TAG, "Sleep interrupted: " + e.getMessage());
            Thread.currentThread().interrupt();
            return false;
        }
    }

    /**
     * Sleep with interruptible support
     *
     * @param durationMs Duration to sleep in milliseconds
     * @param unit Time unit
     * @return True if sleep completed, false if interrupted
     */
    public static boolean sleepSafely(long durationMs, TimeUnit unit) {
        return sleepSafely(unit.toMillis(durationMs));
    }

    /**
     * Set thread name for debugging
     *
     * @param thread Thread to rename
     * @param name New name for the thread
     */
    public static void setThreadName(Thread thread, String name) {
        if (thread != null && name != null) {
            thread.setName(name);
        }
    }

    /**
     * Get the current thread name
     *
     * @return Current thread name
     */
    public static String getCurrentThreadName() {
        return Thread.currentThread().getName();
    }

    // ==================== Cleanup ====================

    /**
     * Shutdown all executor services gracefully.
     * Call this when the application is terminating.
     */
    public static void shutdown() {
        EXECUTOR.shutdown();
        SCHEDULED_EXECUTOR.shutdown();
        try {
            if (!EXECUTOR.awaitTermination(5, TimeUnit.SECONDS)) {
                EXECUTOR.shutdownNow();
            }
            if (!SCHEDULED_EXECUTOR.awaitTermination(5, TimeUnit.SECONDS)) {
                SCHEDULED_EXECUTOR.shutdownNow();
            }
        } catch (InterruptedException e) {
            EXECUTOR.shutdownNow();
            SCHEDULED_EXECUTOR.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
