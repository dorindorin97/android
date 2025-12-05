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

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Safe thread management utilities.
 * Provides helper methods for proper thread lifecycle management.
 */
public class SafeThreadHelper {
    private static final String TAG = "SafeThreadHelper";

    /**
     * Safely stop a thread with interrupt and join
     * Never use Thread.stop() - it's deprecated and unsafe
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
            // Signal the thread to stop
            thread.interrupt();

            // Wait for thread to finish
            thread.join(timeoutMs);

            // Check if thread is still alive
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
        return stopThread(thread, 5000);
    }

    /**
     * Run a task on a specific thread and wait for completion
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
     */
    public static void sleepSafely(long durationMs) {
        try {
            Thread.sleep(durationMs);
        } catch (InterruptedException e) {
            LoggingHelper.d(TAG, "Sleep interrupted: " + e.getMessage());
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Set thread name for debugging
     *
     * @param thread Thread to rename
     * @param name New name for the thread
     */
    public static void setThreadName(Thread thread, String name) {
        if (thread != null) {
            thread.setName(name);
        }
    }
}
