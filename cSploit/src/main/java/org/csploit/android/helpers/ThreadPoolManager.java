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

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Manages thread pool and concurrent task execution.
 * Provides safe thread management with proper lifecycle handling.
 */
public class ThreadPoolManager {
    private static final String TAG = "ThreadPoolManager";
    private static final int CORE_POOL_SIZE = Runtime.getRuntime().availableProcessors();
    private static final long SHUTDOWN_TIMEOUT = 10;

    private static ThreadPoolManager instance;
    private ExecutorService mExecutorService;

    private ThreadPoolManager() {
        mExecutorService = Executors.newFixedThreadPool(CORE_POOL_SIZE, new ThreadFactory() {
            private final AtomicInteger count = new AtomicInteger(0);

            @Override
            public Thread newThread(Runnable r) {
                Thread t = new Thread(r, "cSploit-" + count.incrementAndGet());
                t.setDaemon(false);
                return t;
            }
        });
    }

    /**
     * Get singleton instance
     */
    public static synchronized ThreadPoolManager getInstance() {
        if (instance == null) {
            instance = new ThreadPoolManager();
        }
        return instance;
    }

    /**
     * Submit a task for asynchronous execution
     *
     * @param task The runnable task to execute
     * @return Future representing the submitted task
     */
    public Future<?> submit(Runnable task) {
        return mExecutorService.submit(task);
    }

    /**
     * Submit a task for asynchronous execution with result
     *
     * @param task The callable task to execute
     * @return Future representing the submitted task with result
     */
    public <T> Future<T> submit(java.util.concurrent.Callable<T> task) {
        return mExecutorService.submit(task);
    }

    /**
     * Submit a task to run on background thread
     *
     * @param runnable Task to run
     */
    public void executeAsync(Runnable runnable) {
        submit(runnable);
    }

    /**
     * Cancel a future task
     *
     * @param future The future to cancel
     * @param mayInterruptIfRunning Whether to interrupt if running
     * @return True if task was cancelled
     */
    public boolean cancelTask(Future<?> future, boolean mayInterruptIfRunning) {
        if (future != null) {
            return future.cancel(mayInterruptIfRunning);
        }
        return false;
    }

    /**
     * Wait for a task to complete
     *
     * @param future The future to wait for
     * @param timeout Timeout in milliseconds
     * @return True if task completed, false if timeout occurred
     */
    public boolean waitForTask(Future<?> future, long timeout) {
        if (future == null) {
            return false;
        }

        try {
            future.get(timeout, TimeUnit.MILLISECONDS);
            return true;
        } catch (Exception e) {
            LoggingHelper.d(TAG, "Task wait interrupted or timeout: " + e.getMessage());
            return false;
        }
    }

    /**
     * Shutdown the thread pool gracefully
     */
    public void shutdown() {
        try {
            mExecutorService.shutdown();
            if (!mExecutorService.awaitTermination(SHUTDOWN_TIMEOUT, TimeUnit.SECONDS)) {
                LoggingHelper.w(TAG, "Thread pool did not terminate in time, forcing shutdown");
                mExecutorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            LoggingHelper.e(TAG, "Thread pool shutdown interrupted", e);
            mExecutorService.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Check if thread pool is active
     */
    public boolean isActive() {
        return mExecutorService != null && !mExecutorService.isShutdown();
    }

    /**
     * Get number of active threads
     */
    public int getActiveThreadCount() {
        return CORE_POOL_SIZE;
    }
}
