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

import android.os.Handler;
import android.os.Looper;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Helper class for executing tasks on the main thread.
 * Provides easy-to-use utilities for UI thread operations.
 */
public class MainThreadHelper {
    
    private static final String TAG = "MainThreadHelper";
    private static final Handler mainHandler = new Handler(Looper.getMainLooper());
    private static final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    
    /**
     * Check if current thread is the main thread.
     * 
     * @return true if on main thread
     */
    public static boolean isMainThread() {
        return Looper.myLooper() == Looper.getMainLooper();
    }
    
    /**
     * Run a task on the main thread.
     * If already on main thread, runs immediately.
     * 
     * @param runnable Task to run
     */
    public static void runOnMainThread(@NonNull Runnable runnable) {
        if (isMainThread()) {
            runnable.run();
        } else {
            mainHandler.post(runnable);
        }
    }
    
    /**
     * Post a task to main thread (always posts, even if on main thread).
     * 
     * @param runnable Task to post
     */
    public static void post(@NonNull Runnable runnable) {
        mainHandler.post(runnable);
    }
    
    /**
     * Post a delayed task to main thread.
     * 
     * @param runnable Task to run
     * @param delayMillis Delay in milliseconds
     */
    public static void postDelayed(@NonNull Runnable runnable, long delayMillis) {
        mainHandler.postDelayed(runnable, delayMillis);
    }
    
    /**
     * Remove callbacks for a runnable from main handler.
     * 
     * @param runnable Runnable to remove
     */
    public static void removeCallbacks(@NonNull Runnable runnable) {
        mainHandler.removeCallbacks(runnable);
    }
    
    /**
     * Remove all callbacks and messages from main handler.
     */
    public static void removeAllCallbacks() {
        mainHandler.removeCallbacksAndMessages(null);
    }
    
    /**
     * Run a task on main thread and wait for completion (blocking).
     * Do not call from main thread!
     * 
     * @param runnable Task to run
     * @throws IllegalStateException if called from main thread
     */
    public static void runOnMainThreadBlocking(@NonNull Runnable runnable) {
        if (isMainThread()) {
            throw new IllegalStateException("Cannot call runOnMainThreadBlocking from main thread");
        }
        
        final AtomicBoolean done = new AtomicBoolean(false);
        final Object lock = new Object();
        
        mainHandler.post(() -> {
            try {
                runnable.run();
            } finally {
                synchronized (lock) {
                    done.set(true);
                    lock.notifyAll();
                }
            }
        });
        
        synchronized (lock) {
            while (!done.get()) {
                try {
                    lock.wait();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }
    }
    
    /**
     * Execute a callable on the main thread and return result.
     * 
     * @param callable Callable to execute
     * @param <T> Return type
     * @return Result from callable, or null if execution fails
     */
    @Nullable
    public static <T> T callOnMainThread(@NonNull Callable<T> callable) {
        if (isMainThread()) {
            try {
                return callable.call();
            } catch (Exception e) {
                LoggingHelper.e(TAG, "Error executing callable on main thread", e);
                return null;
            }
        }
        
        final Object[] result = new Object[1];
        final AtomicBoolean done = new AtomicBoolean(false);
        final Object lock = new Object();
        
        mainHandler.post(() -> {
            try {
                result[0] = callable.call();
            } catch (Exception e) {
                LoggingHelper.e(TAG, "Error executing callable on main thread", e);
                result[0] = null;
            } finally {
                synchronized (lock) {
                    done.set(true);
                    lock.notifyAll();
                }
            }
        });
        
        synchronized (lock) {
            while (!done.get()) {
                try {
                    lock.wait();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return null;
                }
            }
        }
        
        @SuppressWarnings("unchecked")
        T typedResult = (T) result[0];
        return typedResult;
    }
    
    /**
     * Schedule a repeating task on main thread.
     * 
     * @param runnable Task to run
     * @param initialDelayMillis Initial delay
     * @param periodMillis Period between executions
     * @return ScheduledFuture that can be used to cancel the task
     */
    @NonNull
    public static ScheduledFuture<?> scheduleAtFixedRate(@NonNull Runnable runnable, 
                                                          long initialDelayMillis, 
                                                          long periodMillis) {
        return scheduler.scheduleAtFixedRate(() -> {
            mainHandler.post(runnable);
        }, initialDelayMillis, periodMillis, TimeUnit.MILLISECONDS);
    }
    
    /**
     * Schedule a one-time task on main thread.
     * 
     * @param runnable Task to run
     * @param delayMillis Delay before execution
     * @return ScheduledFuture that can be used to cancel the task
     */
    @NonNull
    public static ScheduledFuture<?> schedule(@NonNull Runnable runnable, long delayMillis) {
        return scheduler.schedule(() -> {
            mainHandler.post(runnable);
        }, delayMillis, TimeUnit.MILLISECONDS);
    }
    
    /**
     * Get the main thread handler.
     * 
     * @return Main thread Handler
     */
    @NonNull
    public static Handler getMainHandler() {
        return mainHandler;
    }
    
    /**
     * Assert that current thread is main thread.
     * Throws exception if not.
     * 
     * @throws IllegalStateException if not on main thread
     */
    public static void assertMainThread() {
        if (!isMainThread()) {
            throw new IllegalStateException("Must be called on main thread");
        }
    }
    
    /**
     * Assert that current thread is NOT main thread.
     * Throws exception if on main thread.
     * 
     * @throws IllegalStateException if on main thread
     */
    public static void assertNotMainThread() {
        if (isMainThread()) {
            throw new IllegalStateException("Must not be called on main thread");
        }
    }
    
    private MainThreadHelper() {
        // Prevent instantiation
    }
}
