package org.csploit.android.helpers;

import android.os.Handler;
import android.os.Looper;

import java.util.concurrent.Callable;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Help cSploit dealing with threads.
 * 
 * Provides:
 * - Shared thread pool for background tasks
 * - Scheduled task execution
 * - Main thread posting
 * - Thread safety utilities
 */
public final class ThreadHelper {

  private static final ExecutorService EXECUTOR = Executors.newCachedThreadPool();
  private static final ScheduledExecutorService SCHEDULED_EXECUTOR = 
      Executors.newScheduledThreadPool(2);
  private static final Handler MAIN_HANDLER = new Handler(Looper.getMainLooper());

  private ThreadHelper() {}

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
   * Execute a background task
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
   * Schedule a task to run after a delay
   * @param runnable task to run
   * @param delay delay before execution
   * @param unit time unit for delay
   * @return Future representing pending completion
   */
  public static Future<?> schedule(Runnable runnable, long delay, TimeUnit unit) {
    return SCHEDULED_EXECUTOR.schedule(runnable, delay, unit);
  }

  /**
   * Schedule a task to run periodically
   * @param runnable task to run
   * @param initialDelay initial delay before first execution
   * @param period period between executions
   * @param unit time unit for delays
   * @return Future representing pending completion
   */
  public static Future<?> scheduleAtFixedRate(Runnable runnable, long initialDelay, 
                                               long period, TimeUnit unit) {
    return SCHEDULED_EXECUTOR.scheduleAtFixedRate(runnable, initialDelay, period, unit);
  }

  /**
   * Cancel all pending main thread tasks
   */
  public static void cancelMainThreadTasks() {
    MAIN_HANDLER.removeCallbacksAndMessages(null);
  }
}
