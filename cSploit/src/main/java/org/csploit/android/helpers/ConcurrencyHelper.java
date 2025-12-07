package org.csploit.android.helpers;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * Utility class for concurrent operations and threading helpers.
 * Provides methods for executing tasks asynchronously with callbacks.
 */
public final class ConcurrencyHelper {

    private static final ExecutorService BACKGROUND_EXECUTOR = 
            Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors() + 1);
    
    private static final ExecutorService IO_EXECUTOR = 
            Executors.newFixedThreadPool(Math.max(2, Runtime.getRuntime().availableProcessors() / 2));

    /**
     * Callback interface for async operations with result and error handling
     */
    public interface AsyncCallback<T> {
        /**
         * Called when the operation completes successfully
         * @param result the result of the operation
         */
        void onSuccess(T result);

        /**
         * Called when the operation fails
         * @param error the exception that occurred
         */
        void onError(Exception error);

        /**
         * Called when the operation is cancelled
         */
        void onCancelled();
    }

    /**
     * Execute a task in background with callback
     */
    public static <T> void executeAsync(
            @NonNull Callable<T> task,
            @NonNull AsyncCallback<T> callback) {
        
        BACKGROUND_EXECUTOR.execute(() -> {
            try {
                T result = task.call();
                ThreadHelper.runOnMainThread(() -> callback.onSuccess(result));
            } catch (Exception e) {
                ThreadHelper.runOnMainThread(() -> callback.onError(e));
            }
        });
    }

    /**
     * Execute an I/O bound task in background with callback
     */
    public static <T> void executeIOAsync(
            @NonNull Callable<T> task,
            @NonNull AsyncCallback<T> callback) {
        
        IO_EXECUTOR.execute(() -> {
            try {
                T result = task.call();
                ThreadHelper.runOnMainThread(() -> callback.onSuccess(result));
            } catch (Exception e) {
                ThreadHelper.runOnMainThread(() -> callback.onError(e));
            }
        });
    }

    /**
     * Execute a task and get a Future for manual completion handling
     */
    public static <T> Future<T> submitAsync(@NonNull Callable<T> task) {
        return BACKGROUND_EXECUTOR.submit(task);
    }

    /**
     * Execute an I/O task and get a Future for manual completion handling
     */
    public static <T> Future<T> submitIOAsync(@NonNull Callable<T> task) {
        return IO_EXECUTOR.submit(task);
    }

    /**
     * Execute a task with retry logic
     */
    public static <T> void executeWithRetry(
            @NonNull Callable<T> task,
            @NonNull AsyncCallback<T> callback,
            int maxRetries) {
        
        executeWithRetry(task, callback, maxRetries, 1000);
    }

    /**
     * Execute a task with retry logic and delay between retries
     */
    public static <T> void executeWithRetry(
            @NonNull Callable<T> task,
            @NonNull AsyncCallback<T> callback,
            int maxRetries,
            long retryDelayMs) {
        
        BACKGROUND_EXECUTOR.execute(() -> {
            Exception lastError = null;
            
            for (int attempt = 0; attempt < maxRetries; attempt++) {
                try {
                    T result = task.call();
                    ThreadHelper.runOnMainThread(() -> callback.onSuccess(result));
                    return;
                } catch (Exception e) {
                    lastError = e;
                    
                    if (attempt < maxRetries - 1) {
                        try {
                            Thread.sleep(retryDelayMs);
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                            ThreadHelper.runOnMainThread(callback::onCancelled);
                            return;
                        }
                    }
                }
            }
            
            if (lastError != null) {
                final Exception error = lastError;
                ThreadHelper.runOnMainThread(() -> callback.onError(error));
            }
        });
    }

    /**
     * Execute a task with timeout
     */
    public static <T> void executeWithTimeout(
            @NonNull Callable<T> task,
            @NonNull AsyncCallback<T> callback,
            long timeoutMs) {
        
        BACKGROUND_EXECUTOR.execute(() -> {
            Future<T> future = BACKGROUND_EXECUTOR.submit(task);
            
            try {
                T result = future.get(timeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS);
                ThreadHelper.runOnMainThread(() -> callback.onSuccess(result));
            } catch (java.util.concurrent.TimeoutException e) {
                future.cancel(true);
                ThreadHelper.runOnMainThread(() -> 
                    callback.onError(new Exception("Operation timed out after " + timeoutMs + "ms")));
            } catch (Exception e) {
                ThreadHelper.runOnMainThread(() -> callback.onError(e));
            }
        });
    }

    /**
     * Shutdown all executors (should be called on app exit)
     */
    public static void shutdown() {
        BACKGROUND_EXECUTOR.shutdown();
        IO_EXECUTOR.shutdown();
    }
}
