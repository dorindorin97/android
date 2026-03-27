package org.csploit.android.helpers;

import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.util.concurrent.Callable;

/**
 * Utility class for executing operations with automatic retry logic,
 * supporting exponential, linear, and immediate retry strategies.
 */
public class RetryHelper {

    private RetryHelper() {}

    /** Callback interface for retry lifecycle events. */
    public interface RetryCallback {
        void onRetry(int attempt, int maxRetries, long delayMs, Exception lastError);
        void onSuccess(int totalAttempts);
        void onFailure(int totalAttempts, Exception lastError);
    }

    /** Callable that may throw checked exceptions. */
    @FunctionalInterface
    public interface ThrowingCallable<T> {
        T call() throws Exception;
    }

    /** Runnable that may throw checked exceptions. */
    @FunctionalInterface
    public interface ThrowingRunnable {
        void run() throws Exception;
    }

    /**
     * Execute the callable with exponential back-off retry.
     * @param callable  The operation to execute
     * @param maxRetries Maximum number of total attempts (0 = try once)
     * @param initialDelayMs Delay before first retry (ms)
     */
    public static <T> T withExponentialBackoff(ThrowingCallable<T> callable,
                                               int maxRetries,
                                               long initialDelayMs) throws Exception {
        return withExponentialBackoff(callable, maxRetries, initialDelayMs, 2.0, null);
    }

    /**
     * Execute the callable with exponential back-off retry and lifecycle callbacks.
     */
    public static <T> T withExponentialBackoff(ThrowingCallable<T> callable,
                                               int maxRetries,
                                               long initialDelayMs,
                                               double multiplier,
                                               RetryCallback callback) throws Exception {
        int totalAttempts = Math.max(1, maxRetries);
        Exception lastError = null;
        long delay = initialDelayMs;

        for (int attempt = 1; attempt <= totalAttempts; attempt++) {
            try {
                T result = callable.call();
                if (callback != null) callback.onSuccess(attempt);
                return result;
            } catch (Exception e) {
                lastError = e;
                if (attempt < totalAttempts) {
                    if (callback != null) callback.onRetry(attempt, totalAttempts, delay, e);
                    if (delay > 0) {
                        try { Thread.sleep(delay); } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                        }
                    }
                    delay = (long) (delay * multiplier);
                }
            }
        }
        if (callback != null) callback.onFailure(totalAttempts, lastError);
        throw lastError;
    }

    /**
     * Execute the callable with immediate retries (no delay between attempts).
     */
    public static <T> T withImmediateRetry(ThrowingCallable<T> callable, int maxRetries) throws Exception {
        return withExponentialBackoff(callable, maxRetries, 0, 1.0, null);
    }

    /**
     * Execute the callable with linear back-off retry (constant delay).
     */
    public static <T> T withLinearBackoff(ThrowingCallable<T> callable,
                                          int maxRetries,
                                          long delayMs) throws Exception {
        return withExponentialBackoff(callable, maxRetries, delayMs, 1.0, null);
    }

    /**
     * Execute a void operation with retry.
     */
    public static void executeWithRetry(ThrowingRunnable runnable,
                                        int maxRetries,
                                        long delayMs) throws Exception {
        withExponentialBackoff(() -> {
            runnable.run();
            return null;
        }, maxRetries, delayMs, 1.0, null);
    }

    /**
     * Return true if the exception is likely transient and worth retrying.
     */
    public static boolean isRetryable(Throwable t) {
        if (t == null) return false;
        if (t instanceof SocketTimeoutException || t instanceof ConnectException) return true;
        String msg = t.getMessage();
        if (msg != null) {
            String lower = msg.toLowerCase();
            if (lower.contains("timeout") || lower.contains("connection reset") ||
                lower.contains("timed out") || lower.contains("connection refused")) {
                return true;
            }
        }
        return false;
    }

    /** Create a RetryCallback that logs each event via LoggingHelper. */
    public static RetryCallback createLoggingCallback(String operationName) {
        return new RetryCallback() {
            @Override
            public void onRetry(int attempt, int maxRetries, long delayMs, Exception lastError) {
                LoggingHelper.w("RetryHelper", operationName + " attempt " + attempt +
                        "/" + maxRetries + " failed, retrying in " + delayMs + "ms: " +
                        (lastError != null ? lastError.getMessage() : "unknown"));
            }

            @Override
            public void onSuccess(int totalAttempts) {
                LoggingHelper.d("RetryHelper", operationName + " succeeded after " +
                        totalAttempts + " attempt(s)");
            }

            @Override
            public void onFailure(int totalAttempts, Exception lastError) {
                LoggingHelper.e("RetryHelper", operationName + " failed after " +
                        totalAttempts + " attempt(s)", lastError);
            }
        };
    }
}
