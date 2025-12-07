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

import androidx.annotation.NonNull;
import org.csploit.android.helpers.LoggingHelper;
import androidx.annotation.Nullable;
import org.csploit.android.helpers.LoggingHelper;

import java.util.concurrent.Callable;
import org.csploit.android.helpers.LoggingHelper;

/**
 * RetryHelper - Utility for retrying operations with exponential backoff.
 *
 * Provides robust retry logic for network operations and other
 * failure-prone tasks with configurable retry policies.
 *
 * Usage:
 * {@code
 * String result = RetryHelper.withExponentialBackoff(() -> {
 *     return networkCall();
 * }, 4, 2000);
 * }
 */
public final class RetryHelper {

    private static final String TAG = "RetryHelper";

    /**
     * Default initial delay in milliseconds
     */
    public static final long DEFAULT_INITIAL_DELAY_MS = 1000;

    /**
     * Default maximum retries
     */
    public static final int DEFAULT_MAX_RETRIES = 3;

    /**
     * Default backoff multiplier
     */
    public static final double DEFAULT_BACKOFF_MULTIPLIER = 2.0;

    private RetryHelper() {}

    /**
     * Functional interface for retry operations
     */
    public interface RetryOperation<T> {
        T execute() throws Exception;
    }

    /**
     * Functional interface for void retry operations
     */
    public interface VoidRetryOperation {
        void execute() throws Exception;
    }

    /**
     * Callback interface for retry events
     */
    public interface RetryCallback {
        void onRetry(int attempt, int maxRetries, long delayMs, Exception lastError);
        void onSuccess(int totalAttempts);
        void onFailure(int totalAttempts, Exception lastError);
    }

    /**
     * Execute operation with exponential backoff retry.
     *
     * @param operation the operation to execute
     * @param maxRetries maximum number of retry attempts
     * @param initialDelayMs initial delay between retries in milliseconds
     * @param <T> return type
     * @return the result of the operation
     * @throws Exception if all retries fail
     */
    @Nullable
    public static <T> T withExponentialBackoff(
            @NonNull RetryOperation<T> operation,
            int maxRetries,
            long initialDelayMs) throws Exception {
        return withExponentialBackoff(operation, maxRetries, initialDelayMs, DEFAULT_BACKOFF_MULTIPLIER, null);
    }

    /**
     * Execute operation with exponential backoff retry and callback.
     *
     * @param operation the operation to execute
     * @param maxRetries maximum number of retry attempts
     * @param initialDelayMs initial delay between retries in milliseconds
     * @param backoffMultiplier multiplier for exponential backoff
     * @param callback optional callback for retry events
     * @param <T> return type
     * @return the result of the operation
     * @throws Exception if all retries fail
     */
    @Nullable
    public static <T> T withExponentialBackoff(
            @NonNull RetryOperation<T> operation,
            int maxRetries,
            long initialDelayMs,
            double backoffMultiplier,
            @Nullable RetryCallback callback) throws Exception {

        if (maxRetries < 0) maxRetries = 0;
        if (initialDelayMs < 0) initialDelayMs = 0;
        if (backoffMultiplier < 1.0) backoffMultiplier = 1.0;

        Exception lastException = null;
        long currentDelay = initialDelayMs;
        int totalAttempts = 0;

        for (int attempt = 0; attempt <= maxRetries; attempt++) {
            totalAttempts = attempt + 1;
            try {
                T result = operation.execute();
                if (callback != null) {
                    callback.onSuccess(totalAttempts);
                }
                return result;
            } catch (Exception e) {
                lastException = e;
                LoggingHelper.w(TAG, "Attempt " + totalAttempts + " failed: " + e.getMessage());

                if (attempt < maxRetries) {
                    if (callback != null) {
                        callback.onRetry(attempt + 1, maxRetries, currentDelay, e);
                    }

                    try {
                        Thread.sleep(currentDelay);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw e;
                    }

                    currentDelay = (long) (currentDelay * backoffMultiplier);
                }
            }
        }

        if (callback != null) {
            callback.onFailure(totalAttempts, lastException);
        }

        throw lastException != null ? lastException : new RuntimeException("Operation failed after " + totalAttempts + " attempts");
    }

    /**
     * Execute void operation with exponential backoff retry.
     *
     * @param operation the operation to execute
     * @param maxRetries maximum number of retry attempts
     * @param initialDelayMs initial delay between retries in milliseconds
     * @throws Exception if all retries fail
     */
    public static void executeWithRetry(
            @NonNull VoidRetryOperation operation,
            int maxRetries,
            long initialDelayMs) throws Exception {
        withExponentialBackoff(() -> {
            operation.execute();
            return null;
        }, maxRetries, initialDelayMs);
    }

    /**
     * Execute operation with simple linear retry.
     *
     * @param operation the operation to execute
     * @param maxRetries maximum number of retry attempts
     * @param delayMs fixed delay between retries in milliseconds
     * @param <T> return type
     * @return the result of the operation
     * @throws Exception if all retries fail
     */
    @Nullable
    public static <T> T withLinearBackoff(
            @NonNull RetryOperation<T> operation,
            int maxRetries,
            long delayMs) throws Exception {
        return withExponentialBackoff(operation, maxRetries, delayMs, 1.0, null);
    }

    /**
     * Execute operation with no delay between retries.
     *
     * @param operation the operation to execute
     * @param maxRetries maximum number of retry attempts
     * @param <T> return type
     * @return the result of the operation
     * @throws Exception if all retries fail
     */
    @Nullable
    public static <T> T withImmediateRetry(
            @NonNull RetryOperation<T> operation,
            int maxRetries) throws Exception {
        return withExponentialBackoff(operation, maxRetries, 0, 1.0, null);
    }

    /**
     * Execute operation with default retry policy (3 retries, 1s initial, 2x backoff).
     *
     * @param operation the operation to execute
     * @param <T> return type
     * @return the result of the operation
     * @throws Exception if all retries fail
     */
    @Nullable
    public static <T> T withDefaultRetry(@NonNull RetryOperation<T> operation) throws Exception {
        return withExponentialBackoff(operation, DEFAULT_MAX_RETRIES, DEFAULT_INITIAL_DELAY_MS, DEFAULT_BACKOFF_MULTIPLIER, null);
    }

    /**
     * Execute operation with network-optimized retry policy (4 retries, 2s initial, 2x backoff).
     * Suitable for network operations like HTTP requests, git push, etc.
     *
     * @param operation the operation to execute
     * @param <T> return type
     * @return the result of the operation
     * @throws Exception if all retries fail
     */
    @Nullable
    public static <T> T withNetworkRetry(@NonNull RetryOperation<T> operation) throws Exception {
        return withExponentialBackoff(operation, 4, 2000, 2.0, null);
    }

    /**
     * Check if an exception is retryable (typically network errors).
     *
     * @param e the exception to check
     * @return true if the exception is considered retryable
     */
    public static boolean isRetryable(@Nullable Exception e) {
        if (e == null) return false;

        String message = e.getMessage();
        if (message == null) message = "";
        message = message.toLowerCase();

        // Network-related errors
        if (e instanceof java.net.SocketTimeoutException) return true;
        if (e instanceof java.net.ConnectException) return true;
        if (e instanceof java.net.UnknownHostException) return true;
        if (e instanceof java.io.IOException && message.contains("network")) return true;
        if (message.contains("timeout")) return true;
        if (message.contains("connection reset")) return true;
        if (message.contains("connection refused")) return true;
        if (message.contains("temporarily unavailable")) return true;

        return false;
    }

    /**
     * Create a RetryCallback that logs retry events.
     *
     * @param operationName name of the operation for logging
     * @return a logging callback
     */
    @NonNull
    public static RetryCallback createLoggingCallback(@NonNull final String operationName) {
        return new RetryCallback() {
            @Override
            public void onRetry(int attempt, int maxRetries, long delayMs, Exception lastError) {
                LoggingHelper.i(TAG, operationName + " - Retry " + attempt + "/" + maxRetries +
                        ", waiting " + delayMs + "ms. Error: " + lastError.getMessage());
            }

            @Override
            public void onSuccess(int totalAttempts) {
                if (totalAttempts > 1) {
                    LoggingHelper.i(TAG, operationName + " - Succeeded after " + totalAttempts + " attempts");
                }
            }

            @Override
            public void onFailure(int totalAttempts, Exception lastError) {
                LoggingHelper.e(TAG, operationName + " - Failed after " + totalAttempts + " attempts", lastError);
            }
        };
    }
}
