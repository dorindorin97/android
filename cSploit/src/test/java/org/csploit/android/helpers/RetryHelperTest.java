package org.csploit.android.helpers;

import org.junit.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

/**
 * Unit tests for RetryHelper
 */
public class RetryHelperTest {

    @Test
    public void testSuccessOnFirstAttempt() throws Exception {
        String result = RetryHelper.withExponentialBackoff(() -> "success", 3, 100);
        assertEquals("success", result);
    }

    @Test
    public void testSuccessAfterRetries() throws Exception {
        AtomicInteger attempts = new AtomicInteger(0);

        String result = RetryHelper.withExponentialBackoff(() -> {
            if (attempts.incrementAndGet() < 3) {
                throw new RuntimeException("Temporary failure");
            }
            return "success";
        }, 3, 10);

        assertEquals("success", result);
        assertEquals(3, attempts.get());
    }

    @Test(expected = RuntimeException.class)
    public void testAllRetriesFail() throws Exception {
        RetryHelper.withExponentialBackoff(() -> {
            throw new RuntimeException("Always fails");
        }, 2, 10);
    }

    @Test
    public void testWithImmediateRetry() throws Exception {
        AtomicInteger attempts = new AtomicInteger(0);

        String result = RetryHelper.withImmediateRetry(() -> {
            if (attempts.incrementAndGet() < 2) {
                throw new RuntimeException("Temporary failure");
            }
            return "success";
        }, 3);

        assertEquals("success", result);
        assertEquals(2, attempts.get());
    }

    @Test
    public void testWithLinearBackoff() throws Exception {
        AtomicInteger attempts = new AtomicInteger(0);

        String result = RetryHelper.withLinearBackoff(() -> {
            if (attempts.incrementAndGet() < 2) {
                throw new RuntimeException("Temporary failure");
            }
            return "success";
        }, 3, 10);

        assertEquals("success", result);
        assertEquals(2, attempts.get());
    }

    @Test
    public void testIsRetryable() {
        assertTrue(RetryHelper.isRetryable(new java.net.SocketTimeoutException()));
        assertTrue(RetryHelper.isRetryable(new java.net.ConnectException()));
        assertTrue(RetryHelper.isRetryable(new RuntimeException("Connection timeout")));
        assertTrue(RetryHelper.isRetryable(new RuntimeException("connection reset")));

        assertFalse(RetryHelper.isRetryable(null));
        assertFalse(RetryHelper.isRetryable(new IllegalArgumentException("Invalid input")));
    }

    @Test
    public void testExecuteWithRetryVoid() throws Exception {
        AtomicInteger counter = new AtomicInteger(0);

        RetryHelper.executeWithRetry(() -> {
            if (counter.incrementAndGet() < 2) {
                throw new RuntimeException("Temporary failure");
            }
        }, 3, 10);

        assertEquals(2, counter.get());
    }

    @Test
    public void testZeroRetries() throws Exception {
        String result = RetryHelper.withExponentialBackoff(() -> "success", 0, 100);
        assertEquals("success", result);
    }

    @Test(expected = RuntimeException.class)
    public void testZeroRetriesWithFailure() throws Exception {
        RetryHelper.withExponentialBackoff(() -> {
            throw new RuntimeException("Fails");
        }, 0, 100);
    }

    @Test
    public void testCallbackOnSuccess() throws Exception {
        AtomicInteger successCalls = new AtomicInteger(0);
        AtomicInteger failureCalls = new AtomicInteger(0);
        AtomicInteger retryCalls = new AtomicInteger(0);

        RetryHelper.RetryCallback callback = new RetryHelper.RetryCallback() {
            @Override
            public void onRetry(int attempt, int maxRetries, long delayMs, Exception lastError) {
                retryCalls.incrementAndGet();
            }

            @Override
            public void onSuccess(int totalAttempts) {
                successCalls.incrementAndGet();
            }

            @Override
            public void onFailure(int totalAttempts, Exception lastError) {
                failureCalls.incrementAndGet();
            }
        };

        RetryHelper.withExponentialBackoff(() -> "success", 3, 10, 2.0, callback);

        assertEquals(1, successCalls.get());
        assertEquals(0, failureCalls.get());
        assertEquals(0, retryCalls.get());
    }

    @Test
    public void testCallbackOnRetryThenSuccess() throws Exception {
        AtomicInteger attempts = new AtomicInteger(0);
        AtomicInteger retryCalls = new AtomicInteger(0);
        AtomicInteger successCalls = new AtomicInteger(0);

        RetryHelper.RetryCallback callback = new RetryHelper.RetryCallback() {
            @Override
            public void onRetry(int attempt, int maxRetries, long delayMs, Exception lastError) {
                retryCalls.incrementAndGet();
            }

            @Override
            public void onSuccess(int totalAttempts) {
                successCalls.incrementAndGet();
            }

            @Override
            public void onFailure(int totalAttempts, Exception lastError) {}
        };

        RetryHelper.withExponentialBackoff(() -> {
            if (attempts.incrementAndGet() < 3) {
                throw new RuntimeException("Fail");
            }
            return "success";
        }, 4, 10, 2.0, callback);

        assertEquals(2, retryCalls.get());
        assertEquals(1, successCalls.get());
    }

    @Test
    public void testLoggingCallback() {
        RetryHelper.RetryCallback callback = RetryHelper.createLoggingCallback("TestOperation");
        assertNotNull(callback);

        // Should not throw
        callback.onRetry(1, 3, 1000, new RuntimeException("Test"));
        callback.onSuccess(2);
        callback.onFailure(3, new RuntimeException("Test"));
    }
}
