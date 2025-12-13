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
import androidx.annotation.Nullable;

import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * CircuitBreakerHelper - Fault tolerance pattern for network operations.
 *
 * Implements the Circuit Breaker pattern to prevent cascading failures
 * and allow graceful degradation when services are unavailable.
 *
 * States:
 * - CLOSED: Normal operation, requests pass through
 * - OPEN: Failures exceeded threshold, requests fail fast
 * - HALF_OPEN: Testing if service recovered, limited requests allowed
 *
 * Usage:
 * {@code
 * CircuitBreaker breaker = CircuitBreakerHelper.create("network-service")
 *     .failureThreshold(5)
 *     .resetTimeout(30000)
 *     .build();
 *
 * String result = breaker.execute(() -> fetchFromNetwork());
 *
 * // Or use global instance
 * String result = CircuitBreakerHelper.execute("api-service", () -> callApi());
 * }
 */
public final class CircuitBreakerHelper {

    private static final String TAG = "CircuitBreakerHelper";
    private static final Map<String, CircuitBreaker> breakers = new ConcurrentHashMap<>();

    private CircuitBreakerHelper() {}

    /**
     * Circuit breaker states.
     */
    public enum State {
        CLOSED,     // Normal operation
        OPEN,       // Failing fast
        HALF_OPEN   // Testing recovery
    }

    /**
     * Exception thrown when circuit is open.
     */
    public static class CircuitOpenException extends RuntimeException {
        private final String circuitName;
        private final long remainingTimeMs;

        public CircuitOpenException(String circuitName, long remainingTimeMs) {
            super("Circuit '" + circuitName + "' is OPEN. Retry in " + remainingTimeMs + "ms");
            this.circuitName = circuitName;
            this.remainingTimeMs = remainingTimeMs;
        }

        public String getCircuitName() { return circuitName; }
        public long getRemainingTimeMs() { return remainingTimeMs; }
    }

    /**
     * Circuit breaker implementation.
     */
    public static class CircuitBreaker {
        private final String name;
        private final int failureThreshold;
        private final long resetTimeoutMs;
        private final long halfOpenTimeoutMs;
        private final int halfOpenMaxCalls;

        private final AtomicReference<State> state = new AtomicReference<>(State.CLOSED);
        private final AtomicInteger failureCount = new AtomicInteger(0);
        private final AtomicInteger successCount = new AtomicInteger(0);
        private final AtomicLong lastFailureTime = new AtomicLong(0);
        private final AtomicInteger halfOpenCalls = new AtomicInteger(0);
        private final AtomicInteger totalCalls = new AtomicInteger(0);
        private final AtomicInteger totalFailures = new AtomicInteger(0);

        private CircuitBreaker(String name, int failureThreshold, long resetTimeoutMs,
                long halfOpenTimeoutMs, int halfOpenMaxCalls) {
            this.name = name;
            this.failureThreshold = failureThreshold;
            this.resetTimeoutMs = resetTimeoutMs;
            this.halfOpenTimeoutMs = halfOpenTimeoutMs;
            this.halfOpenMaxCalls = halfOpenMaxCalls;
        }

        /**
         * Execute operation through circuit breaker.
         */
        @Nullable
        public <T> T execute(@NonNull Callable<T> operation) throws Exception {
            totalCalls.incrementAndGet();

            if (!canExecute()) {
                long remaining = getRemainingResetTime();
                throw new CircuitOpenException(name, remaining);
            }

            try {
                T result = operation.call();
                onSuccess();
                return result;
            } catch (Exception e) {
                onFailure(e);
                throw e;
            }
        }

        /**
         * Execute operation with fallback.
         */
        @Nullable
        public <T> T executeWithFallback(@NonNull Callable<T> operation, @NonNull Callable<T> fallback) {
            try {
                return execute(operation);
            } catch (CircuitOpenException e) {
                LoggingHelper.d(TAG, "Circuit open, using fallback: " + e.getMessage());
                try {
                    return fallback.call();
                } catch (Exception fallbackError) {
                    LoggingHelper.w(TAG, "Fallback also failed: " + fallbackError.getMessage());
                    return null;
                }
            } catch (Exception e) {
                LoggingHelper.d(TAG, "Operation failed, using fallback: " + e.getMessage());
                try {
                    return fallback.call();
                } catch (Exception fallbackError) {
                    LoggingHelper.w(TAG, "Fallback also failed: " + fallbackError.getMessage());
                    return null;
                }
            }
        }

        /**
         * Check if execution is allowed.
         */
        public boolean canExecute() {
            State currentState = state.get();

            if (currentState == State.CLOSED) {
                return true;
            }

            if (currentState == State.OPEN) {
                if (shouldAttemptReset()) {
                    if (state.compareAndSet(State.OPEN, State.HALF_OPEN)) {
                        halfOpenCalls.set(0);
                        LoggingHelper.i(TAG, "Circuit '" + name + "' transitioning to HALF_OPEN");
                    }
                    return true;
                }
                return false;
            }

            // HALF_OPEN - allow limited calls
            return halfOpenCalls.incrementAndGet() <= halfOpenMaxCalls;
        }

        /**
         * Record successful call.
         */
        private void onSuccess() {
            State currentState = state.get();

            if (currentState == State.HALF_OPEN) {
                successCount.incrementAndGet();
                if (successCount.get() >= halfOpenMaxCalls) {
                    reset();
                    LoggingHelper.i(TAG, "Circuit '" + name + "' recovered, now CLOSED");
                }
            } else if (currentState == State.CLOSED) {
                // Reset failure count on success
                failureCount.set(0);
            }
        }

        /**
         * Record failed call.
         */
        private void onFailure(Exception e) {
            totalFailures.incrementAndGet();
            lastFailureTime.set(java.lang.System.currentTimeMillis());

            State currentState = state.get();

            if (currentState == State.HALF_OPEN) {
                // Any failure in half-open reopens the circuit
                if (state.compareAndSet(State.HALF_OPEN, State.OPEN)) {
                    LoggingHelper.w(TAG, "Circuit '" + name + "' reopened due to failure in HALF_OPEN");
                }
            } else if (currentState == State.CLOSED) {
                int failures = failureCount.incrementAndGet();
                if (failures >= failureThreshold) {
                    if (state.compareAndSet(State.CLOSED, State.OPEN)) {
                        LoggingHelper.w(TAG, "Circuit '" + name + "' opened after " + failures + " failures");
                    }
                }
            }
        }

        /**
         * Check if we should attempt to reset.
         */
        private boolean shouldAttemptReset() {
            long timeSinceLastFailure = java.lang.System.currentTimeMillis() - lastFailureTime.get();
            return timeSinceLastFailure >= resetTimeoutMs;
        }

        /**
         * Get remaining time until reset attempt.
         */
        public long getRemainingResetTime() {
            long elapsed = java.lang.System.currentTimeMillis() - lastFailureTime.get();
            return Math.max(0, resetTimeoutMs - elapsed);
        }

        /**
         * Reset the circuit breaker.
         */
        public void reset() {
            state.set(State.CLOSED);
            failureCount.set(0);
            successCount.set(0);
            halfOpenCalls.set(0);
        }

        /**
         * Force the circuit open.
         */
        public void forceOpen() {
            state.set(State.OPEN);
            lastFailureTime.set(java.lang.System.currentTimeMillis());
        }

        // Getters
        public String getName() { return name; }
        public State getState() { return state.get(); }
        public int getFailureCount() { return failureCount.get(); }
        public int getTotalCalls() { return totalCalls.get(); }
        public int getTotalFailures() { return totalFailures.get(); }

        @NonNull
        @Override
        public String toString() {
            return String.format("CircuitBreaker{name='%s', state=%s, failures=%d/%d}",
                    name, state.get(), failureCount.get(), failureThreshold);
        }
    }

    /**
     * Circuit breaker builder.
     */
    public static class Builder {
        private final String name;
        private int failureThreshold = 5;
        private long resetTimeoutMs = 30000;
        private long halfOpenTimeoutMs = 10000;
        private int halfOpenMaxCalls = 3;

        private Builder(@NonNull String name) {
            this.name = name;
        }

        @NonNull
        public Builder failureThreshold(int threshold) {
            this.failureThreshold = Math.max(1, threshold);
            return this;
        }

        @NonNull
        public Builder resetTimeout(long timeoutMs) {
            this.resetTimeoutMs = Math.max(1000, timeoutMs);
            return this;
        }

        @NonNull
        public Builder halfOpenTimeout(long timeoutMs) {
            this.halfOpenTimeoutMs = timeoutMs;
            return this;
        }

        @NonNull
        public Builder halfOpenMaxCalls(int maxCalls) {
            this.halfOpenMaxCalls = Math.max(1, maxCalls);
            return this;
        }

        @NonNull
        public CircuitBreaker build() {
            return new CircuitBreaker(name, failureThreshold, resetTimeoutMs,
                    halfOpenTimeoutMs, halfOpenMaxCalls);
        }
    }

    /**
     * Create a new circuit breaker builder.
     */
    @NonNull
    public static Builder create(@NonNull String name) {
        return new Builder(name);
    }

    /**
     * Get or create a named circuit breaker.
     */
    @NonNull
    public static CircuitBreaker getOrCreate(@NonNull String name) {
        return breakers.computeIfAbsent(name, k -> create(k).build());
    }

    /**
     * Get or create with custom configuration.
     */
    @NonNull
    public static CircuitBreaker getOrCreate(@NonNull String name, int failureThreshold, long resetTimeoutMs) {
        return breakers.computeIfAbsent(name, k -> create(k)
                .failureThreshold(failureThreshold)
                .resetTimeout(resetTimeoutMs)
                .build());
    }

    /**
     * Execute through a named circuit breaker.
     */
    @Nullable
    public static <T> T execute(@NonNull String name, @NonNull Callable<T> operation) throws Exception {
        return getOrCreate(name).execute(operation);
    }

    /**
     * Execute with fallback through a named circuit breaker.
     */
    @Nullable
    public static <T> T executeWithFallback(@NonNull String name,
            @NonNull Callable<T> operation, @NonNull Callable<T> fallback) {
        return getOrCreate(name).executeWithFallback(operation, fallback);
    }

    /**
     * Check if a circuit is open.
     */
    public static boolean isOpen(@NonNull String name) {
        CircuitBreaker breaker = breakers.get(name);
        return breaker != null && breaker.getState() == State.OPEN;
    }

    /**
     * Reset a named circuit breaker.
     */
    public static void reset(@NonNull String name) {
        CircuitBreaker breaker = breakers.get(name);
        if (breaker != null) {
            breaker.reset();
        }
    }

    /**
     * Reset all circuit breakers.
     */
    public static void resetAll() {
        for (CircuitBreaker breaker : breakers.values()) {
            breaker.reset();
        }
    }

    /**
     * Get all circuit breaker states (for monitoring).
     */
    @NonNull
    public static Map<String, State> getAllStates() {
        Map<String, State> states = new ConcurrentHashMap<>();
        for (Map.Entry<String, CircuitBreaker> entry : breakers.entrySet()) {
            states.put(entry.getKey(), entry.getValue().getState());
        }
        return states;
    }

    /**
     * Remove a circuit breaker.
     */
    public static void remove(@NonNull String name) {
        breakers.remove(name);
    }

    /**
     * Clear all circuit breakers.
     */
    public static void clear() {
        breakers.clear();
    }
}
