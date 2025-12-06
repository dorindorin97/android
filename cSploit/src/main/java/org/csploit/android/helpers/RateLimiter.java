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

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * RateLimiter - Rate limiting utility for scan operations
 *
 * Provides:
 * - Token bucket rate limiting
 * - Sliding window rate limiting
 * - Per-target rate limiting
 * - Adaptive rate limiting based on response times
 * - Rate limiting statistics
 *
 * Usage:
 * {@code
 * RateLimiter limiter = RateLimiter.create(100); // 100 permits per second
 * if (limiter.tryAcquire()) {
 *     // Perform operation
 * }
 * // Or blocking
 * limiter.acquire();
 * // Perform operation
 * }
 */
public final class RateLimiter {

    private static final String TAG = "RateLimiter";

    private final double permitsPerSecond;
    private final long maxBurstPermits;
    private double storedPermits;
    private long nextFreeTicketMicros;
    private final Object mutex = new Object();

    // Statistics
    private final AtomicLong totalRequests = new AtomicLong(0);
    private final AtomicLong grantedRequests = new AtomicLong(0);
    private final AtomicLong deniedRequests = new AtomicLong(0);
    private final AtomicLong waitTimeNanos = new AtomicLong(0);

    /**
     * Create a rate limiter with specified permits per second
     *
     * @param permitsPerSecond the number of permits per second
     */
    private RateLimiter(double permitsPerSecond) {
        this(permitsPerSecond, (long) permitsPerSecond);
    }

    /**
     * Create a rate limiter with specified permits per second and burst size
     *
     * @param permitsPerSecond the number of permits per second
     * @param maxBurstPermits  maximum number of permits that can be accumulated
     */
    private RateLimiter(double permitsPerSecond, long maxBurstPermits) {
        if (permitsPerSecond <= 0) {
            throw new IllegalArgumentException("Permits per second must be positive");
        }
        this.permitsPerSecond = permitsPerSecond;
        this.maxBurstPermits = maxBurstPermits;
        this.storedPermits = 0;
        this.nextFreeTicketMicros = System.nanoTime() / 1000;
    }

    /**
     * Create a rate limiter with specified permits per second
     */
    @NonNull
    public static RateLimiter create(double permitsPerSecond) {
        return new RateLimiter(permitsPerSecond);
    }

    /**
     * Create a rate limiter with specified permits per second and burst size
     */
    @NonNull
    public static RateLimiter create(double permitsPerSecond, long maxBurstPermits) {
        return new RateLimiter(permitsPerSecond, maxBurstPermits);
    }

    /**
     * Create a rate limiter for a specific number of requests per time window
     */
    @NonNull
    public static RateLimiter create(int requests, long duration, TimeUnit unit) {
        double permitsPerSecond = requests / (double) unit.toSeconds(duration);
        return new RateLimiter(Math.max(permitsPerSecond, 0.001));
    }

    /**
     * Acquire a permit, blocking if necessary
     *
     * @return time waited in seconds
     */
    public double acquire() {
        return acquire(1);
    }

    /**
     * Acquire multiple permits, blocking if necessary
     *
     * @param permits number of permits to acquire
     * @return time waited in seconds
     */
    public double acquire(int permits) {
        long waitMicros = reserveAndGetWait(permits);
        totalRequests.incrementAndGet();
        grantedRequests.incrementAndGet();

        if (waitMicros > 0) {
            waitTimeNanos.addAndGet(waitMicros * 1000);
            sleepMicros(waitMicros);
        }

        return waitMicros / 1_000_000.0;
    }

    /**
     * Try to acquire a permit without blocking
     *
     * @return true if permit was acquired
     */
    public boolean tryAcquire() {
        return tryAcquire(1, 0, TimeUnit.MICROSECONDS);
    }

    /**
     * Try to acquire a permit with timeout
     *
     * @param timeout maximum time to wait
     * @param unit    time unit
     * @return true if permit was acquired
     */
    public boolean tryAcquire(long timeout, TimeUnit unit) {
        return tryAcquire(1, timeout, unit);
    }

    /**
     * Try to acquire multiple permits with timeout
     *
     * @param permits number of permits
     * @param timeout maximum time to wait
     * @param unit    time unit
     * @return true if permits were acquired
     */
    public boolean tryAcquire(int permits, long timeout, TimeUnit unit) {
        totalRequests.incrementAndGet();
        long timeoutMicros = unit.toMicros(timeout);

        synchronized (mutex) {
            long nowMicros = System.nanoTime() / 1000;
            long waitMicros = reserveEarliestAvailable(permits, nowMicros);

            if (waitMicros > timeoutMicros) {
                deniedRequests.incrementAndGet();
                return false;
            }

            grantedRequests.incrementAndGet();

            if (waitMicros > 0) {
                waitTimeNanos.addAndGet(waitMicros * 1000);
                sleepMicros(waitMicros);
            }

            return true;
        }
    }

    /**
     * Get the current rate (permits per second)
     */
    public double getRate() {
        return permitsPerSecond;
    }

    /**
     * Update the rate
     */
    public void setRate(double permitsPerSecond) {
        throw new UnsupportedOperationException("Rate modification not supported after creation");
    }

    /**
     * Get statistics
     */
    @NonNull
    public RateLimiterStats getStats() {
        return new RateLimiterStats(
                totalRequests.get(),
                grantedRequests.get(),
                deniedRequests.get(),
                waitTimeNanos.get()
        );
    }

    /**
     * Reset statistics
     */
    public void resetStats() {
        totalRequests.set(0);
        grantedRequests.set(0);
        deniedRequests.set(0);
        waitTimeNanos.set(0);
    }

    private long reserveAndGetWait(int permits) {
        synchronized (mutex) {
            long nowMicros = System.nanoTime() / 1000;
            return reserveEarliestAvailable(permits, nowMicros);
        }
    }

    private long reserveEarliestAvailable(int permits, long nowMicros) {
        resync(nowMicros);

        long returnValue = Math.max(0, nextFreeTicketMicros - nowMicros);

        double storedPermitsToSpend = Math.min(permits, storedPermits);
        double freshPermits = permits - storedPermitsToSpend;

        long waitMicros = (long) (freshPermits * 1_000_000.0 / permitsPerSecond);

        nextFreeTicketMicros += waitMicros;
        storedPermits -= storedPermitsToSpend;

        return returnValue;
    }

    private void resync(long nowMicros) {
        if (nowMicros > nextFreeTicketMicros) {
            double newPermits = (nowMicros - nextFreeTicketMicros) * permitsPerSecond / 1_000_000.0;
            storedPermits = Math.min(maxBurstPermits, storedPermits + newPermits);
            nextFreeTicketMicros = nowMicros;
        }
    }

    private void sleepMicros(long micros) {
        if (micros > 0) {
            try {
                TimeUnit.MICROSECONDS.sleep(micros);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    // ==================== Statistics Class ====================

    /**
     * Rate limiter statistics
     */
    public static class RateLimiterStats {
        private final long totalRequests;
        private final long grantedRequests;
        private final long deniedRequests;
        private final long waitTimeNanos;

        RateLimiterStats(long total, long granted, long denied, long waitNanos) {
            this.totalRequests = total;
            this.grantedRequests = granted;
            this.deniedRequests = denied;
            this.waitTimeNanos = waitNanos;
        }

        public long getTotalRequests() { return totalRequests; }
        public long getGrantedRequests() { return grantedRequests; }
        public long getDeniedRequests() { return deniedRequests; }
        public long getWaitTimeNanos() { return waitTimeNanos; }

        public double getGrantRate() {
            return totalRequests > 0 ? (double) grantedRequests / totalRequests : 0;
        }

        public double getAverageWaitMs() {
            return grantedRequests > 0 ? (waitTimeNanos / 1_000_000.0) / grantedRequests : 0;
        }

        @NonNull
        @Override
        public String toString() {
            return String.format("RateLimiterStats[total=%d, granted=%d, denied=%d, avgWait=%.2fms]",
                    totalRequests, grantedRequests, deniedRequests, getAverageWaitMs());
        }
    }

    // ==================== Per-Key Rate Limiter ====================

    /**
     * Per-key rate limiter for rate limiting per target/resource
     */
    public static class PerKeyRateLimiter<K> {
        private final double permitsPerSecond;
        private final Map<K, RateLimiter> limiters = new ConcurrentHashMap<>();

        public PerKeyRateLimiter(double permitsPerSecond) {
            this.permitsPerSecond = permitsPerSecond;
        }

        @NonNull
        public static <K> PerKeyRateLimiter<K> create(double permitsPerSecond) {
            return new PerKeyRateLimiter<>(permitsPerSecond);
        }

        public double acquire(@NonNull K key) {
            return getLimiter(key).acquire();
        }

        public boolean tryAcquire(@NonNull K key) {
            return getLimiter(key).tryAcquire();
        }

        public boolean tryAcquire(@NonNull K key, long timeout, TimeUnit unit) {
            return getLimiter(key).tryAcquire(timeout, unit);
        }

        @NonNull
        private RateLimiter getLimiter(@NonNull K key) {
            return limiters.computeIfAbsent(key, k -> RateLimiter.create(permitsPerSecond));
        }

        public void remove(@NonNull K key) {
            limiters.remove(key);
        }

        public void clear() {
            limiters.clear();
        }

        public int size() {
            return limiters.size();
        }
    }

    // ==================== Adaptive Rate Limiter ====================

    /**
     * Adaptive rate limiter that adjusts based on response times
     */
    public static class AdaptiveRateLimiter {
        private static final double MIN_RATE = 1.0;
        private static final double MAX_RATE = 1000.0;
        private static final double INCREASE_FACTOR = 1.1;
        private static final double DECREASE_FACTOR = 0.5;

        private volatile double currentRate;
        private volatile RateLimiter limiter;
        private final long targetLatencyMs;
        private final Object mutex = new Object();

        public AdaptiveRateLimiter(double initialRate, long targetLatencyMs) {
            this.currentRate = Math.max(MIN_RATE, Math.min(MAX_RATE, initialRate));
            this.targetLatencyMs = targetLatencyMs;
            this.limiter = RateLimiter.create(currentRate);
        }

        @NonNull
        public static AdaptiveRateLimiter create(double initialRate, long targetLatencyMs) {
            return new AdaptiveRateLimiter(initialRate, targetLatencyMs);
        }

        public void acquire() {
            limiter.acquire();
        }

        public boolean tryAcquire() {
            return limiter.tryAcquire();
        }

        /**
         * Report the latency of an operation to adjust the rate
         */
        public void recordLatency(long latencyMs) {
            synchronized (mutex) {
                if (latencyMs > targetLatencyMs) {
                    // Slow down
                    currentRate = Math.max(MIN_RATE, currentRate * DECREASE_FACTOR);
                } else if (latencyMs < targetLatencyMs * 0.5) {
                    // Speed up
                    currentRate = Math.min(MAX_RATE, currentRate * INCREASE_FACTOR);
                }
                limiter = RateLimiter.create(currentRate);
            }
        }

        /**
         * Report a timeout/failure to slow down
         */
        public void recordFailure() {
            synchronized (mutex) {
                currentRate = Math.max(MIN_RATE, currentRate * DECREASE_FACTOR);
                limiter = RateLimiter.create(currentRate);
            }
        }

        /**
         * Get current rate
         */
        public double getCurrentRate() {
            return currentRate;
        }
    }
}
