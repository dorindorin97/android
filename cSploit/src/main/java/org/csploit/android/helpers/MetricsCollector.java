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

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;

/**
 * MetricsCollector - Performance metrics and statistics collection
 *
 * Provides:
 * - Counter metrics (incrementing values)
 * - Gauge metrics (current values)
 * - Timer metrics (duration tracking)
 * - Histogram metrics (distribution tracking)
 * - Metric export and reporting
 *
 * Usage:
 * {@code
 * MetricsCollector metrics = MetricsCollector.getInstance();
 *
 * // Count events
 * metrics.incrementCounter("scans.started");
 *
 * // Track durations
 * Timer timer = metrics.startTimer("scan.duration");
 * // ... do work ...
 * timer.stop();
 *
 * // Get stats
 * MetricsSummary summary = metrics.getSummary();
 * }
 */
public final class MetricsCollector {

    private static final String TAG = "MetricsCollector";
    private static volatile MetricsCollector instance;

    private final Map<String, Counter> counters = new ConcurrentHashMap<>();
    private final Map<String, Gauge> gauges = new ConcurrentHashMap<>();
    private final Map<String, TimerMetric> timers = new ConcurrentHashMap<>();
    private final Map<String, Histogram> histograms = new ConcurrentHashMap<>();
    private final List<MetricsListener> listeners = new CopyOnWriteArrayList<>();

    private final long startTime;
    private volatile boolean enabled = true;

    private MetricsCollector() {
        startTime = System.currentTimeMillis();
    }

    public static MetricsCollector getInstance() {
        if (instance == null) {
            synchronized (MetricsCollector.class) {
                if (instance == null) {
                    instance = new MetricsCollector();
                }
            }
        }
        return instance;
    }

    // ==================== Counter Operations ====================

    /**
     * Increment a counter by 1
     */
    public void incrementCounter(@NonNull String name) {
        incrementCounter(name, 1);
    }

    /**
     * Increment a counter by specified amount
     */
    public void incrementCounter(@NonNull String name, long amount) {
        if (!enabled) return;
        getOrCreateCounter(name).increment(amount);
        notifyListeners(MetricType.COUNTER, name);
    }

    /**
     * Get current counter value
     */
    public long getCounterValue(@NonNull String name) {
        Counter counter = counters.get(name);
        return counter != null ? counter.getValue() : 0;
    }

    /**
     * Reset a counter
     */
    public void resetCounter(@NonNull String name) {
        Counter counter = counters.get(name);
        if (counter != null) {
            counter.reset();
        }
    }

    private Counter getOrCreateCounter(String name) {
        return counters.computeIfAbsent(name, k -> new Counter());
    }

    // ==================== Gauge Operations ====================

    /**
     * Set a gauge value
     */
    public void setGauge(@NonNull String name, long value) {
        if (!enabled) return;
        getOrCreateGauge(name).setValue(value);
        notifyListeners(MetricType.GAUGE, name);
    }

    /**
     * Increment a gauge by 1
     */
    public void incrementGauge(@NonNull String name) {
        if (!enabled) return;
        getOrCreateGauge(name).increment();
        notifyListeners(MetricType.GAUGE, name);
    }

    /**
     * Decrement a gauge by 1
     */
    public void decrementGauge(@NonNull String name) {
        if (!enabled) return;
        getOrCreateGauge(name).decrement();
        notifyListeners(MetricType.GAUGE, name);
    }

    /**
     * Get current gauge value
     */
    public long getGaugeValue(@NonNull String name) {
        Gauge gauge = gauges.get(name);
        return gauge != null ? gauge.getValue() : 0;
    }

    private Gauge getOrCreateGauge(String name) {
        return gauges.computeIfAbsent(name, k -> new Gauge());
    }

    // ==================== Timer Operations ====================

    /**
     * Start a timer and return a Timer object to stop it later
     */
    @NonNull
    public Timer startTimer(@NonNull String name) {
        return new Timer(name, this);
    }

    /**
     * Record a duration directly (in milliseconds)
     */
    public void recordDuration(@NonNull String name, long durationMs) {
        if (!enabled) return;
        getOrCreateTimerMetric(name).record(durationMs);
        notifyListeners(MetricType.TIMER, name);
    }

    /**
     * Get timer statistics
     */
    @Nullable
    public TimerStats getTimerStats(@NonNull String name) {
        TimerMetric timer = timers.get(name);
        return timer != null ? timer.getStats() : null;
    }

    private TimerMetric getOrCreateTimerMetric(String name) {
        return timers.computeIfAbsent(name, k -> new TimerMetric());
    }

    // ==================== Histogram Operations ====================

    /**
     * Record a value in a histogram
     */
    public void recordHistogram(@NonNull String name, long value) {
        if (!enabled) return;
        getOrCreateHistogram(name).record(value);
        notifyListeners(MetricType.HISTOGRAM, name);
    }

    /**
     * Get histogram statistics
     */
    @Nullable
    public HistogramStats getHistogramStats(@NonNull String name) {
        Histogram histogram = histograms.get(name);
        return histogram != null ? histogram.getStats() : null;
    }

    private Histogram getOrCreateHistogram(String name) {
        return histograms.computeIfAbsent(name, k -> new Histogram());
    }

    // ==================== Summary and Export ====================

    /**
     * Get a summary of all metrics
     */
    @NonNull
    public MetricsSummary getSummary() {
        return new MetricsSummary(this);
    }

    /**
     * Export all metrics as a map
     */
    @NonNull
    public Map<String, Object> export() {
        Map<String, Object> result = new LinkedHashMap<>();

        result.put("uptime_ms", System.currentTimeMillis() - startTime);
        result.put("enabled", enabled);

        // Counters
        Map<String, Long> counterValues = new LinkedHashMap<>();
        for (Map.Entry<String, Counter> entry : counters.entrySet()) {
            counterValues.put(entry.getKey(), entry.getValue().getValue());
        }
        result.put("counters", counterValues);

        // Gauges
        Map<String, Long> gaugeValues = new LinkedHashMap<>();
        for (Map.Entry<String, Gauge> entry : gauges.entrySet()) {
            gaugeValues.put(entry.getKey(), entry.getValue().getValue());
        }
        result.put("gauges", gaugeValues);

        // Timers
        Map<String, Map<String, Object>> timerValues = new LinkedHashMap<>();
        for (Map.Entry<String, TimerMetric> entry : timers.entrySet()) {
            TimerStats stats = entry.getValue().getStats();
            Map<String, Object> timerData = new LinkedHashMap<>();
            timerData.put("count", stats.count);
            timerData.put("min_ms", stats.min);
            timerData.put("max_ms", stats.max);
            timerData.put("avg_ms", stats.average);
            timerData.put("total_ms", stats.total);
            timerValues.put(entry.getKey(), timerData);
        }
        result.put("timers", timerValues);

        return result;
    }

    /**
     * Reset all metrics
     */
    public void resetAll() {
        counters.clear();
        gauges.clear();
        timers.clear();
        histograms.clear();
    }

    /**
     * Enable/disable metrics collection
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Check if metrics collection is enabled
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Get uptime in milliseconds
     */
    public long getUptimeMs() {
        return System.currentTimeMillis() - startTime;
    }

    // ==================== Listeners ====================

    public void addListener(@NonNull MetricsListener listener) {
        listeners.add(listener);
    }

    public void removeListener(@NonNull MetricsListener listener) {
        listeners.remove(listener);
    }

    private void notifyListeners(MetricType type, String name) {
        for (MetricsListener listener : listeners) {
            try {
                listener.onMetricUpdated(type, name);
            } catch (Exception e) {
                // Ignore listener errors
            }
        }
    }

    // ==================== Supporting Classes ====================

    public enum MetricType {
        COUNTER, GAUGE, TIMER, HISTOGRAM
    }

    public interface MetricsListener {
        void onMetricUpdated(MetricType type, String name);
    }

    /**
     * Counter implementation using LongAdder for high concurrency
     */
    private static class Counter {
        private final LongAdder value = new LongAdder();

        void increment(long amount) {
            value.add(amount);
        }

        long getValue() {
            return value.sum();
        }

        void reset() {
            value.reset();
        }
    }

    /**
     * Gauge implementation using AtomicLong
     */
    private static class Gauge {
        private final AtomicLong value = new AtomicLong(0);

        void setValue(long val) {
            value.set(val);
        }

        void increment() {
            value.incrementAndGet();
        }

        void decrement() {
            value.decrementAndGet();
        }

        long getValue() {
            return value.get();
        }
    }

    /**
     * Timer metric with statistics
     */
    private static class TimerMetric {
        private final LongAdder count = new LongAdder();
        private final LongAdder total = new LongAdder();
        private final AtomicLong min = new AtomicLong(Long.MAX_VALUE);
        private final AtomicLong max = new AtomicLong(Long.MIN_VALUE);

        void record(long duration) {
            count.increment();
            total.add(duration);

            // Update min
            long currentMin;
            do {
                currentMin = min.get();
                if (duration >= currentMin) break;
            } while (!min.compareAndSet(currentMin, duration));

            // Update max
            long currentMax;
            do {
                currentMax = max.get();
                if (duration <= currentMax) break;
            } while (!max.compareAndSet(currentMax, duration));
        }

        TimerStats getStats() {
            long c = count.sum();
            long t = total.sum();
            return new TimerStats(
                    c,
                    t,
                    c > 0 ? min.get() : 0,
                    c > 0 ? max.get() : 0,
                    c > 0 ? (double) t / c : 0
            );
        }
    }

    /**
     * Timer statistics
     */
    public static class TimerStats {
        public final long count;
        public final long total;
        public final long min;
        public final long max;
        public final double average;

        TimerStats(long count, long total, long min, long max, double average) {
            this.count = count;
            this.total = total;
            this.min = min;
            this.max = max;
            this.average = average;
        }

        @NonNull
        @Override
        public String toString() {
            return String.format("TimerStats[count=%d, min=%dms, max=%dms, avg=%.2fms, total=%dms]",
                    count, min, max, average, total);
        }
    }

    /**
     * Histogram implementation for distribution tracking
     */
    private static class Histogram {
        private final List<Long> values = Collections.synchronizedList(new ArrayList<>());
        private static final int MAX_VALUES = 10000;

        void record(long value) {
            if (values.size() < MAX_VALUES) {
                values.add(value);
            }
        }

        HistogramStats getStats() {
            if (values.isEmpty()) {
                return new HistogramStats(0, 0, 0, 0, 0, 0, 0, 0);
            }

            List<Long> sorted;
            synchronized (values) {
                sorted = new ArrayList<>(values);
            }
            Collections.sort(sorted);

            int size = sorted.size();
            long min = sorted.get(0);
            long max = sorted.get(size - 1);
            long sum = 0;
            for (long v : sorted) sum += v;
            double avg = (double) sum / size;
            long median = sorted.get(size / 2);
            long p95 = sorted.get((int) (size * 0.95));
            long p99 = sorted.get((int) (size * 0.99));

            return new HistogramStats(size, min, max, avg, median, p95, p99, sum);
        }
    }

    /**
     * Histogram statistics
     */
    public static class HistogramStats {
        public final long count;
        public final long min;
        public final long max;
        public final double average;
        public final long median;
        public final long p95;
        public final long p99;
        public final long sum;

        HistogramStats(long count, long min, long max, double avg, long median, long p95, long p99, long sum) {
            this.count = count;
            this.min = min;
            this.max = max;
            this.average = avg;
            this.median = median;
            this.p95 = p95;
            this.p99 = p99;
            this.sum = sum;
        }

        @NonNull
        @Override
        public String toString() {
            return String.format("HistogramStats[count=%d, min=%d, max=%d, avg=%.2f, p50=%d, p95=%d, p99=%d]",
                    count, min, max, average, median, p95, p99);
        }
    }

    /**
     * Timer helper for measuring durations
     */
    public static class Timer {
        private final String name;
        private final MetricsCollector collector;
        private final long startNanos;
        private boolean stopped = false;

        Timer(String name, MetricsCollector collector) {
            this.name = name;
            this.collector = collector;
            this.startNanos = System.nanoTime();
        }

        /**
         * Stop the timer and record the duration
         *
         * @return duration in milliseconds
         */
        public long stop() {
            if (stopped) {
                return 0;
            }
            stopped = true;
            long durationMs = (System.nanoTime() - startNanos) / 1_000_000;
            collector.recordDuration(name, durationMs);
            return durationMs;
        }

        /**
         * Get elapsed time without stopping
         */
        public long elapsed() {
            return (System.nanoTime() - startNanos) / 1_000_000;
        }
    }

    /**
     * Summary of all metrics
     */
    public static class MetricsSummary {
        private final MetricsCollector collector;

        MetricsSummary(MetricsCollector collector) {
            this.collector = collector;
        }

        public long getUptimeMs() {
            return collector.getUptimeMs();
        }

        public int getCounterCount() {
            return collector.counters.size();
        }

        public int getGaugeCount() {
            return collector.gauges.size();
        }

        public int getTimerCount() {
            return collector.timers.size();
        }

        public int getHistogramCount() {
            return collector.histograms.size();
        }

        public Map<String, Object> toMap() {
            return collector.export();
        }

        @NonNull
        @Override
        public String toString() {
            return String.format("MetricsSummary[uptime=%s, counters=%d, gauges=%d, timers=%d, histograms=%d]",
                    TimeHelper.formatDuration(getUptimeMs()),
                    getCounterCount(), getGaugeCount(), getTimerCount(), getHistogramCount());
        }
    }
}
