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

import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * LatencyAnalyzer - Network latency measurement and analysis.
 *
 * Provides:
 * - TCP/ICMP latency measurement
 * - Statistical analysis (min, max, avg, jitter)
 * - Connection quality assessment
 * - Historical latency tracking
 * - Network stability analysis
 *
 * Usage:
 * {@code
 * // Measure latency
 * LatencyResult result = LatencyAnalyzer.measureLatency("192.168.1.1", 80, 5);
 *
 * // Get statistics
 * double avg = result.getAverageLatency();
 * double jitter = result.getJitter();
 *
 * // Assess quality
 * ConnectionQuality quality = result.getQuality();
 * }
 */
public final class LatencyAnalyzer {

    private static final String TAG = "LatencyAnalyzer";
    private static final int DEFAULT_TIMEOUT = 5000;
    private static final int DEFAULT_SAMPLE_COUNT = 10;

    /**
     * Latency measurement result.
     */
    public static class LatencyResult {
        private final String host;
        private final int port;
        private final List<Long> samples;
        private final List<Long> failedSamples;
        private final long timestamp;
        private long minLatency = Long.MAX_VALUE;
        private long maxLatency = Long.MIN_VALUE;
        private double averageLatency;
        private double standardDeviation;
        private double jitter;
        private double packetLoss;

        public LatencyResult(@NonNull String host, int port) {
            this.host = host;
            this.port = port;
            this.samples = new ArrayList<>();
            this.failedSamples = new ArrayList<>();
            this.timestamp = System.currentTimeMillis();
        }

        public String getHost() { return host; }
        public int getPort() { return port; }
        public List<Long> getSamples() { return Collections.unmodifiableList(samples); }
        public int getSampleCount() { return samples.size(); }
        public int getFailedCount() { return failedSamples.size(); }
        public long getTimestamp() { return timestamp; }
        public long getMinLatency() { return minLatency == Long.MAX_VALUE ? 0 : minLatency; }
        public long getMaxLatency() { return maxLatency == Long.MIN_VALUE ? 0 : maxLatency; }
        public double getAverageLatency() { return averageLatency; }
        public double getStandardDeviation() { return standardDeviation; }
        public double getJitter() { return jitter; }
        public double getPacketLoss() { return packetLoss; }

        public void addSample(long latencyMs) {
            samples.add(latencyMs);
            if (latencyMs < minLatency) minLatency = latencyMs;
            if (latencyMs > maxLatency) maxLatency = latencyMs;
            calculateStatistics();
        }

        public void addFailedSample() {
            failedSamples.add(System.currentTimeMillis());
            calculateStatistics();
        }

        private void calculateStatistics() {
            int totalSamples = samples.size() + failedSamples.size();
            if (totalSamples == 0) return;

            // Packet loss
            packetLoss = (failedSamples.size() * 100.0) / totalSamples;

            if (samples.isEmpty()) return;

            // Average
            long sum = 0;
            for (long sample : samples) {
                sum += sample;
            }
            averageLatency = (double) sum / samples.size();

            // Standard deviation
            double sumSquares = 0;
            for (long sample : samples) {
                sumSquares += Math.pow(sample - averageLatency, 2);
            }
            standardDeviation = Math.sqrt(sumSquares / samples.size());

            // Jitter (average deviation between consecutive samples)
            if (samples.size() > 1) {
                double jitterSum = 0;
                for (int i = 1; i < samples.size(); i++) {
                    jitterSum += Math.abs(samples.get(i) - samples.get(i - 1));
                }
                jitter = jitterSum / (samples.size() - 1);
            }
        }

        /**
         * Get connection quality assessment.
         */
        @NonNull
        public ConnectionQuality getQuality() {
            if (packetLoss > 50) return ConnectionQuality.VERY_POOR;
            if (packetLoss > 20) return ConnectionQuality.POOR;

            if (samples.isEmpty()) return ConnectionQuality.UNKNOWN;

            if (averageLatency < 20 && jitter < 10 && packetLoss < 1) {
                return ConnectionQuality.EXCELLENT;
            } else if (averageLatency < 50 && jitter < 20 && packetLoss < 2) {
                return ConnectionQuality.GOOD;
            } else if (averageLatency < 100 && jitter < 40 && packetLoss < 5) {
                return ConnectionQuality.FAIR;
            } else if (averageLatency < 200 && packetLoss < 10) {
                return ConnectionQuality.POOR;
            } else {
                return ConnectionQuality.VERY_POOR;
            }
        }

        @NonNull
        @Override
        public String toString() {
            return String.format("Latency{host='%s', avg=%.1fms, min=%d, max=%d, jitter=%.1f, loss=%.1f%%}",
                    host, averageLatency, getMinLatency(), getMaxLatency(), jitter, packetLoss);
        }
    }

    /**
     * Connection quality levels.
     */
    public enum ConnectionQuality {
        EXCELLENT("Excellent", 5),
        GOOD("Good", 4),
        FAIR("Fair", 3),
        POOR("Poor", 2),
        VERY_POOR("Very Poor", 1),
        UNKNOWN("Unknown", 0);

        private final String description;
        private final int score;

        ConnectionQuality(String description, int score) {
            this.description = description;
            this.score = score;
        }

        public String getDescription() { return description; }
        public int getScore() { return score; }
    }

    private LatencyAnalyzer() {}

    /**
     * Measure TCP latency to host:port.
     */
    @NonNull
    public static LatencyResult measureLatency(@NonNull String host, int port) {
        return measureLatency(host, port, DEFAULT_SAMPLE_COUNT, DEFAULT_TIMEOUT);
    }

    /**
     * Measure TCP latency with sample count.
     */
    @NonNull
    public static LatencyResult measureLatency(@NonNull String host, int port, int sampleCount) {
        return measureLatency(host, port, sampleCount, DEFAULT_TIMEOUT);
    }

    /**
     * Measure TCP latency with full parameters.
     */
    @NonNull
    public static LatencyResult measureLatency(@NonNull String host, int port, int sampleCount, int timeoutMs) {
        LatencyResult result = new LatencyResult(host, port);

        for (int i = 0; i < sampleCount; i++) {
            long startTime = System.nanoTime();

            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(host, port), timeoutMs);
                long latency = (System.nanoTime() - startTime) / 1_000_000;
                result.addSample(latency);
            } catch (Exception e) {
                result.addFailedSample();
            }

            // Small delay between samples
            if (i < sampleCount - 1) {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }

        return result;
    }

    /**
     * Measure latency asynchronously.
     */
    @NonNull
    public static Future<LatencyResult> measureLatencyAsync(
            @NonNull String host, int port, int sampleCount, int timeoutMs) {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<LatencyResult> future = executor.submit(() ->
                measureLatency(host, port, sampleCount, timeoutMs));
        executor.shutdown();
        return future;
    }

    /**
     * Measure latency to multiple hosts in parallel.
     */
    @NonNull
    public static List<LatencyResult> measureMultipleHosts(
            @NonNull List<String> hosts, int port, int sampleCount, int timeoutMs) {
        List<LatencyResult> results = Collections.synchronizedList(new ArrayList<>());
        ExecutorService executor = Executors.newFixedThreadPool(Math.min(hosts.size(), 10));
        List<Future<?>> futures = new ArrayList<>();

        for (String host : hosts) {
            futures.add(executor.submit(() -> {
                results.add(measureLatency(host, port, sampleCount, timeoutMs));
            }));
        }

        // Wait for completion
        for (Future<?> future : futures) {
            try {
                future.get(timeoutMs * sampleCount * 2L, TimeUnit.MILLISECONDS);
            } catch (Exception e) {
                Log.w(TAG, "Timeout waiting for latency measurement", e);
            }
        }

        executor.shutdown();
        return new ArrayList<>(results);
    }

    /**
     * Single latency probe (no statistics).
     */
    public static long probe(@NonNull String host, int port, int timeoutMs) {
        long startTime = System.nanoTime();

        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            return (System.nanoTime() - startTime) / 1_000_000;
        } catch (Exception e) {
            return -1;
        }
    }

    /**
     * Check if host is reachable.
     */
    public static boolean isReachable(@NonNull String host, int timeoutMs) {
        try {
            InetAddress address = InetAddress.getByName(host);
            return address.isReachable(timeoutMs);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Compare two latency results.
     */
    @NonNull
    public static LatencyComparison compare(@NonNull LatencyResult result1, @NonNull LatencyResult result2) {
        return new LatencyComparison(result1, result2);
    }

    /**
     * Latency comparison result.
     */
    public static class LatencyComparison {
        private final LatencyResult result1;
        private final LatencyResult result2;
        private final double latencyDiff;
        private final double jitterDiff;
        private final double losssDiff;

        public LatencyComparison(@NonNull LatencyResult r1, @NonNull LatencyResult r2) {
            this.result1 = r1;
            this.result2 = r2;
            this.latencyDiff = r2.getAverageLatency() - r1.getAverageLatency();
            this.jitterDiff = r2.getJitter() - r1.getJitter();
            this.losssDiff = r2.getPacketLoss() - r1.getPacketLoss();
        }

        public LatencyResult getResult1() { return result1; }
        public LatencyResult getResult2() { return result2; }
        public double getLatencyDiff() { return latencyDiff; }
        public double getJitterDiff() { return jitterDiff; }
        public double getLossDiff() { return losssDiff; }

        public boolean isImproved() {
            return latencyDiff < 0 && jitterDiff <= 0 && losssDiff <= 0;
        }

        public boolean isDegraded() {
            return latencyDiff > 0 || jitterDiff > 10 || losssDiff > 5;
        }

        @NonNull
        @Override
        public String toString() {
            return String.format("LatencyChange: %.1fms (latency), %.1f (jitter), %.1f%% (loss)",
                    latencyDiff, jitterDiff, losssDiff);
        }
    }

    /**
     * Get latency classification.
     */
    @NonNull
    public static String classifyLatency(double latencyMs) {
        if (latencyMs < 0) return "unreachable";
        if (latencyMs < 10) return "excellent";
        if (latencyMs < 30) return "very good";
        if (latencyMs < 50) return "good";
        if (latencyMs < 100) return "fair";
        if (latencyMs < 200) return "poor";
        return "very poor";
    }

    /**
     * Get recommended timeout based on measured latency.
     */
    public static int getRecommendedTimeout(@NonNull LatencyResult result) {
        if (result.getSampleCount() == 0) return DEFAULT_TIMEOUT;

        // Use 3x the max latency with a minimum of 1 second
        long recommended = (long) (result.getMaxLatency() * 3);
        return Math.max((int) recommended, 1000);
    }

    /**
     * Calculate percentile latency.
     */
    public static long getPercentile(@NonNull LatencyResult result, int percentile) {
        if (result.getSamples().isEmpty()) return 0;

        List<Long> sorted = new ArrayList<>(result.getSamples());
        Collections.sort(sorted);

        int index = (int) Math.ceil((percentile / 100.0) * sorted.size()) - 1;
        return sorted.get(Math.max(0, Math.min(index, sorted.size() - 1)));
    }

    /**
     * Format latency result as string.
     */
    @NonNull
    public static String formatResult(@NonNull LatencyResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== Latency Analysis ===\n");
        sb.append("Host: ").append(result.getHost()).append(":").append(result.getPort()).append("\n");
        sb.append("Samples: ").append(result.getSampleCount()).append("\n");
        sb.append("Failed: ").append(result.getFailedCount()).append("\n");
        sb.append("\n");
        sb.append("Min: ").append(result.getMinLatency()).append("ms\n");
        sb.append("Max: ").append(result.getMaxLatency()).append("ms\n");
        sb.append("Avg: ").append(String.format("%.2f", result.getAverageLatency())).append("ms\n");
        sb.append("StdDev: ").append(String.format("%.2f", result.getStandardDeviation())).append("ms\n");
        sb.append("Jitter: ").append(String.format("%.2f", result.getJitter())).append("ms\n");
        sb.append("Loss: ").append(String.format("%.1f", result.getPacketLoss())).append("%\n");
        sb.append("\n");
        sb.append("Quality: ").append(result.getQuality().getDescription()).append("\n");
        return sb.toString();
    }
}
