/*
 * This file is part of the cSploit.
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

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Network speed testing utility for measuring connection quality.
 *
 * Provides:
 * - Download speed tests
 * - Latency/ping measurements
 * - Connection quality assessment
 * - Bandwidth estimation
 */
public final class NetworkSpeedTester {

    private static final String TAG = "NetworkSpeedTester";

    // Default test endpoints (publicly available test files)
    private static final String[] DEFAULT_TEST_URLS = {
        "https://speed.cloudflare.com/__down?bytes=1000000",
        "https://www.google.com/generate_204"
    };

    private static final int DEFAULT_TIMEOUT_MS = 10000;
    private static final int PING_COUNT = 5;
    private static final int BUFFER_SIZE = 8192;

    private NetworkSpeedTester() {}

    /**
     * Result of a speed test operation
     */
    public static class SpeedTestResult {
        public final double downloadSpeedMbps;
        public final double latencyMs;
        public final long bytesTransferred;
        public final long durationMs;
        public final boolean success;
        public final String error;

        private SpeedTestResult(double downloadSpeedMbps, double latencyMs,
                               long bytesTransferred, long durationMs,
                               boolean success, String error) {
            this.downloadSpeedMbps = downloadSpeedMbps;
            this.latencyMs = latencyMs;
            this.bytesTransferred = bytesTransferred;
            this.durationMs = durationMs;
            this.success = success;
            this.error = error;
        }

        public static SpeedTestResult success(double speedMbps, double latencyMs,
                                              long bytes, long duration) {
            return new SpeedTestResult(speedMbps, latencyMs, bytes, duration, true, null);
        }

        public static SpeedTestResult failure(String error) {
            return new SpeedTestResult(0, 0, 0, 0, false, error);
        }

        public String getSpeedFormatted() {
            if (downloadSpeedMbps >= 1) {
                return String.format(Locale.US, "%.2f Mbps", downloadSpeedMbps);
            } else {
                return String.format(Locale.US, "%.0f Kbps", downloadSpeedMbps * 1000);
            }
        }

        public String getLatencyFormatted() {
            return String.format(Locale.US, "%.1f ms", latencyMs);
        }

        public String getQualityRating() {
            if (downloadSpeedMbps >= 100 && latencyMs < 20) return "Excellent";
            if (downloadSpeedMbps >= 50 && latencyMs < 50) return "Very Good";
            if (downloadSpeedMbps >= 25 && latencyMs < 100) return "Good";
            if (downloadSpeedMbps >= 10 && latencyMs < 150) return "Fair";
            if (downloadSpeedMbps >= 5) return "Moderate";
            return "Poor";
        }
    }

    /**
     * Result of a ping/latency test
     */
    public static class PingResult {
        public final String host;
        public final double minMs;
        public final double maxMs;
        public final double avgMs;
        public final int packetsSent;
        public final int packetsReceived;
        public final double packetLoss;
        public final boolean reachable;

        public PingResult(String host, double minMs, double maxMs, double avgMs,
                         int packetsSent, int packetsReceived) {
            this.host = host;
            this.minMs = minMs;
            this.maxMs = maxMs;
            this.avgMs = avgMs;
            this.packetsSent = packetsSent;
            this.packetsReceived = packetsReceived;
            this.packetLoss = packetsSent > 0 ?
                ((packetsSent - packetsReceived) * 100.0 / packetsSent) : 100;
            this.reachable = packetsReceived > 0;
        }

        public String getSummary() {
            return String.format(Locale.US,
                "Host: %s | Avg: %.1fms | Min: %.1fms | Max: %.1fms | Loss: %.1f%%",
                host, avgMs, minMs, maxMs, packetLoss);
        }
    }

    // ==================== Speed Test Methods ====================

    /**
     * Perform a quick download speed test
     *
     * @return SpeedTestResult with download speed in Mbps
     */
    public static SpeedTestResult testDownloadSpeed() {
        return testDownloadSpeed(DEFAULT_TEST_URLS[0], DEFAULT_TIMEOUT_MS);
    }

    /**
     * Perform a download speed test with custom URL
     *
     * @param testUrl URL to download for testing
     * @param timeoutMs timeout in milliseconds
     * @return SpeedTestResult with download speed in Mbps
     */
    public static SpeedTestResult testDownloadSpeed(String testUrl, int timeoutMs) {
        HttpURLConnection connection = null;
        InputStream inputStream = null;

        try {
            URL url = new URL(testUrl);
            connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(timeoutMs);
            connection.setReadTimeout(timeoutMs);
            connection.setRequestMethod("GET");
            connection.setRequestProperty("User-Agent", "cSploit-SpeedTest/1.0");

            long startTime = System.nanoTime();
            connection.connect();

            inputStream = connection.getInputStream();
            byte[] buffer = new byte[BUFFER_SIZE];
            long totalBytes = 0;
            int bytesRead;

            while ((bytesRead = inputStream.read(buffer)) != -1) {
                totalBytes += bytesRead;
            }

            long endTime = System.nanoTime();
            long durationMs = TimeUnit.NANOSECONDS.toMillis(endTime - startTime);

            if (durationMs == 0) durationMs = 1; // Prevent division by zero

            // Calculate speed in Mbps: (bytes * 8) / (milliseconds * 1000) = Mbps
            double speedMbps = (totalBytes * 8.0) / (durationMs * 1000.0);

            // Measure latency
            double latency = measureLatency(url.getHost(), 443);

            return SpeedTestResult.success(speedMbps, latency, totalBytes, durationMs);

        } catch (Exception e) {
            LoggingHelper.e(TAG, "Speed test failed", e);
            return SpeedTestResult.failure(e.getMessage());
        } finally {
            CloseableHelper.close(inputStream);
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    // ==================== Latency/Ping Methods ====================

    /**
     * Measure TCP latency to a host
     *
     * @param host target host
     * @param port target port
     * @return latency in milliseconds, or -1 if unreachable
     */
    public static double measureLatency(String host, int port) {
        return measureLatency(host, port, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Measure TCP latency to a host with custom timeout
     *
     * @param host target host
     * @param port target port
     * @param timeoutMs timeout in milliseconds
     * @return latency in milliseconds, or -1 if unreachable
     */
    public static double measureLatency(String host, int port, int timeoutMs) {
        Socket socket = null;
        try {
            socket = new Socket();
            long start = System.nanoTime();
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            long end = System.nanoTime();
            return TimeUnit.NANOSECONDS.toMicros(end - start) / 1000.0;
        } catch (IOException e) {
            return -1;
        } finally {
            CloseableHelper.close(socket);
        }
    }

    /**
     * Perform multiple ping measurements and return statistics
     *
     * @param host target host
     * @param port target port
     * @param count number of pings
     * @return PingResult with statistics
     */
    public static PingResult ping(String host, int port, int count) {
        List<Double> latencies = new ArrayList<>();
        int received = 0;

        for (int i = 0; i < count; i++) {
            double latency = measureLatency(host, port, 5000);
            if (latency >= 0) {
                latencies.add(latency);
                received++;
            }

            // Small delay between pings
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }

        if (latencies.isEmpty()) {
            return new PingResult(host, 0, 0, 0, count, 0);
        }

        double min = Double.MAX_VALUE;
        double max = Double.MIN_VALUE;
        double sum = 0;

        for (double lat : latencies) {
            min = Math.min(min, lat);
            max = Math.max(max, lat);
            sum += lat;
        }

        double avg = sum / latencies.size();
        return new PingResult(host, min, max, avg, count, received);
    }

    /**
     * Perform ping test with default settings
     *
     * @param host target host
     * @return PingResult with statistics
     */
    public static PingResult ping(String host) {
        return ping(host, 80, PING_COUNT);
    }

    /**
     * Check if a host is reachable using ICMP (requires root) or TCP fallback
     *
     * @param host target host
     * @param timeoutMs timeout in milliseconds
     * @return true if reachable
     */
    public static boolean isReachable(String host, int timeoutMs) {
        try {
            InetAddress address = InetAddress.getByName(host);
            // Try ICMP first
            if (address.isReachable(timeoutMs)) {
                return true;
            }
            // Fallback to TCP on common ports
            return measureLatency(host, 80, timeoutMs) >= 0 ||
                   measureLatency(host, 443, timeoutMs) >= 0;
        } catch (IOException e) {
            return false;
        }
    }

    // ==================== Bandwidth Estimation ====================

    /**
     * Estimate available bandwidth to a host
     *
     * @param host target host
     * @param port target port
     * @return estimated bandwidth in Mbps, or -1 if estimation fails
     */
    public static double estimateBandwidth(String host, int port) {
        // Use multiple small packets to estimate bandwidth
        final int testCount = 10;
        final int packetSize = 1024;

        List<Double> rates = new ArrayList<>();

        for (int i = 0; i < testCount; i++) {
            Socket socket = null;
            try {
                socket = new Socket();
                long startConnect = System.nanoTime();
                socket.connect(new InetSocketAddress(host, port), 5000);
                long connectTime = System.nanoTime() - startConnect;

                // Estimate based on TCP handshake time
                // Rough approximation: smaller RTT suggests better bandwidth
                double rttMs = TimeUnit.NANOSECONDS.toMicros(connectTime) / 1000.0;
                if (rttMs > 0) {
                    // Very rough bandwidth estimation based on RTT
                    // This is a simplified model
                    double estimatedMbps = Math.min(1000 / rttMs, 1000);
                    rates.add(estimatedMbps);
                }
            } catch (IOException e) {
                // Ignore individual failures
            } finally {
                CloseableHelper.close(socket);
            }
        }

        if (rates.isEmpty()) {
            return -1;
        }

        double sum = 0;
        for (double rate : rates) {
            sum += rate;
        }
        return sum / rates.size();
    }

    // ==================== Parallel Testing ====================

    /**
     * Test latency to multiple hosts in parallel
     *
     * @param hosts list of hosts to test
     * @param port port to connect to
     * @return list of PingResults
     */
    public static List<PingResult> pingMultiple(List<String> hosts, int port) {
        ExecutorService executor = Executors.newFixedThreadPool(
            Math.min(hosts.size(), 10)
        );
        List<Future<PingResult>> futures = new ArrayList<>();

        for (String host : hosts) {
            futures.add(executor.submit(() -> ping(host, port, 3)));
        }

        List<PingResult> results = new ArrayList<>();
        for (Future<PingResult> future : futures) {
            try {
                results.add(future.get(30, TimeUnit.SECONDS));
            } catch (Exception e) {
                LoggingHelper.d(TAG, "Ping task failed: " + e.getMessage());
            }
        }

        executor.shutdown();
        return results;
    }

    /**
     * Find the host with lowest latency from a list
     *
     * @param hosts list of hosts to test
     * @param port port to connect to
     * @return hostname with lowest latency, or null if all fail
     */
    public static String findLowestLatencyHost(List<String> hosts, int port) {
        List<PingResult> results = pingMultiple(hosts, port);

        PingResult best = null;
        for (PingResult result : results) {
            if (result.reachable) {
                if (best == null || result.avgMs < best.avgMs) {
                    best = result;
                }
            }
        }

        return best != null ? best.host : null;
    }

    // ==================== Connection Quality ====================

    /**
     * Assess overall connection quality
     *
     * @return quality description string
     */
    public static String assessConnectionQuality() {
        SpeedTestResult speedResult = testDownloadSpeed();
        if (!speedResult.success) {
            return "Unable to assess - connection test failed";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Connection Quality: ").append(speedResult.getQualityRating()).append("\n");
        sb.append("Download Speed: ").append(speedResult.getSpeedFormatted()).append("\n");
        sb.append("Latency: ").append(speedResult.getLatencyFormatted());

        return sb.toString();
    }

    /**
     * Check if connection is suitable for real-time operations
     *
     * @param maxLatencyMs maximum acceptable latency
     * @param minSpeedMbps minimum acceptable speed
     * @return true if connection meets requirements
     */
    public static boolean isSuitableForRealtime(double maxLatencyMs, double minSpeedMbps) {
        SpeedTestResult result = testDownloadSpeed();
        return result.success &&
               result.latencyMs <= maxLatencyMs &&
               result.downloadSpeedMbps >= minSpeedMbps;
    }
}
