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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with cSploit.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.csploit.android.helpers;

import android.net.TrafficStats;
import android.os.Build;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Helper class for collecting and tracking network metrics.
 * Provides real-time network statistics, bandwidth monitoring, and historical data.
 */
public final class NetworkMetricsHelper {

    private static final String TAG = "NetworkMetricsHelper";

    // Traffic stats tracking
    private static final AtomicLong lastRxBytes = new AtomicLong(0);
    private static final AtomicLong lastTxBytes = new AtomicLong(0);
    private static final AtomicLong lastUpdateTime = new AtomicLong(0);
    private static final AtomicLong currentRxSpeed = new AtomicLong(0);
    private static final AtomicLong currentTxSpeed = new AtomicLong(0);

    // Historical data
    private static final List<BandwidthSample> bandwidthHistory = new ArrayList<>();
    private static final int MAX_HISTORY_SIZE = 300; // 5 minutes at 1 sample/sec

    // Host metrics
    private static final Map<String, HostMetrics> hostMetrics = new ConcurrentHashMap<>();

    /**
     * Represents a single bandwidth sample point.
     */
    public static class BandwidthSample {
        public final long timestamp;
        public final long rxBytesPerSec;
        public final long txBytesPerSec;

        public BandwidthSample(long timestamp, long rxBytesPerSec, long txBytesPerSec) {
            this.timestamp = timestamp;
            this.rxBytesPerSec = rxBytesPerSec;
            this.txBytesPerSec = txBytesPerSec;
        }
    }

    /**
     * Metrics for a specific host.
     */
    public static class HostMetrics {
        public final String address;
        public long packetsReceived;
        public long packetsSent;
        public long bytesReceived;
        public long bytesSent;
        public long lastSeen;
        public int openPorts;
        public List<Long> latencies = new ArrayList<>();

        public HostMetrics(String address) {
            this.address = address;
            this.lastSeen = System.currentTimeMillis();
        }

        public double getAverageLatency() {
            if (latencies.isEmpty()) {
                return -1;
            }
            long sum = 0;
            for (Long latency : latencies) {
                sum += latency;
            }
            return (double) sum / latencies.size();
        }

        public void addLatency(long latency) {
            latencies.add(latency);
            // Keep only last 100 samples
            while (latencies.size() > 100) {
                latencies.remove(0);
            }
        }
    }

    /**
     * Network interface statistics.
     */
    public static class InterfaceStats {
        public String name;
        public long rxBytes;
        public long txBytes;
        public long rxPackets;
        public long txPackets;
        public long rxErrors;
        public long txErrors;
        public long rxDropped;
        public long txDropped;

        @Override
        public String toString() {
            return String.format(Locale.US,
                    "Interface %s: RX=%s TX=%s (RX pkts=%d, TX pkts=%d)",
                    name,
                    StringHelper.formatBytes(rxBytes),
                    StringHelper.formatBytes(txBytes),
                    rxPackets, txPackets);
        }
    }

    /**
     * Summary of all network metrics.
     */
    public static class NetworkSummary {
        public long totalRxBytes;
        public long totalTxBytes;
        public long currentRxSpeed;
        public long currentTxSpeed;
        public int activeConnections;
        public int hostsDiscovered;
        public long uptime;

        @NonNull
        public String getReadableSummary() {
            StringBuilder sb = new StringBuilder();
            sb.append("Network Summary\n");
            sb.append("==============\n");
            sb.append("Total Downloaded: ").append(StringHelper.formatBytes(totalRxBytes)).append("\n");
            sb.append("Total Uploaded: ").append(StringHelper.formatBytes(totalTxBytes)).append("\n");
            sb.append("Current Download: ").append(StringHelper.formatBytes(currentRxSpeed)).append("/s\n");
            sb.append("Current Upload: ").append(StringHelper.formatBytes(currentTxSpeed)).append("/s\n");
            sb.append("Active Connections: ").append(activeConnections).append("\n");
            sb.append("Hosts Discovered: ").append(hostsDiscovered).append("\n");
            return sb.toString();
        }
    }

    private NetworkMetricsHelper() {
        // Prevent instantiation
    }

    /**
     * Update bandwidth metrics. Should be called periodically (e.g., every second).
     */
    public static void updateBandwidth() {
        long now = System.currentTimeMillis();
        long rxBytes = getTotalRxBytes();
        long txBytes = getTotalTxBytes();

        long lastTime = lastUpdateTime.get();
        long lastRx = lastRxBytes.get();
        long lastTx = lastTxBytes.get();

        if (lastTime > 0 && now > lastTime) {
            long timeDiff = now - lastTime;
            long rxDiff = rxBytes - lastRx;
            long txDiff = txBytes - lastTx;

            // Calculate bytes per second
            long rxSpeed = (rxDiff * 1000) / timeDiff;
            long txSpeed = (txDiff * 1000) / timeDiff;

            currentRxSpeed.set(Math.max(0, rxSpeed));
            currentTxSpeed.set(Math.max(0, txSpeed));

            // Add to history
            synchronized (bandwidthHistory) {
                bandwidthHistory.add(new BandwidthSample(now, rxSpeed, txSpeed));
                while (bandwidthHistory.size() > MAX_HISTORY_SIZE) {
                    bandwidthHistory.remove(0);
                }
            }
        }

        lastRxBytes.set(rxBytes);
        lastTxBytes.set(txBytes);
        lastUpdateTime.set(now);
    }

    /**
     * Get total received bytes.
     */
    public static long getTotalRxBytes() {
        return TrafficStats.getTotalRxBytes();
    }

    /**
     * Get total transmitted bytes.
     */
    public static long getTotalTxBytes() {
        return TrafficStats.getTotalTxBytes();
    }

    /**
     * Get current download speed (bytes per second).
     */
    public static long getCurrentRxSpeed() {
        return currentRxSpeed.get();
    }

    /**
     * Get current upload speed (bytes per second).
     */
    public static long getCurrentTxSpeed() {
        return currentTxSpeed.get();
    }

    /**
     * Get formatted current download speed.
     */
    @NonNull
    public static String getFormattedRxSpeed() {
        return StringHelper.formatBytes(currentRxSpeed.get()) + "/s";
    }

    /**
     * Get formatted current upload speed.
     */
    @NonNull
    public static String getFormattedTxSpeed() {
        return StringHelper.formatBytes(currentTxSpeed.get()) + "/s";
    }

    /**
     * Get bandwidth history.
     */
    @NonNull
    public static List<BandwidthSample> getBandwidthHistory() {
        synchronized (bandwidthHistory) {
            return new ArrayList<>(bandwidthHistory);
        }
    }

    /**
     * Get average download speed over the history period.
     */
    public static long getAverageRxSpeed() {
        synchronized (bandwidthHistory) {
            if (bandwidthHistory.isEmpty()) {
                return 0;
            }
            long sum = 0;
            for (BandwidthSample sample : bandwidthHistory) {
                sum += sample.rxBytesPerSec;
            }
            return sum / bandwidthHistory.size();
        }
    }

    /**
     * Get average upload speed over the history period.
     */
    public static long getAverageTxSpeed() {
        synchronized (bandwidthHistory) {
            if (bandwidthHistory.isEmpty()) {
                return 0;
            }
            long sum = 0;
            for (BandwidthSample sample : bandwidthHistory) {
                sum += sample.txBytesPerSec;
            }
            return sum / bandwidthHistory.size();
        }
    }

    /**
     * Get peak download speed from history.
     */
    public static long getPeakRxSpeed() {
        synchronized (bandwidthHistory) {
            long peak = 0;
            for (BandwidthSample sample : bandwidthHistory) {
                if (sample.rxBytesPerSec > peak) {
                    peak = sample.rxBytesPerSec;
                }
            }
            return peak;
        }
    }

    /**
     * Get peak upload speed from history.
     */
    public static long getPeakTxSpeed() {
        synchronized (bandwidthHistory) {
            long peak = 0;
            for (BandwidthSample sample : bandwidthHistory) {
                if (sample.txBytesPerSec > peak) {
                    peak = sample.txBytesPerSec;
                }
            }
            return peak;
        }
    }

    /**
     * Record metrics for a specific host.
     *
     * @param address Host address
     * @param bytesReceived Bytes received from host
     * @param bytesSent Bytes sent to host
     */
    public static void recordHostTraffic(@NonNull String address, long bytesReceived, long bytesSent) {
        HostMetrics metrics = hostMetrics.computeIfAbsent(address, HostMetrics::new);
        metrics.bytesReceived += bytesReceived;
        metrics.bytesSent += bytesSent;
        if (bytesReceived > 0) metrics.packetsReceived++;
        if (bytesSent > 0) metrics.packetsSent++;
        metrics.lastSeen = System.currentTimeMillis();
    }

    /**
     * Record latency for a specific host.
     *
     * @param address Host address
     * @param latencyMs Latency in milliseconds
     */
    public static void recordHostLatency(@NonNull String address, long latencyMs) {
        HostMetrics metrics = hostMetrics.computeIfAbsent(address, HostMetrics::new);
        metrics.addLatency(latencyMs);
        metrics.lastSeen = System.currentTimeMillis();
    }

    /**
     * Record open ports for a host.
     *
     * @param address Host address
     * @param openPortCount Number of open ports
     */
    public static void recordHostPorts(@NonNull String address, int openPortCount) {
        HostMetrics metrics = hostMetrics.computeIfAbsent(address, HostMetrics::new);
        metrics.openPorts = openPortCount;
        metrics.lastSeen = System.currentTimeMillis();
    }

    /**
     * Get metrics for a specific host.
     *
     * @param address Host address
     * @return Host metrics or null if not tracked
     */
    @Nullable
    public static HostMetrics getHostMetrics(@NonNull String address) {
        return hostMetrics.get(address);
    }

    /**
     * Get all tracked host metrics.
     */
    @NonNull
    public static Map<String, HostMetrics> getAllHostMetrics() {
        return new HashMap<>(hostMetrics);
    }

    /**
     * Clear host metrics.
     */
    public static void clearHostMetrics() {
        hostMetrics.clear();
    }

    /**
     * Get interface statistics from /proc/net/dev.
     *
     * @param interfaceName Interface name (e.g., "wlan0")
     * @return Interface stats or null if not found
     */
    @Nullable
    public static InterfaceStats getInterfaceStats(@NonNull String interfaceName) {
        File devFile = new File("/proc/net/dev");
        if (!devFile.exists()) {
            return null;
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(devFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.startsWith(interfaceName + ":")) {
                    return parseInterfaceStats(interfaceName, line);
                }
            }
        } catch (IOException e) {
            LoggingHelper.error("Failed to read interface stats: " + e.getMessage());
        }

        return null;
    }

    private static InterfaceStats parseInterfaceStats(String name, String line) {
        // Format: interface: rx_bytes rx_packets rx_errs rx_drop ... tx_bytes tx_packets tx_errs tx_drop ...
        String[] parts = line.split("\\s+");
        if (parts.length < 17) {
            return null;
        }

        InterfaceStats stats = new InterfaceStats();
        stats.name = name;

        try {
            // Skip the interface name
            int offset = parts[0].endsWith(":") ? 1 : 2;
            stats.rxBytes = Long.parseLong(parts[offset]);
            stats.rxPackets = Long.parseLong(parts[offset + 1]);
            stats.rxErrors = Long.parseLong(parts[offset + 2]);
            stats.rxDropped = Long.parseLong(parts[offset + 3]);
            stats.txBytes = Long.parseLong(parts[offset + 8]);
            stats.txPackets = Long.parseLong(parts[offset + 9]);
            stats.txErrors = Long.parseLong(parts[offset + 10]);
            stats.txDropped = Long.parseLong(parts[offset + 11]);
        } catch (NumberFormatException | ArrayIndexOutOfBoundsException e) {
            LoggingHelper.error("Failed to parse interface stats: " + e.getMessage());
            return null;
        }

        return stats;
    }

    /**
     * Get statistics for all network interfaces.
     */
    @NonNull
    public static List<InterfaceStats> getAllInterfaceStats() {
        List<InterfaceStats> statsList = new ArrayList<>();
        File devFile = new File("/proc/net/dev");

        if (!devFile.exists()) {
            return statsList;
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(devFile))) {
            String line;
            boolean headerSkipped = false;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                // Skip header lines
                if (line.contains("|") || line.isEmpty()) {
                    headerSkipped = true;
                    continue;
                }
                if (!headerSkipped) {
                    continue;
                }

                int colonIdx = line.indexOf(':');
                if (colonIdx > 0) {
                    String ifName = line.substring(0, colonIdx).trim();
                    InterfaceStats stats = parseInterfaceStats(ifName, line);
                    if (stats != null) {
                        statsList.add(stats);
                    }
                }
            }
        } catch (IOException e) {
            LoggingHelper.error("Failed to read all interface stats: " + e.getMessage());
        }

        return statsList;
    }

    /**
     * Measure latency to a host using ping.
     *
     * @param address Host address
     * @return Latency in milliseconds or -1 if unreachable
     */
    public static long measureLatency(@NonNull String address) {
        try {
            InetAddress inet = InetAddress.getByName(address);
            long start = System.currentTimeMillis();
            boolean reachable = inet.isReachable(5000);
            long end = System.currentTimeMillis();

            if (reachable) {
                long latency = end - start;
                recordHostLatency(address, latency);
                return latency;
            }
        } catch (Exception e) {
            LoggingHelper.debug("Failed to measure latency to " + address + ": " + e.getMessage());
        }
        return -1;
    }

    /**
     * Get a comprehensive network summary.
     */
    @NonNull
    public static NetworkSummary getNetworkSummary() {
        NetworkSummary summary = new NetworkSummary();
        summary.totalRxBytes = getTotalRxBytes();
        summary.totalTxBytes = getTotalTxBytes();
        summary.currentRxSpeed = getCurrentRxSpeed();
        summary.currentTxSpeed = getCurrentTxSpeed();
        summary.hostsDiscovered = hostMetrics.size();
        summary.activeConnections = getActiveConnectionCount();
        return summary;
    }

    /**
     * Get number of active TCP connections from /proc/net/tcp.
     */
    public static int getActiveConnectionCount() {
        int count = 0;
        File tcpFile = new File("/proc/net/tcp");

        if (tcpFile.exists()) {
            try (BufferedReader reader = new BufferedReader(new FileReader(tcpFile))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    // Skip header and count established connections (state 01)
                    if (line.contains(": ") && line.contains(" 01 ")) {
                        count++;
                    }
                }
            } catch (IOException e) {
                LoggingHelper.debug("Failed to read TCP connections: " + e.getMessage());
            }
        }

        return count;
    }

    /**
     * Clear all collected metrics and reset state.
     */
    public static void reset() {
        lastRxBytes.set(0);
        lastTxBytes.set(0);
        lastUpdateTime.set(0);
        currentRxSpeed.set(0);
        currentTxSpeed.set(0);
        synchronized (bandwidthHistory) {
            bandwidthHistory.clear();
        }
        hostMetrics.clear();
    }

    /**
     * Format a bandwidth value for display.
     *
     * @param bytesPerSecond Bytes per second
     * @return Formatted string (e.g., "1.5 MB/s")
     */
    @NonNull
    public static String formatBandwidth(long bytesPerSecond) {
        return StringHelper.formatBytes(bytesPerSecond) + "/s";
    }
}
