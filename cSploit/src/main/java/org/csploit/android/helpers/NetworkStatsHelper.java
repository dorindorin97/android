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

import org.csploit.android.core.System;
import org.csploit.android.net.Target;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * NetworkStatsHelper - Provides comprehensive network statistics and analytics.
 *
 * Features:
 * - Target statistics (counts, types, status)
 * - Port statistics (most common ports, services)
 * - Vulnerability statistics
 * - Performance metrics tracking
 * - Network health indicators
 *
 * Usage:
 * {@code
 * NetworkStatsHelper stats = NetworkStatsHelper.getInstance();
 * NetworkSummary summary = stats.getNetworkSummary();
 * List<PortStatistic> topPorts = stats.getTopOpenPorts(10);
 * }
 */
public final class NetworkStatsHelper {
    private static final String TAG = "NetworkStatsHelper";

    private static volatile NetworkStatsHelper sInstance;
    private final AtomicLong mPacketsSent = new AtomicLong(0);
    private final AtomicLong mPacketsReceived = new AtomicLong(0);
    private final AtomicLong mBytesTransferred = new AtomicLong(0);
    private long mScanStartTime = 0;
    private long mLastUpdateTime = 0;

    private NetworkStatsHelper() {
        mLastUpdateTime = java.lang.System.currentTimeMillis();
    }

    /**
     * Get singleton instance
     */
    @NonNull
    public static NetworkStatsHelper getInstance() {
        if (sInstance == null) {
            synchronized (NetworkStatsHelper.class) {
                if (sInstance == null) {
                    sInstance = new NetworkStatsHelper();
                }
            }
        }
        return sInstance;
    }

    /**
     * Get comprehensive network summary
     */
    @NonNull
    public NetworkSummary getNetworkSummary() {
        return new NetworkSummary();
    }

    /**
     * Get top N most commonly open ports across all targets
     */
    @NonNull
    public List<PortStatistic> getTopOpenPorts(int limit) {
        Map<Integer, PortStatistic> portCounts = new HashMap<>();

        for (Target target : System.getTargets()) {
            for (Target.Port port : target.getOpenPorts()) {
                int portNum = port.getNumber();
                PortStatistic stat = portCounts.get(portNum);
                if (stat == null) {
                    stat = new PortStatistic(portNum, port.getService());
                    portCounts.put(portNum, stat);
                }
                stat.incrementCount();
            }
        }

        List<PortStatistic> result = new ArrayList<>(portCounts.values());
        result.sort((a, b) -> Integer.compare(b.count, a.count));

        if (result.size() > limit) {
            return result.subList(0, limit);
        }
        return result;
    }

    /**
     * Get targets grouped by device type
     */
    @NonNull
    public Map<String, List<Target>> getTargetsByDeviceType() {
        Map<String, List<Target>> result = new HashMap<>();

        for (Target target : System.getTargets()) {
            String deviceType = target.getDeviceType();
            if (deviceType == null || deviceType.isEmpty()) {
                deviceType = "Unknown";
            }

            List<Target> list = result.get(deviceType);
            if (list == null) {
                list = new ArrayList<>();
                result.put(deviceType, list);
            }
            list.add(target);
        }

        return result;
    }

    /**
     * Get targets grouped by operating system
     */
    @NonNull
    public Map<String, List<Target>> getTargetsByOS() {
        Map<String, List<Target>> result = new HashMap<>();

        for (Target target : System.getTargets()) {
            String os = target.getDeviceOS();
            if (os == null || os.isEmpty()) {
                os = "Unknown";
            }

            List<Target> list = result.get(os);
            if (list == null) {
                list = new ArrayList<>();
                result.put(os, list);
            }
            list.add(target);
        }

        return result;
    }

    /**
     * Get vulnerability statistics
     */
    @NonNull
    public VulnerabilityStats getVulnerabilityStats() {
        return new VulnerabilityStats();
    }

    /**
     * Record packet sent for statistics
     */
    public void recordPacketSent(long bytes) {
        mPacketsSent.incrementAndGet();
        mBytesTransferred.addAndGet(bytes);
    }

    /**
     * Record packet received for statistics
     */
    public void recordPacketReceived(long bytes) {
        mPacketsReceived.incrementAndGet();
        mBytesTransferred.addAndGet(bytes);
    }

    /**
     * Start scan timer
     */
    public void startScanTimer() {
        mScanStartTime = java.lang.System.currentTimeMillis();
    }

    /**
     * Get scan duration in milliseconds
     */
    public long getScanDuration() {
        if (mScanStartTime == 0) {
            return 0;
        }
        return java.lang.System.currentTimeMillis() - mScanStartTime;
    }

    /**
     * Reset all statistics
     */
    public void reset() {
        mPacketsSent.set(0);
        mPacketsReceived.set(0);
        mBytesTransferred.set(0);
        mScanStartTime = 0;
        mLastUpdateTime = java.lang.System.currentTimeMillis();
    }

    /**
     * Get performance metrics
     */
    @NonNull
    public PerformanceMetrics getPerformanceMetrics() {
        return new PerformanceMetrics();
    }

    /**
     * Network summary statistics
     */
    public static class NetworkSummary {
        public final int totalTargets;
        public final int endpointTargets;
        public final int networkTargets;
        public final int remoteTargets;
        public final int connectedTargets;
        public final int targetsWithOpenPorts;
        public final int targetsWithVulnerabilities;
        public final int totalOpenPorts;
        public final int totalVulnerabilities;
        public final int selectedTargets;
        public final String networkAddress;
        public final String gatewayAddress;
        public final String localAddress;

        NetworkSummary() {
            List<Target> targets = System.getTargets();
            this.totalTargets = targets.size();

            int ep = 0, net = 0, rem = 0, conn = 0, ports = 0, vuln = 0, sel = 0;
            int totalPorts = 0, totalVulns = 0;

            for (Target t : targets) {
                switch (t.getType()) {
                    case ENDPOINT: ep++; break;
                    case NETWORK: net++; break;
                    case REMOTE: rem++; break;
                }
                if (t.isConnected()) conn++;
                if (t.hasOpenPorts()) {
                    ports++;
                    totalPorts += t.getOpenPorts().size();
                }
                if (!t.getExploits().isEmpty()) {
                    vuln++;
                    totalVulns += t.getExploits().size();
                }
                if (t.isSelected()) sel++;
            }

            this.endpointTargets = ep;
            this.networkTargets = net;
            this.remoteTargets = rem;
            this.connectedTargets = conn;
            this.targetsWithOpenPorts = ports;
            this.targetsWithVulnerabilities = vuln;
            this.totalOpenPorts = totalPorts;
            this.totalVulnerabilities = totalVulns;
            this.selectedTargets = sel;

            // Network info
            if (System.getNetwork() != null) {
                this.networkAddress = System.getNetwork().getNetworkRepresentation();
                this.gatewayAddress = System.getNetwork().getGatewayAddress() != null ?
                        System.getNetwork().getGatewayAddress().getHostAddress() : "N/A";
                this.localAddress = System.getNetwork().getLocalAddressAsString();
            } else {
                this.networkAddress = "N/A";
                this.gatewayAddress = "N/A";
                this.localAddress = "N/A";
            }
        }

        @Override
        public String toString() {
            return String.format(
                "NetworkSummary{targets=%d (EP:%d, NET:%d, REM:%d), " +
                "connected=%d, withPorts=%d (%d total), withVulns=%d (%d total), selected=%d}",
                totalTargets, endpointTargets, networkTargets, remoteTargets,
                connectedTargets, targetsWithOpenPorts, totalOpenPorts,
                targetsWithVulnerabilities, totalVulnerabilities, selectedTargets
            );
        }

        /**
         * Get formatted summary for display
         */
        public String getFormattedSummary() {
            StringBuilder sb = new StringBuilder();
            sb.append("Network: ").append(networkAddress).append("\n");
            sb.append("Gateway: ").append(gatewayAddress).append("\n");
            sb.append("Local IP: ").append(localAddress).append("\n");
            sb.append("---\n");
            sb.append("Targets: ").append(totalTargets).append("\n");
            sb.append("  - Endpoints: ").append(endpointTargets).append("\n");
            sb.append("  - Networks: ").append(networkTargets).append("\n");
            sb.append("  - Remote: ").append(remoteTargets).append("\n");
            sb.append("Connected: ").append(connectedTargets).append("\n");
            sb.append("Open Ports: ").append(totalOpenPorts).append(" (on ").append(targetsWithOpenPorts).append(" hosts)\n");
            sb.append("Vulnerabilities: ").append(totalVulnerabilities).append(" (on ").append(targetsWithVulnerabilities).append(" hosts)\n");
            return sb.toString();
        }
    }

    /**
     * Port statistics
     */
    public static class PortStatistic {
        public final int portNumber;
        public final String serviceName;
        public int count;

        PortStatistic(int portNumber, @Nullable String serviceName) {
            this.portNumber = portNumber;
            this.serviceName = serviceName != null ? serviceName : "Unknown";
            this.count = 0;
        }

        void incrementCount() {
            count++;
        }

        @Override
        public String toString() {
            return String.format("Port %d (%s): %d hosts", portNumber, serviceName, count);
        }
    }

    /**
     * Vulnerability statistics
     */
    public static class VulnerabilityStats {
        public final int totalVulnerabilities;
        public final int criticalCount;
        public final int highCount;
        public final int mediumCount;
        public final int lowCount;
        public final int affectedHosts;
        public final Map<String, Integer> byType;

        VulnerabilityStats() {
            List<Target> targets = System.getTargets();
            this.byType = new HashMap<>();

            int total = 0, critical = 0, high = 0, medium = 0, low = 0, hosts = 0;

            for (Target target : targets) {
                if (!target.getExploits().isEmpty()) {
                    hosts++;
                    for (Target.Exploit exploit : target.getExploits()) {
                        total++;
                        String type = exploit.getClass().getSimpleName();
                        byType.merge(type, 1, Integer::sum);
                    }
                }
            }

            this.totalVulnerabilities = total;
            this.criticalCount = critical;
            this.highCount = high;
            this.mediumCount = medium;
            this.lowCount = low;
            this.affectedHosts = hosts;
        }

        @Override
        public String toString() {
            return String.format(
                "VulnerabilityStats{total=%d, hosts=%d, types=%s}",
                totalVulnerabilities, affectedHosts, byType.keySet()
            );
        }
    }

    /**
     * Performance metrics
     */
    public class PerformanceMetrics {
        public final long packetsSent;
        public final long packetsReceived;
        public final long bytesTransferred;
        public final long scanDurationMs;
        public final double packetsPerSecond;

        PerformanceMetrics() {
            this.packetsSent = mPacketsSent.get();
            this.packetsReceived = mPacketsReceived.get();
            this.bytesTransferred = mBytesTransferred.get();
            this.scanDurationMs = getScanDuration();

            if (scanDurationMs > 0) {
                this.packetsPerSecond = (packetsSent + packetsReceived) * 1000.0 / scanDurationMs;
            } else {
                this.packetsPerSecond = 0;
            }
        }

        @Override
        public String toString() {
            return String.format(
                "PerformanceMetrics{sent=%d, recv=%d, bytes=%d, duration=%dms, rate=%.2f pps}",
                packetsSent, packetsReceived, bytesTransferred, scanDurationMs, packetsPerSecond
            );
        }

        /**
         * Get human-readable bytes transferred
         */
        public String getFormattedBytesTransferred() {
            return formatBytes(bytesTransferred);
        }

        /**
         * Get human-readable scan duration
         */
        public String getFormattedDuration() {
            if (scanDurationMs < 1000) {
                return scanDurationMs + "ms";
            } else if (scanDurationMs < 60000) {
                return String.format("%.1fs", scanDurationMs / 1000.0);
            } else {
                long minutes = scanDurationMs / 60000;
                long seconds = (scanDurationMs % 60000) / 1000;
                return String.format("%dm %ds", minutes, seconds);
            }
        }

        private String formatBytes(long bytes) {
            if (bytes < 1024) return bytes + " B";
            if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
            if (bytes < 1024 * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024));
            return String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024));
        }
    }
}
