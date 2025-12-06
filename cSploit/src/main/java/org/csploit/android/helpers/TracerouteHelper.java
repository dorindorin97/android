/*
 * This file is part of the cSploit.
 *
 * Copyleft of Simone Margaritelli aka evilsocket <evilsocket@gmail.com>
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

import android.content.Context;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Helper class for traceroute operations and hop analysis.
 * Provides utilities for parsing traceroute output, analyzing network paths,
 * and detecting routing anomalies.
 */
public final class TracerouteHelper {

    private static final String TAG = "TracerouteHelper";

    // Regex patterns for parsing traceroute output
    private static final Pattern HOP_PATTERN = Pattern.compile(
            "^\\s*(\\d+)\\s+([\\w.-]+|\\*)\\s*(?:\\(([\\d.]+)\\))?\\s*([\\d.]+)?\\s*ms");
    private static final Pattern IP_PATTERN = Pattern.compile(
            "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}");
    private static final Pattern TIMEOUT_PATTERN = Pattern.compile("^\\s*(\\d+)\\s+\\*");
    
    // Constants
    public static final int DEFAULT_MAX_HOPS = 30;
    public static final int DEFAULT_TIMEOUT_MS = 5000;
    public static final int DEFAULT_QUERIES_PER_HOP = 3;
    public static final float HIGH_LATENCY_THRESHOLD_MS = 200.0f;
    public static final float PACKET_LOSS_THRESHOLD_PERCENT = 10.0f;

    private TracerouteHelper() {
        // Private constructor to prevent instantiation
    }

    /**
     * Represents a single hop in a traceroute path.
     */
    public static class Hop {
        private final int hopNumber;
        private final String hostname;
        private final String ipAddress;
        private final List<Float> latencies;
        private final boolean isTimeout;
        private final String asn;
        private final String location;

        public Hop(int hopNumber, @Nullable String hostname, @Nullable String ipAddress,
                   @NonNull List<Float> latencies, boolean isTimeout) {
            this(hopNumber, hostname, ipAddress, latencies, isTimeout, null, null);
        }

        public Hop(int hopNumber, @Nullable String hostname, @Nullable String ipAddress,
                   @NonNull List<Float> latencies, boolean isTimeout,
                   @Nullable String asn, @Nullable String location) {
            this.hopNumber = hopNumber;
            this.hostname = hostname;
            this.ipAddress = ipAddress;
            this.latencies = new ArrayList<>(latencies);
            this.isTimeout = isTimeout;
            this.asn = asn;
            this.location = location;
        }

        public int getHopNumber() {
            return hopNumber;
        }

        @Nullable
        public String getHostname() {
            return hostname;
        }

        @Nullable
        public String getIpAddress() {
            return ipAddress;
        }

        @NonNull
        public List<Float> getLatencies() {
            return Collections.unmodifiableList(latencies);
        }

        public boolean isTimeout() {
            return isTimeout;
        }

        @Nullable
        public String getAsn() {
            return asn;
        }

        @Nullable
        public String getLocation() {
            return location;
        }

        /**
         * Gets the average latency for this hop.
         */
        public float getAverageLatency() {
            if (latencies.isEmpty()) {
                return -1;
            }
            float sum = 0;
            for (Float latency : latencies) {
                sum += latency;
            }
            return sum / latencies.size();
        }

        /**
         * Gets the minimum latency for this hop.
         */
        public float getMinLatency() {
            if (latencies.isEmpty()) {
                return -1;
            }
            float min = Float.MAX_VALUE;
            for (Float latency : latencies) {
                if (latency < min) {
                    min = latency;
                }
            }
            return min;
        }

        /**
         * Gets the maximum latency for this hop.
         */
        public float getMaxLatency() {
            if (latencies.isEmpty()) {
                return -1;
            }
            float max = Float.MIN_VALUE;
            for (Float latency : latencies) {
                if (latency > max) {
                    max = latency;
                }
            }
            return max;
        }

        /**
         * Gets the jitter (variation) in latency.
         */
        public float getJitter() {
            return getMaxLatency() - getMinLatency();
        }

        /**
         * Calculates packet loss percentage.
         */
        public float getPacketLossPercent(int expectedProbes) {
            if (expectedProbes <= 0) {
                return 0;
            }
            int received = latencies.size();
            return ((float) (expectedProbes - received) / expectedProbes) * 100;
        }

        /**
         * Checks if this hop has high latency.
         */
        public boolean hasHighLatency() {
            return getAverageLatency() > HIGH_LATENCY_THRESHOLD_MS;
        }

        @Override
        public String toString() {
            if (isTimeout) {
                return String.format(Locale.US, "%2d  * * *", hopNumber);
            }
            String host = hostname != null ? hostname : ipAddress;
            float avgLatency = getAverageLatency();
            return String.format(Locale.US, "%2d  %s  %.2f ms", hopNumber, host, avgLatency);
        }
    }

    /**
     * Represents a complete traceroute result.
     */
    public static class TracerouteResult {
        private final String destination;
        private final List<Hop> hops;
        private final long startTime;
        private final long endTime;
        private final boolean completed;
        private final String errorMessage;

        public TracerouteResult(@NonNull String destination, @NonNull List<Hop> hops,
                                long startTime, long endTime, boolean completed,
                                @Nullable String errorMessage) {
            this.destination = destination;
            this.hops = new CopyOnWriteArrayList<>(hops);
            this.startTime = startTime;
            this.endTime = endTime;
            this.completed = completed;
            this.errorMessage = errorMessage;
        }

        @NonNull
        public String getDestination() {
            return destination;
        }

        @NonNull
        public List<Hop> getHops() {
            return Collections.unmodifiableList(hops);
        }

        public long getStartTime() {
            return startTime;
        }

        public long getEndTime() {
            return endTime;
        }

        public long getDurationMs() {
            return endTime - startTime;
        }

        public boolean isCompleted() {
            return completed;
        }

        @Nullable
        public String getErrorMessage() {
            return errorMessage;
        }

        public int getHopCount() {
            return hops.size();
        }

        /**
         * Gets the overall average latency across all hops.
         */
        public float getOverallAverageLatency() {
            float sum = 0;
            int count = 0;
            for (Hop hop : hops) {
                if (!hop.isTimeout()) {
                    sum += hop.getAverageLatency();
                    count++;
                }
            }
            return count > 0 ? sum / count : -1;
        }

        /**
         * Gets the timeout percentage.
         */
        public float getTimeoutPercent() {
            if (hops.isEmpty()) {
                return 0;
            }
            int timeouts = 0;
            for (Hop hop : hops) {
                if (hop.isTimeout()) {
                    timeouts++;
                }
            }
            return ((float) timeouts / hops.size()) * 100;
        }

        /**
         * Finds the hop with the highest latency.
         */
        @Nullable
        public Hop getBottleneckHop() {
            Hop bottleneck = null;
            float maxLatency = -1;
            for (Hop hop : hops) {
                if (!hop.isTimeout() && hop.getAverageLatency() > maxLatency) {
                    maxLatency = hop.getAverageLatency();
                    bottleneck = hop;
                }
            }
            return bottleneck;
        }

        /**
         * Gets all hops with high latency.
         */
        @NonNull
        public List<Hop> getHighLatencyHops() {
            List<Hop> highLatencyHops = new ArrayList<>();
            for (Hop hop : hops) {
                if (hop.hasHighLatency()) {
                    highLatencyHops.add(hop);
                }
            }
            return highLatencyHops;
        }
    }

    /**
     * Parses a single line of traceroute output into a Hop.
     */
    @Nullable
    public static Hop parseHopLine(@NonNull String line) {
        line = line.trim();
        
        // Check for timeout
        Matcher timeoutMatcher = TIMEOUT_PATTERN.matcher(line);
        if (timeoutMatcher.find()) {
            int hopNumber = Integer.parseInt(timeoutMatcher.group(1));
            return new Hop(hopNumber, null, null, Collections.emptyList(), true);
        }

        // Parse normal hop
        Matcher hopMatcher = HOP_PATTERN.matcher(line);
        if (hopMatcher.find()) {
            int hopNumber = Integer.parseInt(hopMatcher.group(1));
            String hostname = hopMatcher.group(2);
            String ipAddress = hopMatcher.group(3);
            
            // Extract latencies
            List<Float> latencies = new ArrayList<>();
            Pattern latencyPattern = Pattern.compile("([\\d.]+)\\s*ms");
            Matcher latencyMatcher = latencyPattern.matcher(line);
            while (latencyMatcher.find()) {
                try {
                    latencies.add(Float.parseFloat(latencyMatcher.group(1)));
                } catch (NumberFormatException ignored) {
                    // Skip invalid latency values
                }
            }

            // If hostname looks like an IP, set it as IP address
            if (hostname != null && IP_PATTERN.matcher(hostname).matches()) {
                if (ipAddress == null) {
                    ipAddress = hostname;
                }
            }

            boolean isTimeout = latencies.isEmpty() || "*".equals(hostname);
            return new Hop(hopNumber, hostname, ipAddress, latencies, isTimeout);
        }

        return null;
    }

    /**
     * Parses complete traceroute output into a TracerouteResult.
     */
    @NonNull
    public static TracerouteResult parseTracerouteOutput(@NonNull String destination,
                                                          @NonNull String output,
                                                          long startTime, long endTime) {
        List<Hop> hops = new ArrayList<>();
        String[] lines = output.split("\n");
        
        for (String line : lines) {
            if (line.trim().isEmpty()) {
                continue;
            }
            Hop hop = parseHopLine(line);
            if (hop != null) {
                hops.add(hop);
            }
        }

        boolean completed = !hops.isEmpty() && 
                (hops.get(hops.size() - 1).getIpAddress() != null ||
                 hops.size() >= DEFAULT_MAX_HOPS);

        return new TracerouteResult(destination, hops, startTime, endTime, completed, null);
    }

    /**
     * Calculates the latency delta between consecutive hops.
     */
    @NonNull
    public static List<Float> calculateHopDeltas(@NonNull List<Hop> hops) {
        List<Float> deltas = new ArrayList<>();
        float previousLatency = 0;
        
        for (Hop hop : hops) {
            if (!hop.isTimeout()) {
                float currentLatency = hop.getAverageLatency();
                if (currentLatency > 0) {
                    deltas.add(currentLatency - previousLatency);
                    previousLatency = currentLatency;
                }
            }
        }
        
        return deltas;
    }

    /**
     * Detects routing anomalies in the traceroute path.
     */
    @NonNull
    public static List<String> detectAnomalies(@NonNull TracerouteResult result) {
        List<String> anomalies = new ArrayList<>();
        List<Hop> hops = result.getHops();

        // Check for high timeout percentage
        if (result.getTimeoutPercent() > 30) {
            anomalies.add(String.format(Locale.US, 
                    "High timeout rate: %.1f%% of hops timed out", result.getTimeoutPercent()));
        }

        // Check for routing loops
        List<String> seenIps = new ArrayList<>();
        for (Hop hop : hops) {
            if (hop.getIpAddress() != null) {
                if (seenIps.contains(hop.getIpAddress())) {
                    anomalies.add("Routing loop detected at hop " + hop.getHopNumber() + 
                            " (" + hop.getIpAddress() + ")");
                }
                seenIps.add(hop.getIpAddress());
            }
        }

        // Check for latency spikes
        List<Float> deltas = calculateHopDeltas(hops);
        for (int i = 0; i < deltas.size(); i++) {
            if (deltas.get(i) > HIGH_LATENCY_THRESHOLD_MS) {
                anomalies.add(String.format(Locale.US,
                        "Latency spike at hop %d: +%.2f ms", i + 1, deltas.get(i)));
            }
        }

        // Check for consecutive timeouts
        int consecutiveTimeouts = 0;
        for (Hop hop : hops) {
            if (hop.isTimeout()) {
                consecutiveTimeouts++;
                if (consecutiveTimeouts >= 3) {
                    anomalies.add("Multiple consecutive timeouts starting at hop " + 
                            (hop.getHopNumber() - 2));
                    break;
                }
            } else {
                consecutiveTimeouts = 0;
            }
        }

        // Check for asymmetric routing indicators
        float previousLatency = 0;
        for (Hop hop : hops) {
            if (!hop.isTimeout()) {
                float currentLatency = hop.getAverageLatency();
                if (currentLatency > 0 && currentLatency < previousLatency - 50) {
                    anomalies.add(String.format(Locale.US,
                            "Possible asymmetric routing at hop %d (latency decreased by %.2f ms)",
                            hop.getHopNumber(), previousLatency - currentLatency));
                }
                previousLatency = currentLatency;
            }
        }

        return anomalies;
    }

    /**
     * Identifies the network segment type based on hop characteristics.
     */
    @NonNull
    public static String identifyNetworkSegment(@NonNull Hop hop) {
        if (hop.isTimeout()) {
            return "Unknown (timeout)";
        }

        String hostname = hop.getHostname();
        String ip = hop.getIpAddress();
        float latency = hop.getAverageLatency();

        // Check for private IP ranges
        if (ip != null) {
            if (ip.startsWith("192.168.") || ip.startsWith("10.") || 
                ip.startsWith("172.16.") || ip.startsWith("172.17.") ||
                ip.startsWith("172.18.") || ip.startsWith("172.19.") ||
                ip.startsWith("172.20.") || ip.startsWith("172.21.") ||
                ip.startsWith("172.22.") || ip.startsWith("172.23.") ||
                ip.startsWith("172.24.") || ip.startsWith("172.25.") ||
                ip.startsWith("172.26.") || ip.startsWith("172.27.") ||
                ip.startsWith("172.28.") || ip.startsWith("172.29.") ||
                ip.startsWith("172.30.") || ip.startsWith("172.31.")) {
                return "Local Network";
            }
        }

        // Check hostname patterns
        if (hostname != null) {
            String lowerHostname = hostname.toLowerCase(Locale.US);
            
            if (lowerHostname.contains("gateway") || lowerHostname.contains("gw")) {
                return "Gateway";
            }
            if (lowerHostname.contains("core") || lowerHostname.contains("backbone")) {
                return "Backbone/Core";
            }
            if (lowerHostname.contains("edge") || lowerHostname.contains("border")) {
                return "Edge Router";
            }
            if (lowerHostname.contains("isp") || lowerHostname.contains("carrier")) {
                return "ISP Network";
            }
            if (lowerHostname.contains("cdn") || lowerHostname.contains("cache")) {
                return "CDN/Cache";
            }
            if (lowerHostname.contains("ix") || lowerHostname.contains("exchange")) {
                return "Internet Exchange";
            }
        }

        // Classify by latency
        if (latency < 5) {
            return "Local/LAN";
        } else if (latency < 30) {
            return "Regional";
        } else if (latency < 100) {
            return "National";
        } else {
            return "International";
        }
    }

    /**
     * Generates a summary of the traceroute result.
     */
    @NonNull
    public static String generateSummary(@NonNull TracerouteResult result) {
        StringBuilder summary = new StringBuilder();
        
        summary.append("Traceroute to ").append(result.getDestination()).append("\n");
        summary.append("==========================================\n\n");
        
        summary.append(String.format(Locale.US, "Total hops: %d\n", result.getHopCount()));
        summary.append(String.format(Locale.US, "Duration: %d ms\n", result.getDurationMs()));
        summary.append(String.format(Locale.US, "Status: %s\n\n", 
                result.isCompleted() ? "Completed" : "Incomplete"));
        
        float avgLatency = result.getOverallAverageLatency();
        if (avgLatency > 0) {
            summary.append(String.format(Locale.US, "Average latency: %.2f ms\n", avgLatency));
        }
        
        float timeoutPercent = result.getTimeoutPercent();
        if (timeoutPercent > 0) {
            summary.append(String.format(Locale.US, "Timeout rate: %.1f%%\n", timeoutPercent));
        }
        
        Hop bottleneck = result.getBottleneckHop();
        if (bottleneck != null) {
            summary.append(String.format(Locale.US, "\nBottleneck: Hop %d (%.2f ms)\n",
                    bottleneck.getHopNumber(), bottleneck.getAverageLatency()));
        }
        
        List<String> anomalies = detectAnomalies(result);
        if (!anomalies.isEmpty()) {
            summary.append("\nAnomalies detected:\n");
            for (String anomaly : anomalies) {
                summary.append("  • ").append(anomaly).append("\n");
            }
        }
        
        return summary.toString();
    }

    /**
     * Formats a hop for display.
     */
    @NonNull
    public static String formatHop(@NonNull Hop hop, boolean showDetails) {
        StringBuilder sb = new StringBuilder();
        
        sb.append(String.format(Locale.US, "%2d  ", hop.getHopNumber()));
        
        if (hop.isTimeout()) {
            sb.append("* * *");
        } else {
            String display = hop.getHostname() != null ? hop.getHostname() : hop.getIpAddress();
            sb.append(display);
            
            if (hop.getHostname() != null && hop.getIpAddress() != null && 
                !hop.getHostname().equals(hop.getIpAddress())) {
                sb.append(" (").append(hop.getIpAddress()).append(")");
            }
            
            List<Float> latencies = hop.getLatencies();
            for (Float latency : latencies) {
                sb.append(String.format(Locale.US, "  %.2f ms", latency));
            }
            
            if (showDetails) {
                sb.append("\n     Segment: ").append(identifyNetworkSegment(hop));
                if (hop.hasHighLatency()) {
                    sb.append(" [HIGH LATENCY]");
                }
            }
        }
        
        return sb.toString();
    }

    /**
     * Calculates path efficiency compared to direct distance.
     */
    public static float calculatePathEfficiency(@NonNull TracerouteResult result) {
        List<Hop> hops = result.getHops();
        if (hops.isEmpty()) {
            return 0;
        }

        // Estimate efficiency based on hop count and latency patterns
        int totalHops = hops.size();
        int timeouts = 0;
        int highLatencyHops = 0;

        for (Hop hop : hops) {
            if (hop.isTimeout()) {
                timeouts++;
            } else if (hop.hasHighLatency()) {
                highLatencyHops++;
            }
        }

        // Calculate efficiency score (0-100)
        float hopPenalty = Math.min(totalHops * 2, 40);
        float timeoutPenalty = (timeouts / (float) totalHops) * 30;
        float latencyPenalty = (highLatencyHops / (float) totalHops) * 30;

        return Math.max(0, 100 - hopPenalty - timeoutPenalty - latencyPenalty);
    }

    /**
     * Compares two traceroute results.
     */
    @NonNull
    public static String compareRoutes(@NonNull TracerouteResult route1, 
                                       @NonNull TracerouteResult route2) {
        StringBuilder comparison = new StringBuilder();
        
        comparison.append("Route Comparison\n");
        comparison.append("================\n\n");
        
        comparison.append(String.format(Locale.US, "%-25s %-15s %-15s\n", 
                "Metric", "Route 1", "Route 2"));
        comparison.append(String.format(Locale.US, "%-25s %-15d %-15d\n",
                "Hop Count", route1.getHopCount(), route2.getHopCount()));
        comparison.append(String.format(Locale.US, "%-25s %-15.2f %-15.2f\n",
                "Avg Latency (ms)", route1.getOverallAverageLatency(), 
                route2.getOverallAverageLatency()));
        comparison.append(String.format(Locale.US, "%-25s %-15.1f%% %-15.1f%%\n",
                "Timeout Rate", route1.getTimeoutPercent(), route2.getTimeoutPercent()));
        comparison.append(String.format(Locale.US, "%-25s %-15.1f %-15.1f\n",
                "Path Efficiency", calculatePathEfficiency(route1), 
                calculatePathEfficiency(route2)));
        
        // Find common hops
        List<String> commonIps = new ArrayList<>();
        for (Hop hop1 : route1.getHops()) {
            if (hop1.getIpAddress() != null) {
                for (Hop hop2 : route2.getHops()) {
                    if (hop1.getIpAddress().equals(hop2.getIpAddress())) {
                        commonIps.add(hop1.getIpAddress());
                        break;
                    }
                }
            }
        }
        
        comparison.append(String.format(Locale.US, "\nCommon hops: %d\n", commonIps.size()));
        
        return comparison.toString();
    }
}
