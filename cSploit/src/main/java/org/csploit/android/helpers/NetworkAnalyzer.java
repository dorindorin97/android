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

import org.csploit.android.core.System;
import org.csploit.android.helpers.LoggingHelper;
import org.csploit.android.net.Network;
import org.csploit.android.helpers.LoggingHelper;
import org.csploit.android.net.Target;
import org.csploit.android.helpers.LoggingHelper;

import java.util.ArrayList;
import org.csploit.android.helpers.LoggingHelper;
import java.util.Collections;
import org.csploit.android.helpers.LoggingHelper;
import java.util.HashMap;
import org.csploit.android.helpers.LoggingHelper;
import java.util.List;
import org.csploit.android.helpers.LoggingHelper;
import java.util.Map;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.ConcurrentHashMap;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.CountDownLatch;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.TimeUnit;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.atomic.AtomicBoolean;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.atomic.AtomicInteger;
import org.csploit.android.helpers.LoggingHelper;

/**
 * NetworkAnalyzer - Comprehensive network analysis and statistics utility
 *
 * Provides:
 * - Network topology analysis
 * - Traffic pattern detection
 * - Host classification
 * - Network statistics aggregation
 * - Anomaly detection
 * - Network health assessment
 */
public final class NetworkAnalyzer {

    private static final String TAG = "NetworkAnalyzer";
    private static volatile NetworkAnalyzer instance;

    private final AtomicBoolean isAnalyzing = new AtomicBoolean(false);
    private final Map<String, HostProfile> hostProfiles = new ConcurrentHashMap<>();
    private final Map<String, NetworkSegment> segments = new ConcurrentHashMap<>();

    /**
     * Host classification types
     */
    public enum HostType {
        GATEWAY("Gateway", "Network router/gateway device"),
        SERVER("Server", "Server providing network services"),
        WORKSTATION("Workstation", "Desktop or laptop computer"),
        MOBILE("Mobile", "Mobile device (phone/tablet)"),
        IOT("IoT", "Internet of Things device"),
        PRINTER("Printer", "Network printer"),
        NETWORK_DEVICE("Network Device", "Switch, access point, etc."),
        UNKNOWN("Unknown", "Unclassified device");

        private final String name;
        private final String description;

        HostType(String name, String description) {
            this.name = name;
            this.description = description;
        }

        public String getName() { return name; }
        public String getDescription() { return description; }
    }

    /**
     * Network health status
     */
    public enum HealthStatus {
        EXCELLENT(5, "Excellent", "Network is functioning optimally"),
        GOOD(4, "Good", "Network is healthy with minor issues"),
        FAIR(3, "Fair", "Some issues detected, monitoring recommended"),
        POOR(2, "Poor", "Multiple issues detected, action recommended"),
        CRITICAL(1, "Critical", "Severe issues detected, immediate action required");

        private final int level;
        private final String name;
        private final String description;

        HealthStatus(int level, String name, String description) {
            this.level = level;
            this.name = name;
            this.description = description;
        }

        public int getLevel() { return level; }
        public String getName() { return name; }
        public String getDescription() { return description; }
    }

    /**
     * Host profile with detailed information
     */
    public static class HostProfile {
        private final String targetUuid;
        private final String ipAddress;
        private final String macAddress;
        private HostType hostType = HostType.UNKNOWN;
        private final List<Integer> openPorts = new ArrayList<>();
        private final List<String> services = new ArrayList<>();
        private String operatingSystem;
        private String hostname;
        private long firstSeen;
        private long lastSeen;
        private int activityScore;
        private boolean isActive = true;

        public HostProfile(String targetUuid, String ipAddress, String macAddress) {
            this.targetUuid = targetUuid;
            this.ipAddress = ipAddress;
            this.macAddress = macAddress;
            this.firstSeen = java.lang.System.currentTimeMillis();
            this.lastSeen = this.firstSeen;
        }

        // Getters
        public String getTargetUuid() { return targetUuid; }
        public String getIpAddress() { return ipAddress; }
        public String getMacAddress() { return macAddress; }
        public HostType getHostType() { return hostType; }
        public List<Integer> getOpenPorts() { return Collections.unmodifiableList(openPorts); }
        public List<String> getServices() { return Collections.unmodifiableList(services); }
        public String getOperatingSystem() { return operatingSystem; }
        public String getHostname() { return hostname; }
        public long getFirstSeen() { return firstSeen; }
        public long getLastSeen() { return lastSeen; }
        public int getActivityScore() { return activityScore; }
        public boolean isActive() { return isActive; }

        // Setters
        public void setHostType(HostType type) { this.hostType = type; }
        public void setOperatingSystem(String os) { this.operatingSystem = os; }
        public void setHostname(String hostname) { this.hostname = hostname; }
        public void setActive(boolean active) { this.isActive = active; }
        public void updateLastSeen() { this.lastSeen = java.lang.System.currentTimeMillis(); }
        public void incrementActivityScore() { this.activityScore++; }

        public void addOpenPort(int port) {
            if (!openPorts.contains(port)) {
                openPorts.add(port);
            }
        }

        public void addService(String service) {
            if (service != null && !services.contains(service)) {
                services.add(service);
            }
        }
    }

    /**
     * Network segment information
     */
    public static class NetworkSegment {
        private final String networkAddress;
        private final int cidr;
        private final List<String> hostUuids = new ArrayList<>();
        private int activeHosts;
        private int totalHosts;

        public NetworkSegment(String networkAddress, int cidr) {
            this.networkAddress = networkAddress;
            this.cidr = cidr;
        }

        public String getNetworkAddress() { return networkAddress; }
        public int getCidr() { return cidr; }
        public List<String> getHostUuids() { return Collections.unmodifiableList(hostUuids); }
        public int getActiveHosts() { return activeHosts; }
        public int getTotalHosts() { return totalHosts; }

        public void addHost(String uuid) {
            if (!hostUuids.contains(uuid)) {
                hostUuids.add(uuid);
                totalHosts++;
            }
        }

        public void setActiveHosts(int count) { this.activeHosts = count; }
    }

    /**
     * Network analysis result
     */
    public static class AnalysisResult {
        private final long timestamp;
        private final int totalHosts;
        private final int activeHosts;
        private final Map<HostType, Integer> hostTypeCounts;
        private final List<String> anomalies;
        private final HealthStatus healthStatus;
        private final double securityScore;
        private final Map<String, HostProfile> hostProfiles;

        private AnalysisResult(Builder builder) {
            this.timestamp = builder.timestamp;
            this.totalHosts = builder.totalHosts;
            this.activeHosts = builder.activeHosts;
            this.hostTypeCounts = Collections.unmodifiableMap(new HashMap<>(builder.hostTypeCounts));
            this.anomalies = Collections.unmodifiableList(new ArrayList<>(builder.anomalies));
            this.healthStatus = builder.healthStatus;
            this.securityScore = builder.securityScore;
            this.hostProfiles = Collections.unmodifiableMap(new HashMap<>(builder.hostProfiles));
        }

        public long getTimestamp() { return timestamp; }
        public int getTotalHosts() { return totalHosts; }
        public int getActiveHosts() { return activeHosts; }
        public Map<HostType, Integer> getHostTypeCounts() { return hostTypeCounts; }
        public List<String> getAnomalies() { return anomalies; }
        public HealthStatus getHealthStatus() { return healthStatus; }
        public double getSecurityScore() { return securityScore; }
        public Map<String, HostProfile> getHostProfiles() { return hostProfiles; }

        @NonNull
        @Override
        public String toString() {
            return String.format("NetworkAnalysis[%d hosts (%d active), Health: %s, Security: %.1f%%]",
                    totalHosts, activeHosts, healthStatus.getName(), securityScore);
        }

        public static class Builder {
            private long timestamp;
            private int totalHosts;
            private int activeHosts;
            private Map<HostType, Integer> hostTypeCounts = new HashMap<>();
            private List<String> anomalies = new ArrayList<>();
            private HealthStatus healthStatus = HealthStatus.FAIR;
            private double securityScore = 50.0;
            private Map<String, HostProfile> hostProfiles = new HashMap<>();

            public Builder() {
                this.timestamp = java.lang.System.currentTimeMillis();
                for (HostType type : HostType.values()) {
                    hostTypeCounts.put(type, 0);
                }
            }

            public Builder totalHosts(int val) { totalHosts = val; return this; }
            public Builder activeHosts(int val) { activeHosts = val; return this; }
            public Builder incrementHostType(HostType type) {
                hostTypeCounts.put(type, hostTypeCounts.get(type) + 1);
                return this;
            }
            public Builder addAnomaly(String anomaly) { anomalies.add(anomaly); return this; }
            public Builder healthStatus(HealthStatus status) { healthStatus = status; return this; }
            public Builder securityScore(double score) { securityScore = score; return this; }
            public Builder addHostProfile(HostProfile profile) {
                hostProfiles.put(profile.getTargetUuid(), profile);
                return this;
            }

            public AnalysisResult build() {
                return new AnalysisResult(this);
            }
        }
    }

    /**
     * Callback interface for analysis events
     */
    public interface AnalysisCallback {
        void onAnalysisStarted();
        void onHostAnalyzed(Target target, HostProfile profile);
        void onProgress(int current, int total);
        void onAnalysisComplete(AnalysisResult result);
        void onError(String error);
    }

    private NetworkAnalyzer() {}

    public static NetworkAnalyzer getInstance() {
        if (instance == null) {
            synchronized (NetworkAnalyzer.class) {
                if (instance == null) {
                    instance = new NetworkAnalyzer();
                }
            }
        }
        return instance;
    }

    /**
     * Perform comprehensive network analysis
     */
    public void analyze(@NonNull AnalysisCallback callback) {
        if (isAnalyzing.get()) {
            callback.onError("Analysis already in progress");
            return;
        }

        isAnalyzing.set(true);

        ThreadHelper.executeBackground(() -> {
            AnalysisResult.Builder resultBuilder = new AnalysisResult.Builder();

            try {
                ThreadHelper.runOnMainThread(callback::onAnalysisStarted);

                List<Target> targets = System.getTargets();
                int total = targets.size();
                AtomicInteger current = new AtomicInteger(0);
                int activeCount = 0;

                for (Target target : targets) {
                    if (target.getType() == Target.Type.NETWORK) {
                        continue;
                    }

                    HostProfile profile = analyzeHost(target);
                    if (profile != null) {
                        hostProfiles.put(target.getUuid(), profile);
                        resultBuilder.addHostProfile(profile);
                        resultBuilder.incrementHostType(profile.getHostType());

                        if (profile.isActive()) {
                            activeCount++;
                        }

                        final HostProfile finalProfile = profile;
                        ThreadHelper.runOnMainThread(() -> callback.onHostAnalyzed(target, finalProfile));
                    }

                    int progress = current.incrementAndGet();
                    ThreadHelper.runOnMainThread(() -> callback.onProgress(progress, total));
                }

                // Calculate health and security scores
                resultBuilder.totalHosts(targets.size())
                        .activeHosts(activeCount);

                // Detect anomalies
                detectAnomalies(resultBuilder, targets);

                // Calculate security score
                double securityScore = calculateSecurityScore(targets);
                resultBuilder.securityScore(securityScore);

                // Determine health status
                HealthStatus health = determineHealthStatus(securityScore, resultBuilder);
                resultBuilder.healthStatus(health);

                AnalysisResult result = resultBuilder.build();
                ThreadHelper.runOnMainThread(() -> callback.onAnalysisComplete(result));

            } catch (Exception e) {
                LoggingHelper.e(TAG, "Analysis error", e);
                ThreadHelper.runOnMainThread(() -> callback.onError(e.getMessage()));
            } finally {
                isAnalyzing.set(false);
            }
        });
    }

    /**
     * Analyze a single host
     */
    @Nullable
    private HostProfile analyzeHost(Target target) {
        if (target == null || target.getAddress() == null) {
            return null;
        }

        String ipAddress = target.getAddress().getHostAddress();
        byte[] mac = target.getHardwareAddress();
        String macAddress = mac != null ? NetworkHelper.bytesToMac(mac) : "";

        HostProfile profile = new HostProfile(target.getUuid(), ipAddress, macAddress);

        // Add open ports
        for (Target.Port port : target.getOpenPorts()) {
            profile.addOpenPort(port.getNumber());
            if (port.haveService()) {
                profile.addService(port.getService());
            }
        }

        // Set OS and hostname
        if (target.getDeviceOS() != null) {
            profile.setOperatingSystem(target.getDeviceOS());
        }
        if (target.hasAlias()) {
            profile.setHostname(target.getAlias());
        }

        // Classify host type
        profile.setHostType(classifyHost(target, profile));
        profile.setActive(target.isConnected());

        return profile;
    }

    /**
     * Classify a host based on its characteristics
     */
    private HostType classifyHost(Target target, HostProfile profile) {
        // Check if it's the gateway
        if (target.isRouter()) {
            return HostType.GATEWAY;
        }

        List<Integer> ports = profile.getOpenPorts();
        List<String> services = profile.getServices();
        String os = profile.getOperatingSystem();

        // Server detection
        if (hasServerPorts(ports) || hasServerServices(services)) {
            return HostType.SERVER;
        }

        // Printer detection
        if (ports.contains(9100) || ports.contains(515) || ports.contains(631)) {
            return HostType.PRINTER;
        }

        // IoT detection
        if (isLikelyIoT(ports, services, os)) {
            return HostType.IOT;
        }

        // Mobile detection
        if (os != null && (os.toLowerCase().contains("android") || os.toLowerCase().contains("ios"))) {
            return HostType.MOBILE;
        }

        // Workstation detection
        if (os != null && (os.toLowerCase().contains("windows") ||
                          os.toLowerCase().contains("mac") ||
                          os.toLowerCase().contains("linux"))) {
            return HostType.WORKSTATION;
        }

        return HostType.UNKNOWN;
    }

    private boolean hasServerPorts(List<Integer> ports) {
        int[] serverPorts = {21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432};
        for (int sp : serverPorts) {
            if (ports.contains(sp)) {
                return true;
            }
        }
        return false;
    }

    private boolean hasServerServices(List<String> services) {
        String[] serverServices = {"http", "https", "ssh", "ftp", "smtp", "dns", "mysql", "postgresql"};
        for (String service : services) {
            for (String ss : serverServices) {
                if (service.toLowerCase().contains(ss)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean isLikelyIoT(List<Integer> ports, List<String> services, String os) {
        // Common IoT ports
        if (ports.contains(8080) || ports.contains(8443) || ports.contains(1883) || ports.contains(8883)) {
            // Check if it's not a typical server
            if (!ports.contains(22) && !ports.contains(80)) {
                return true;
            }
        }
        return false;
    }

    private void detectAnomalies(AnalysisResult.Builder builder, List<Target> targets) {
        // Detect unusual open ports
        for (Target target : targets) {
            if (target.getType() == Target.Type.NETWORK) continue;

            List<Target.Port> ports = target.getOpenPorts();

            // Check for Telnet (insecure)
            for (Target.Port port : ports) {
                if (port.getNumber() == 23) {
                    builder.addAnomaly("Telnet service detected on " + target.getDisplayAddress());
                }
                // Check for unencrypted FTP
                if (port.getNumber() == 21) {
                    builder.addAnomaly("FTP service detected on " + target.getDisplayAddress());
                }
            }

            // Check for too many open ports
            if (ports.size() > 20) {
                builder.addAnomaly("Unusually high number of open ports on " + target.getDisplayAddress());
            }
        }
    }

    private double calculateSecurityScore(List<Target> targets) {
        double score = 100.0;
        int targetCount = 0;

        for (Target target : targets) {
            if (target.getType() == Target.Type.NETWORK) continue;
            targetCount++;

            List<Target.Port> ports = target.getOpenPorts();

            // Deduct for insecure services
            for (Target.Port port : ports) {
                int portNum = port.getNumber();
                // Telnet
                if (portNum == 23) score -= 5;
                // FTP
                if (portNum == 21) score -= 3;
                // Unencrypted services
                if (portNum == 110 || portNum == 143) score -= 2;
            }

            // Deduct for exploits
            if (target.hasExploits()) {
                score -= target.getExploits().size() * 5;
            }
        }

        return Math.max(0, Math.min(100, score));
    }

    private HealthStatus determineHealthStatus(double securityScore, AnalysisResult.Builder builder) {
        int anomalyCount = 0;
        // Count anomalies from builder

        if (securityScore >= 90) {
            return HealthStatus.EXCELLENT;
        } else if (securityScore >= 70) {
            return HealthStatus.GOOD;
        } else if (securityScore >= 50) {
            return HealthStatus.FAIR;
        } else if (securityScore >= 30) {
            return HealthStatus.POOR;
        } else {
            return HealthStatus.CRITICAL;
        }
    }

    /**
     * Get cached host profile
     */
    @Nullable
    public HostProfile getHostProfile(String targetUuid) {
        return hostProfiles.get(targetUuid);
    }

    /**
     * Check if analysis is in progress
     */
    public boolean isAnalyzing() {
        return isAnalyzing.get();
    }

    /**
     * Clear all cached data
     */
    public void clearCache() {
        hostProfiles.clear();
        segments.clear();
    }
}
