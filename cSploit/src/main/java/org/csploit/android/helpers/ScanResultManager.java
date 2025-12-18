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

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * ScanResultManager - Manages and organizes scan results.
 *
 * Provides:
 * - Result storage and retrieval
 * - Result comparison and diffing
 * - Export to multiple formats
 * - Result filtering and searching
 * - Historical tracking
 *
 * Usage:
 * {@code
 * // Store scan result
 * ScanResultManager.getInstance().storeScanResult(result);
 *
 * // Get all results for target
 * List<ScanResult> results = ScanResultManager.getInstance().getResultsForTarget(targetId);
 *
 * // Export to CSV
 * ScanResultManager.getInstance().exportToCSV(results, outputPath);
 * }
 */
public final class ScanResultManager {

    private static final String TAG = "ScanResultManager";
    private static volatile ScanResultManager instance;

    private final Map<String, List<ScanResult>> resultsByTarget;
    private final Map<String, ScanResult> resultsById;
    private final AtomicLong resultIdCounter;
    private String storagePath;

    /**
     * Scan result data class.
     */
    public static class ScanResult {
        private final String id;
        private final String targetId;
        private final String targetAddress;
        private final ScanType scanType;
        private final long startTime;
        private long endTime;
        private ScanStatus status;
        private final List<PortResult> portResults;
        private final List<ServiceResult> serviceResults;
        private final Map<String, String> metadata;
        private String errorMessage;

        public ScanResult(@NonNull String targetId, @NonNull String targetAddress, @NonNull ScanType scanType) {
            this.id = java.util.UUID.randomUUID().toString();
            this.targetId = targetId;
            this.targetAddress = targetAddress;
            this.scanType = scanType;
            this.startTime = System.currentTimeMillis();
            this.status = ScanStatus.IN_PROGRESS;
            this.portResults = new ArrayList<>();
            this.serviceResults = new ArrayList<>();
            this.metadata = new HashMap<>();
        }

        public String getId() { return id; }
        public String getTargetId() { return targetId; }
        public String getTargetAddress() { return targetAddress; }
        public ScanType getScanType() { return scanType; }
        public long getStartTime() { return startTime; }
        public long getEndTime() { return endTime; }
        public long getDuration() { return endTime > 0 ? endTime - startTime : System.currentTimeMillis() - startTime; }
        public ScanStatus getStatus() { return status; }
        public List<PortResult> getPortResults() { return Collections.unmodifiableList(portResults); }
        public List<ServiceResult> getServiceResults() { return Collections.unmodifiableList(serviceResults); }
        public Map<String, String> getMetadata() { return Collections.unmodifiableMap(metadata); }
        public String getErrorMessage() { return errorMessage; }

        public void complete() {
            this.endTime = System.currentTimeMillis();
            this.status = ScanStatus.COMPLETED;
        }

        public void fail(@NonNull String error) {
            this.endTime = System.currentTimeMillis();
            this.status = ScanStatus.FAILED;
            this.errorMessage = error;
        }

        public void addPortResult(@NonNull PortResult result) {
            portResults.add(result);
        }

        public void addServiceResult(@NonNull ServiceResult result) {
            serviceResults.add(result);
        }

        public void setMetadata(@NonNull String key, @NonNull String value) {
            metadata.put(key, value);
        }

        public int getOpenPortCount() {
            int count = 0;
            for (PortResult pr : portResults) {
                if (pr.isOpen()) count++;
            }
            return count;
        }

        @NonNull
        @Override
        public String toString() {
            return String.format("ScanResult{target='%s', type=%s, status=%s, ports=%d}",
                    targetAddress, scanType, status, portResults.size());
        }
    }

    /**
     * Port scan result.
     */
    public static class PortResult {
        private final int port;
        private final String protocol;
        private final boolean open;
        private String service;
        private String version;
        private String banner;
        private long responseTime;

        public PortResult(int port, @NonNull String protocol, boolean open) {
            this.port = port;
            this.protocol = protocol;
            this.open = open;
        }

        public int getPort() { return port; }
        public String getProtocol() { return protocol; }
        public boolean isOpen() { return open; }
        public String getService() { return service; }
        public String getVersion() { return version; }
        public String getBanner() { return banner; }
        public long getResponseTime() { return responseTime; }

        public void setService(String service) { this.service = service; }
        public void setVersion(String version) { this.version = version; }
        public void setBanner(String banner) { this.banner = banner; }
        public void setResponseTime(long responseTime) { this.responseTime = responseTime; }

        @NonNull
        @Override
        public String toString() {
            return String.format("%d/%s %s %s",
                    port, protocol, open ? "open" : "closed",
                    service != null ? service : "");
        }
    }

    /**
     * Service detection result.
     */
    public static class ServiceResult {
        private final String serviceName;
        private final int port;
        private String version;
        private String product;
        private String extraInfo;
        private float confidence;

        public ServiceResult(@NonNull String serviceName, int port) {
            this.serviceName = serviceName;
            this.port = port;
            this.confidence = 1.0f;
        }

        public String getServiceName() { return serviceName; }
        public int getPort() { return port; }
        public String getVersion() { return version; }
        public String getProduct() { return product; }
        public String getExtraInfo() { return extraInfo; }
        public float getConfidence() { return confidence; }

        public void setVersion(String version) { this.version = version; }
        public void setProduct(String product) { this.product = product; }
        public void setExtraInfo(String extraInfo) { this.extraInfo = extraInfo; }
        public void setConfidence(float confidence) { this.confidence = confidence; }

        @NonNull
        @Override
        public String toString() {
            return String.format("%s on port %d%s",
                    serviceName, port, version != null ? " v" + version : "");
        }
    }

    /**
     * Scan types.
     */
    public enum ScanType {
        PORT_SCAN,
        SERVICE_SCAN,
        OS_DETECTION,
        VULNERABILITY_SCAN,
        FULL_SCAN
    }

    /**
     * Scan status.
     */
    public enum ScanStatus {
        PENDING,
        IN_PROGRESS,
        COMPLETED,
        FAILED,
        CANCELLED
    }

    private ScanResultManager() {
        this.resultsByTarget = new ConcurrentHashMap<>();
        this.resultsById = new ConcurrentHashMap<>();
        this.resultIdCounter = new AtomicLong(0);
    }

    /**
     * Get singleton instance.
     */
    @NonNull
    public static ScanResultManager getInstance() {
        if (instance == null) {
            synchronized (ScanResultManager.class) {
                if (instance == null) {
                    instance = new ScanResultManager();
                }
            }
        }
        return instance;
    }

    /**
     * Set storage path for exports.
     */
    public void setStoragePath(@NonNull String path) {
        this.storagePath = path;
    }

    /**
     * Store a scan result.
     */
    public void storeScanResult(@NonNull ScanResult result) {
        resultsById.put(result.getId(), result);

        resultsByTarget.computeIfAbsent(result.getTargetId(), k -> new ArrayList<>())
                .add(result);
    }

    /**
     * Get result by ID.
     */
    @Nullable
    public ScanResult getResultById(@NonNull String id) {
        return resultsById.get(id);
    }

    /**
     * Get all results for a target.
     */
    @NonNull
    public List<ScanResult> getResultsForTarget(@NonNull String targetId) {
        List<ScanResult> results = resultsByTarget.get(targetId);
        return results != null ? new ArrayList<>(results) : new ArrayList<>();
    }

    /**
     * Get most recent result for a target.
     */
    @Nullable
    public ScanResult getMostRecentResult(@NonNull String targetId) {
        List<ScanResult> results = resultsByTarget.get(targetId);
        if (results == null || results.isEmpty()) return null;

        return results.stream()
                .max(Comparator.comparingLong(ScanResult::getStartTime))
                .orElse(null);
    }

    /**
     * Get all stored results.
     */
    @NonNull
    public List<ScanResult> getAllResults() {
        return new ArrayList<>(resultsById.values());
    }

    /**
     * Filter results by scan type.
     */
    @NonNull
    public List<ScanResult> filterByType(@NonNull ScanType type) {
        List<ScanResult> filtered = new ArrayList<>();
        for (ScanResult result : resultsById.values()) {
            if (result.getScanType() == type) {
                filtered.add(result);
            }
        }
        return filtered;
    }

    /**
     * Filter results by status.
     */
    @NonNull
    public List<ScanResult> filterByStatus(@NonNull ScanStatus status) {
        List<ScanResult> filtered = new ArrayList<>();
        for (ScanResult result : resultsById.values()) {
            if (result.getStatus() == status) {
                filtered.add(result);
            }
        }
        return filtered;
    }

    /**
     * Filter results by time range.
     */
    @NonNull
    public List<ScanResult> filterByTimeRange(long startTime, long endTime) {
        List<ScanResult> filtered = new ArrayList<>();
        for (ScanResult result : resultsById.values()) {
            if (result.getStartTime() >= startTime && result.getStartTime() <= endTime) {
                filtered.add(result);
            }
        }
        return filtered;
    }

    /**
     * Compare two scan results.
     */
    @NonNull
    public ScanDiff compareResults(@NonNull ScanResult older, @NonNull ScanResult newer) {
        ScanDiff diff = new ScanDiff(older, newer);

        // Compare ports
        Map<Integer, PortResult> olderPorts = new HashMap<>();
        for (PortResult pr : older.getPortResults()) {
            olderPorts.put(pr.getPort(), pr);
        }

        for (PortResult newPort : newer.getPortResults()) {
            PortResult oldPort = olderPorts.remove(newPort.getPort());
            if (oldPort == null) {
                if (newPort.isOpen()) {
                    diff.addNewOpenPort(newPort);
                }
            } else if (oldPort.isOpen() != newPort.isOpen()) {
                if (newPort.isOpen()) {
                    diff.addNewOpenPort(newPort);
                } else {
                    diff.addClosedPort(oldPort);
                }
            }
        }

        // Any remaining old ports that were open are now closed
        for (PortResult oldPort : olderPorts.values()) {
            if (oldPort.isOpen()) {
                diff.addClosedPort(oldPort);
            }
        }

        return diff;
    }

    /**
     * Scan diff result.
     */
    public static class ScanDiff {
        private final ScanResult olderResult;
        private final ScanResult newerResult;
        private final List<PortResult> newOpenPorts;
        private final List<PortResult> closedPorts;
        private final List<ServiceResult> newServices;
        private final List<ServiceResult> changedServices;

        public ScanDiff(@NonNull ScanResult older, @NonNull ScanResult newer) {
            this.olderResult = older;
            this.newerResult = newer;
            this.newOpenPorts = new ArrayList<>();
            this.closedPorts = new ArrayList<>();
            this.newServices = new ArrayList<>();
            this.changedServices = new ArrayList<>();
        }

        public void addNewOpenPort(PortResult port) { newOpenPorts.add(port); }
        public void addClosedPort(PortResult port) { closedPorts.add(port); }
        public void addNewService(ServiceResult service) { newServices.add(service); }
        public void addChangedService(ServiceResult service) { changedServices.add(service); }

        public List<PortResult> getNewOpenPorts() { return newOpenPorts; }
        public List<PortResult> getClosedPorts() { return closedPorts; }
        public List<ServiceResult> getNewServices() { return newServices; }
        public List<ServiceResult> getChangedServices() { return changedServices; }

        public boolean hasChanges() {
            return !newOpenPorts.isEmpty() || !closedPorts.isEmpty() ||
                   !newServices.isEmpty() || !changedServices.isEmpty();
        }

        @NonNull
        @Override
        public String toString() {
            return String.format("ScanDiff{newOpen=%d, closed=%d, newServices=%d, changed=%d}",
                    newOpenPorts.size(), closedPorts.size(), newServices.size(), changedServices.size());
        }
    }

    /**
     * Export results to CSV.
     */
    public boolean exportToCSV(@NonNull List<ScanResult> results, @NonNull String filePath) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
            // Write header
            writer.write("Target,Address,Scan Type,Start Time,End Time,Status,Open Ports,Services\n");

            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US);

            for (ScanResult result : results) {
                StringBuilder services = new StringBuilder();
                for (ServiceResult sr : result.getServiceResults()) {
                    if (services.length() > 0) services.append("; ");
                    services.append(sr.getServiceName()).append(":").append(sr.getPort());
                }

                writer.write(String.format("%s,%s,%s,%s,%s,%s,%d,\"%s\"\n",
                        escapeCSV(result.getTargetId()),
                        escapeCSV(result.getTargetAddress()),
                        result.getScanType(),
                        sdf.format(new Date(result.getStartTime())),
                        result.getEndTime() > 0 ? sdf.format(new Date(result.getEndTime())) : "",
                        result.getStatus(),
                        result.getOpenPortCount(),
                        services.toString()
                ));
            }

            return true;
        } catch (IOException e) {
            Log.e(TAG, "Failed to export to CSV", e);
            return false;
        }
    }

    /**
     * Export results to JSON.
     */
    @NonNull
    public String exportToJSON(@NonNull List<ScanResult> results) {
        StringBuilder json = new StringBuilder();
        json.append("{\n  \"scanResults\": [\n");

        for (int i = 0; i < results.size(); i++) {
            ScanResult result = results.get(i);
            json.append("    {\n");
            json.append("      \"id\": \"").append(result.getId()).append("\",\n");
            json.append("      \"targetId\": \"").append(result.getTargetId()).append("\",\n");
            json.append("      \"targetAddress\": \"").append(result.getTargetAddress()).append("\",\n");
            json.append("      \"scanType\": \"").append(result.getScanType()).append("\",\n");
            json.append("      \"startTime\": ").append(result.getStartTime()).append(",\n");
            json.append("      \"endTime\": ").append(result.getEndTime()).append(",\n");
            json.append("      \"status\": \"").append(result.getStatus()).append("\",\n");
            json.append("      \"openPortCount\": ").append(result.getOpenPortCount()).append(",\n");

            // Port results
            json.append("      \"ports\": [\n");
            List<PortResult> ports = result.getPortResults();
            for (int j = 0; j < ports.size(); j++) {
                PortResult port = ports.get(j);
                json.append("        {");
                json.append("\"port\": ").append(port.getPort()).append(", ");
                json.append("\"protocol\": \"").append(port.getProtocol()).append("\", ");
                json.append("\"open\": ").append(port.isOpen());
                if (port.getService() != null) {
                    json.append(", \"service\": \"").append(port.getService()).append("\"");
                }
                json.append("}");
                if (j < ports.size() - 1) json.append(",");
                json.append("\n");
            }
            json.append("      ]\n");

            json.append("    }");
            if (i < results.size() - 1) json.append(",");
            json.append("\n");
        }

        json.append("  ]\n}");
        return json.toString();
    }

    /**
     * Generate summary report.
     */
    @NonNull
    public String generateSummary(@NonNull List<ScanResult> results) {
        StringBuilder sb = new StringBuilder();
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US);

        sb.append("=== Scan Results Summary ===\n\n");
        sb.append("Total Scans: ").append(results.size()).append("\n");

        int completed = 0, failed = 0, totalPorts = 0;
        for (ScanResult result : results) {
            if (result.getStatus() == ScanStatus.COMPLETED) completed++;
            if (result.getStatus() == ScanStatus.FAILED) failed++;
            totalPorts += result.getOpenPortCount();
        }

        sb.append("Completed: ").append(completed).append("\n");
        sb.append("Failed: ").append(failed).append("\n");
        sb.append("Total Open Ports Found: ").append(totalPorts).append("\n\n");

        sb.append("--- Individual Results ---\n");
        for (ScanResult result : results) {
            sb.append("\nTarget: ").append(result.getTargetAddress()).append("\n");
            sb.append("  Type: ").append(result.getScanType()).append("\n");
            sb.append("  Status: ").append(result.getStatus()).append("\n");
            sb.append("  Time: ").append(sdf.format(new Date(result.getStartTime()))).append("\n");
            sb.append("  Duration: ").append(result.getDuration()).append("ms\n");
            sb.append("  Open Ports: ").append(result.getOpenPortCount()).append("\n");

            if (!result.getPortResults().isEmpty()) {
                sb.append("  Ports: ");
                for (PortResult pr : result.getPortResults()) {
                    if (pr.isOpen()) {
                        sb.append(pr.getPort()).append("/").append(pr.getProtocol()).append(" ");
                    }
                }
                sb.append("\n");
            }
        }

        return sb.toString();
    }

    /**
     * Clear all stored results.
     */
    public void clearAll() {
        resultsById.clear();
        resultsByTarget.clear();
    }

    /**
     * Clear results for a specific target.
     */
    public void clearResultsForTarget(@NonNull String targetId) {
        List<ScanResult> results = resultsByTarget.remove(targetId);
        if (results != null) {
            for (ScanResult result : results) {
                resultsById.remove(result.getId());
            }
        }
    }

    /**
     * Get statistics.
     */
    @NonNull
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalResults", resultsById.size());
        stats.put("uniqueTargets", resultsByTarget.size());

        int completed = 0, failed = 0, totalPorts = 0;
        for (ScanResult result : resultsById.values()) {
            if (result.getStatus() == ScanStatus.COMPLETED) completed++;
            if (result.getStatus() == ScanStatus.FAILED) failed++;
            totalPorts += result.getOpenPortCount();
        }

        stats.put("completedScans", completed);
        stats.put("failedScans", failed);
        stats.put("totalOpenPorts", totalPorts);

        return stats;
    }

    /**
     * Escape CSV special characters.
     */
    @NonNull
    private String escapeCSV(@Nullable String value) {
        if (value == null) return "";
        if (value.contains(",") || value.contains("\"") || value.contains("\n")) {
            return "\"" + value.replace("\"", "\"\"") + "\"";
        }
        return value;
    }
}
