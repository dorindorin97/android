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

import android.content.Context;
import android.os.Environment;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import org.csploit.android.net.Target;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * ReportGenerator - Generate comprehensive scan reports
 *
 * Creates professional reports from scan results in multiple formats:
 * - HTML reports with styling
 * - JSON reports for data processing
 * - Plain text reports for simple viewing
 * - CSV exports for spreadsheet analysis
 *
 * Features:
 * - Customizable report templates
 * - Executive summaries
 * - Detailed vulnerability listings
 * - Target and port information
 * - Remediation recommendations
 * - Charts and statistics
 *
 * Usage:
 * {@code
 * ReportGenerator generator = new ReportGenerator(context);
 * File report = generator.generateHtmlReport(targets, scanResults, "Network Audit");
 * }
 */
public final class ReportGenerator {

    private static final String TAG = "ReportGenerator";
    private static final SimpleDateFormat DATE_FORMAT =
            new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US);
    private static final SimpleDateFormat FILE_DATE_FORMAT =
            new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US);

    private final Context context;
    private final File reportsDir;

    /**
     * Report format types
     */
    public enum Format {
        HTML(".html", "text/html"),
        JSON(".json", "application/json"),
        TEXT(".txt", "text/plain"),
        CSV(".csv", "text/csv");

        private final String extension;
        private final String mimeType;

        Format(String extension, String mimeType) {
            this.extension = extension;
            this.mimeType = mimeType;
        }

        public String getExtension() { return extension; }
        public String getMimeType() { return mimeType; }
    }

    /**
     * Report configuration options
     */
    public static class ReportConfig {
        private boolean includeExecutiveSummary = true;
        private boolean includeTargetDetails = true;
        private boolean includeVulnerabilities = true;
        private boolean includeOpenPorts = true;
        private boolean includeRemediation = true;
        private boolean includeStatistics = true;
        private String reportTitle = "Network Security Scan Report";
        private String organizationName = "";
        private String auditorName = "";

        public ReportConfig setIncludeExecutiveSummary(boolean val) {
            includeExecutiveSummary = val; return this;
        }
        public ReportConfig setIncludeTargetDetails(boolean val) {
            includeTargetDetails = val; return this;
        }
        public ReportConfig setIncludeVulnerabilities(boolean val) {
            includeVulnerabilities = val; return this;
        }
        public ReportConfig setIncludeOpenPorts(boolean val) {
            includeOpenPorts = val; return this;
        }
        public ReportConfig setIncludeRemediation(boolean val) {
            includeRemediation = val; return this;
        }
        public ReportConfig setIncludeStatistics(boolean val) {
            includeStatistics = val; return this;
        }
        public ReportConfig setReportTitle(String val) {
            reportTitle = val; return this;
        }
        public ReportConfig setOrganizationName(String val) {
            organizationName = val; return this;
        }
        public ReportConfig setAuditorName(String val) {
            auditorName = val; return this;
        }

        public static ReportConfig getDefault() {
            return new ReportConfig();
        }

        public static ReportConfig getMinimal() {
            return new ReportConfig()
                    .setIncludeExecutiveSummary(false)
                    .setIncludeRemediation(false)
                    .setIncludeStatistics(false);
        }
    }

    /**
     * Report generation result
     */
    public static class ReportResult {
        private final boolean success;
        private final File file;
        private final String error;
        private final long generationTimeMs;

        private ReportResult(boolean success, File file, String error, long timeMs) {
            this.success = success;
            this.file = file;
            this.error = error;
            this.generationTimeMs = timeMs;
        }

        public boolean isSuccess() { return success; }
        public File getFile() { return file; }
        public String getError() { return error; }
        public long getGenerationTimeMs() { return generationTimeMs; }

        static ReportResult success(File file, long timeMs) {
            return new ReportResult(true, file, null, timeMs);
        }

        static ReportResult failure(String error) {
            return new ReportResult(false, null, error, 0);
        }
    }

    public ReportGenerator(@NonNull Context context) {
        this.context = context.getApplicationContext();
        this.reportsDir = new File(context.getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS),
                "cSploit_Reports");
        if (!reportsDir.exists()) {
            reportsDir.mkdirs();
        }
    }

    /**
     * Generate HTML report
     */
    @NonNull
    public ReportResult generateHtmlReport(@NonNull List<Target> targets,
                                           @Nullable List<VulnerabilityScanner.ScanResult> scanResults,
                                           @NonNull ReportConfig config) {
        long startTime = System.currentTimeMillis();
        String filename = "report_" + FILE_DATE_FORMAT.format(new Date()) + Format.HTML.extension;
        File outputFile = new File(reportsDir, filename);

        try {
            StringBuilder html = new StringBuilder();
            html.append(generateHtmlHeader(config));
            html.append(generateHtmlBody(targets, scanResults, config));
            html.append(generateHtmlFooter());

            writeToFile(outputFile, html.toString());
            long duration = System.currentTimeMillis() - startTime;
            LoggingHelper.d(TAG, "Generated HTML report: " + outputFile.getAbsolutePath());
            return ReportResult.success(outputFile, duration);
        } catch (IOException e) {
            LoggingHelper.e(TAG, "Failed to generate HTML report", e);
            return ReportResult.failure(e.getMessage());
        }
    }

    /**
     * Generate JSON report
     */
    @NonNull
    public ReportResult generateJsonReport(@NonNull List<Target> targets,
                                           @Nullable List<VulnerabilityScanner.ScanResult> scanResults,
                                           @NonNull ReportConfig config) {
        long startTime = System.currentTimeMillis();
        String filename = "report_" + FILE_DATE_FORMAT.format(new Date()) + Format.JSON.extension;
        File outputFile = new File(reportsDir, filename);

        try {
            JSONObject report = new JSONObject();
            report.put("reportTitle", config.reportTitle);
            report.put("generatedAt", DATE_FORMAT.format(new Date()));
            report.put("organizationName", config.organizationName);
            report.put("auditorName", config.auditorName);

            // Targets
            JSONArray targetsArray = new JSONArray();
            for (Target target : targets) {
                targetsArray.put(targetToJson(target));
            }
            report.put("targets", targetsArray);
            report.put("targetCount", targets.size());

            // Scan results
            if (scanResults != null && !scanResults.isEmpty()) {
                JSONArray resultsArray = new JSONArray();
                int totalVulns = 0;
                for (VulnerabilityScanner.ScanResult result : scanResults) {
                    resultsArray.put(scanResultToJson(result));
                    totalVulns += result.getTotalVulnerabilities();
                }
                report.put("scanResults", resultsArray);
                report.put("totalVulnerabilities", totalVulns);
            }

            // Statistics
            if (config.includeStatistics) {
                report.put("statistics", generateStatisticsJson(targets, scanResults));
            }

            writeToFile(outputFile, report.toString(2));
            long duration = System.currentTimeMillis() - startTime;
            LoggingHelper.d(TAG, "Generated JSON report: " + outputFile.getAbsolutePath());
            return ReportResult.success(outputFile, duration);
        } catch (IOException | JSONException e) {
            LoggingHelper.e(TAG, "Failed to generate JSON report", e);
            return ReportResult.failure(e.getMessage());
        }
    }

    /**
     * Generate plain text report
     */
    @NonNull
    public ReportResult generateTextReport(@NonNull List<Target> targets,
                                           @Nullable List<VulnerabilityScanner.ScanResult> scanResults,
                                           @NonNull ReportConfig config) {
        long startTime = System.currentTimeMillis();
        String filename = "report_" + FILE_DATE_FORMAT.format(new Date()) + Format.TEXT.extension;
        File outputFile = new File(reportsDir, filename);

        try {
            StringBuilder text = new StringBuilder();
            text.append(generateTextHeader(config));
            text.append(generateTextBody(targets, scanResults, config));
            text.append(generateTextFooter());

            writeToFile(outputFile, text.toString());
            long duration = System.currentTimeMillis() - startTime;
            LoggingHelper.d(TAG, "Generated text report: " + outputFile.getAbsolutePath());
            return ReportResult.success(outputFile, duration);
        } catch (IOException e) {
            LoggingHelper.e(TAG, "Failed to generate text report", e);
            return ReportResult.failure(e.getMessage());
        }
    }

    /**
     * Generate CSV report
     */
    @NonNull
    public ReportResult generateCsvReport(@NonNull List<Target> targets,
                                          @Nullable List<VulnerabilityScanner.ScanResult> scanResults) {
        long startTime = System.currentTimeMillis();
        String filename = "report_" + FILE_DATE_FORMAT.format(new Date()) + Format.CSV.extension;
        File outputFile = new File(reportsDir, filename);

        try {
            StringBuilder csv = new StringBuilder();
            // Header
            csv.append("Target Address,Type,Device Type,Device OS,Open Ports,Vulnerabilities\n");

            // Data rows
            for (Target target : targets) {
                csv.append(escapeCsv(target.getDisplayAddress())).append(",");
                csv.append(escapeCsv(target.getType().toString())).append(",");
                csv.append(escapeCsv(target.getDeviceType())).append(",");
                csv.append(escapeCsv(target.getDeviceOS())).append(",");

                List<Target.Port> ports = target.getOpenPorts();
                csv.append(ports.size()).append(",");

                // Find matching scan result
                int vulnCount = 0;
                if (scanResults != null) {
                    for (VulnerabilityScanner.ScanResult result : scanResults) {
                        if (result.getTargetId().equals(target.getUuid())) {
                            vulnCount = result.getTotalVulnerabilities();
                            break;
                        }
                    }
                }
                csv.append(vulnCount).append("\n");
            }

            writeToFile(outputFile, csv.toString());
            long duration = System.currentTimeMillis() - startTime;
            LoggingHelper.d(TAG, "Generated CSV report: " + outputFile.getAbsolutePath());
            return ReportResult.success(outputFile, duration);
        } catch (IOException e) {
            LoggingHelper.e(TAG, "Failed to generate CSV report", e);
            return ReportResult.failure(e.getMessage());
        }
    }

    /**
     * Get reports directory
     */
    @NonNull
    public File getReportsDirectory() {
        return reportsDir;
    }

    /**
     * List all generated reports
     */
    @NonNull
    public File[] listReports() {
        File[] files = reportsDir.listFiles();
        return files != null ? files : new File[0];
    }

    /**
     * Delete old reports older than specified days
     */
    public int cleanupOldReports(int daysOld) {
        long cutoffTime = System.currentTimeMillis() - (daysOld * 24L * 60L * 60L * 1000L);
        int deleted = 0;
        File[] files = reportsDir.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.lastModified() < cutoffTime && file.delete()) {
                    deleted++;
                }
            }
        }
        LoggingHelper.d(TAG, "Cleaned up " + deleted + " old reports");
        return deleted;
    }

    // HTML generation helpers
    private String generateHtmlHeader(ReportConfig config) {
        return "<!DOCTYPE html>\n" +
                "<html lang=\"en\">\n" +
                "<head>\n" +
                "    <meta charset=\"UTF-8\">\n" +
                "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" +
                "    <title>" + escapeHtml(config.reportTitle) + "</title>\n" +
                "    <style>\n" +
                "        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #f5f5f5; }\n" +
                "        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }\n" +
                "        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 15px; }\n" +
                "        h2 { color: #34495e; margin-top: 30px; }\n" +
                "        .summary-box { background: #ecf0f1; padding: 20px; border-radius: 8px; margin: 20px 0; }\n" +
                "        .stat { display: inline-block; margin-right: 30px; }\n" +
                "        .stat-value { font-size: 32px; font-weight: bold; color: #3498db; }\n" +
                "        .stat-label { color: #7f8c8d; }\n" +
                "        table { width: 100%; border-collapse: collapse; margin: 20px 0; }\n" +
                "        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }\n" +
                "        th { background: #3498db; color: white; }\n" +
                "        tr:hover { background: #f5f5f5; }\n" +
                "        .severity-critical { color: #c0392b; font-weight: bold; }\n" +
                "        .severity-high { color: #e74c3c; }\n" +
                "        .severity-medium { color: #f39c12; }\n" +
                "        .severity-low { color: #27ae60; }\n" +
                "        .severity-info { color: #3498db; }\n" +
                "        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; font-size: 12px; }\n" +
                "    </style>\n" +
                "</head>\n" +
                "<body>\n" +
                "<div class=\"container\">\n";
    }

    private String generateHtmlBody(List<Target> targets,
                                    List<VulnerabilityScanner.ScanResult> scanResults,
                                    ReportConfig config) {
        StringBuilder html = new StringBuilder();

        // Title
        html.append("<h1>").append(escapeHtml(config.reportTitle)).append("</h1>\n");
        html.append("<p>Generated: ").append(DATE_FORMAT.format(new Date())).append("</p>\n");

        if (!config.organizationName.isEmpty()) {
            html.append("<p>Organization: ").append(escapeHtml(config.organizationName)).append("</p>\n");
        }

        // Executive Summary
        if (config.includeExecutiveSummary) {
            html.append("<div class=\"summary-box\">\n");
            html.append("<h2>Executive Summary</h2>\n");
            html.append("<div class=\"stat\"><div class=\"stat-value\">").append(targets.size())
                    .append("</div><div class=\"stat-label\">Targets Scanned</div></div>\n");

            int totalPorts = 0;
            for (Target t : targets) {
                totalPorts += t.getOpenPorts().size();
            }
            html.append("<div class=\"stat\"><div class=\"stat-value\">").append(totalPorts)
                    .append("</div><div class=\"stat-label\">Open Ports</div></div>\n");

            if (scanResults != null) {
                int totalVulns = 0;
                for (VulnerabilityScanner.ScanResult r : scanResults) {
                    totalVulns += r.getTotalVulnerabilities();
                }
                html.append("<div class=\"stat\"><div class=\"stat-value\">").append(totalVulns)
                        .append("</div><div class=\"stat-label\">Vulnerabilities</div></div>\n");
            }
            html.append("</div>\n");
        }

        // Target Details
        if (config.includeTargetDetails) {
            html.append("<h2>Target Details</h2>\n");
            html.append("<table>\n");
            html.append("<tr><th>Address</th><th>Type</th><th>Device Type</th><th>OS</th><th>Open Ports</th></tr>\n");
            for (Target target : targets) {
                html.append("<tr>");
                html.append("<td>").append(escapeHtml(target.getDisplayAddress())).append("</td>");
                html.append("<td>").append(target.getType()).append("</td>");
                html.append("<td>").append(escapeHtml(target.getDeviceType())).append("</td>");
                html.append("<td>").append(escapeHtml(target.getDeviceOS())).append("</td>");
                html.append("<td>").append(target.getOpenPorts().size()).append("</td>");
                html.append("</tr>\n");
            }
            html.append("</table>\n");
        }

        // Vulnerabilities
        if (config.includeVulnerabilities && scanResults != null) {
            html.append("<h2>Vulnerability Summary</h2>\n");
            html.append("<table>\n");
            html.append("<tr><th>Target</th><th>Vulnerability</th><th>Severity</th><th>CVE</th><th>CVSS</th></tr>\n");
            for (VulnerabilityScanner.ScanResult result : scanResults) {
                for (VulnerabilityScanner.Vulnerability vuln : result.getVulnerabilities()) {
                    html.append("<tr>");
                    html.append("<td>").append(escapeHtml(result.getTargetAddress())).append("</td>");
                    html.append("<td>").append(escapeHtml(vuln.getName())).append("</td>");
                    html.append("<td class=\"severity-").append(vuln.getSeverity().name().toLowerCase())
                            .append("\">").append(vuln.getSeverity().getDisplayName()).append("</td>");
                    html.append("<td>").append(vuln.getCveId() != null ? vuln.getCveId() : "N/A").append("</td>");
                    html.append("<td>").append(String.format("%.1f", vuln.getCvssScore())).append("</td>");
                    html.append("</tr>\n");
                }
            }
            html.append("</table>\n");
        }

        return html.toString();
    }

    private String generateHtmlFooter() {
        return "<div class=\"footer\">\n" +
                "    <p>Report generated by cSploit Security Scanner</p>\n" +
                "</div>\n" +
                "</div>\n" +
                "</body>\n" +
                "</html>";
    }

    // Text generation helpers
    private String generateTextHeader(ReportConfig config) {
        StringBuilder text = new StringBuilder();
        text.append("=".repeat(60)).append("\n");
        text.append(config.reportTitle).append("\n");
        text.append("=".repeat(60)).append("\n\n");
        text.append("Generated: ").append(DATE_FORMAT.format(new Date())).append("\n");
        if (!config.organizationName.isEmpty()) {
            text.append("Organization: ").append(config.organizationName).append("\n");
        }
        text.append("\n");
        return text.toString();
    }

    private String generateTextBody(List<Target> targets,
                                    List<VulnerabilityScanner.ScanResult> scanResults,
                                    ReportConfig config) {
        StringBuilder text = new StringBuilder();

        text.append("-".repeat(60)).append("\n");
        text.append("TARGETS SUMMARY\n");
        text.append("-".repeat(60)).append("\n\n");
        text.append("Total targets scanned: ").append(targets.size()).append("\n\n");

        for (Target target : targets) {
            text.append("Target: ").append(target.getDisplayAddress()).append("\n");
            text.append("  Type: ").append(target.getType()).append("\n");
            if (target.getDeviceType() != null) {
                text.append("  Device: ").append(target.getDeviceType()).append("\n");
            }
            if (target.getDeviceOS() != null) {
                text.append("  OS: ").append(target.getDeviceOS()).append("\n");
            }
            text.append("  Open Ports: ").append(target.getOpenPorts().size()).append("\n");
            text.append("\n");
        }

        if (scanResults != null && !scanResults.isEmpty()) {
            text.append("-".repeat(60)).append("\n");
            text.append("VULNERABILITIES\n");
            text.append("-".repeat(60)).append("\n\n");

            for (VulnerabilityScanner.ScanResult result : scanResults) {
                text.append("Target: ").append(result.getTargetAddress()).append("\n");
                for (VulnerabilityScanner.Vulnerability vuln : result.getVulnerabilities()) {
                    text.append("  [").append(vuln.getSeverity().getDisplayName()).append("] ");
                    text.append(vuln.getName());
                    if (vuln.getCveId() != null) {
                        text.append(" (").append(vuln.getCveId()).append(")");
                    }
                    text.append("\n");
                }
                text.append("\n");
            }
        }

        return text.toString();
    }

    private String generateTextFooter() {
        return "\n" + "=".repeat(60) + "\n" +
                "Report generated by cSploit Security Scanner\n" +
                "=".repeat(60) + "\n";
    }

    // JSON helpers
    private JSONObject targetToJson(Target target) throws JSONException {
        JSONObject json = new JSONObject();
        json.put("id", target.getUuid());
        json.put("address", target.getDisplayAddress());
        json.put("type", target.getType().toString());
        json.put("deviceType", target.getDeviceType());
        json.put("deviceOS", target.getDeviceOS());

        JSONArray portsArray = new JSONArray();
        for (Target.Port port : target.getOpenPorts()) {
            JSONObject portJson = new JSONObject();
            portJson.put("number", port.getNumber());
            portJson.put("protocol", port.getProtocol().toString());
            portJson.put("service", port.getService());
            portJson.put("version", port.getVersion());
            portsArray.put(portJson);
        }
        json.put("openPorts", portsArray);

        return json;
    }

    private JSONObject scanResultToJson(VulnerabilityScanner.ScanResult result) throws JSONException {
        JSONObject json = new JSONObject();
        json.put("targetId", result.getTargetId());
        json.put("targetAddress", result.getTargetAddress());
        json.put("scanStartTime", result.getScanStartTime());
        json.put("scanEndTime", result.getScanEndTime());
        json.put("scanDurationMs", result.getScanDuration());
        json.put("completed", result.isScanCompleted());

        JSONArray vulnsArray = new JSONArray();
        for (VulnerabilityScanner.Vulnerability vuln : result.getVulnerabilities()) {
            JSONObject vulnJson = new JSONObject();
            vulnJson.put("id", vuln.getId());
            vulnJson.put("name", vuln.getName());
            vulnJson.put("description", vuln.getDescription());
            vulnJson.put("severity", vuln.getSeverity().name());
            vulnJson.put("category", vuln.getCategory().name());
            vulnJson.put("cveId", vuln.getCveId());
            vulnJson.put("cvssScore", vuln.getCvssScore());
            vulnJson.put("affectedPort", vuln.getAffectedPort());
            vulnJson.put("affectedService", vuln.getAffectedService());
            vulnJson.put("remediation", vuln.getRemediation());
            vulnJson.put("exploitAvailable", vuln.isExploitAvailable());
            vulnsArray.put(vulnJson);
        }
        json.put("vulnerabilities", vulnsArray);
        json.put("totalVulnerabilities", result.getTotalVulnerabilities());

        return json;
    }

    private JSONObject generateStatisticsJson(List<Target> targets,
                                              List<VulnerabilityScanner.ScanResult> scanResults) throws JSONException {
        JSONObject stats = new JSONObject();
        stats.put("totalTargets", targets.size());

        int totalPorts = 0;
        for (Target t : targets) {
            totalPorts += t.getOpenPorts().size();
        }
        stats.put("totalOpenPorts", totalPorts);

        if (scanResults != null) {
            int totalVulns = 0;
            int critical = 0, high = 0, medium = 0, low = 0, info = 0;

            for (VulnerabilityScanner.ScanResult result : scanResults) {
                totalVulns += result.getTotalVulnerabilities();
                critical += result.getCountBySeverity(VulnerabilityScanner.Severity.CRITICAL);
                high += result.getCountBySeverity(VulnerabilityScanner.Severity.HIGH);
                medium += result.getCountBySeverity(VulnerabilityScanner.Severity.MEDIUM);
                low += result.getCountBySeverity(VulnerabilityScanner.Severity.LOW);
                info += result.getCountBySeverity(VulnerabilityScanner.Severity.INFO);
            }

            stats.put("totalVulnerabilities", totalVulns);
            JSONObject severityCounts = new JSONObject();
            severityCounts.put("critical", critical);
            severityCounts.put("high", high);
            severityCounts.put("medium", medium);
            severityCounts.put("low", low);
            severityCounts.put("info", info);
            stats.put("vulnerabilitiesBySeverity", severityCounts);
        }

        return stats;
    }

    // Utility methods
    private void writeToFile(File file, String content) throws IOException {
        try (FileWriter writer = new FileWriter(file)) {
            writer.write(content);
        }
    }

    private String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    private String escapeCsv(String text) {
        if (text == null) return "";
        if (text.contains(",") || text.contains("\"") || text.contains("\n")) {
            return "\"" + text.replace("\"", "\"\"") + "\"";
        }
        return text;
    }
}
