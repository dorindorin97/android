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

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Environment;

import androidx.core.content.FileProvider;

import org.csploit.android.net.Target;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Scan result exporter for cSploit.
 *
 * Provides:
 * - Export to JSON format
 * - Export to CSV format
 * - Export to HTML report
 * - Export to plain text
 * - Share functionality
 */
public final class ScanExporter {

    private static final String TAG = "ScanExporter";
    // Thread-safe DateTimeFormatter (immutable and thread-safe unlike SimpleDateFormat)
    private static final DateTimeFormatter DATE_FORMAT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss", Locale.US);
    private static final DateTimeFormatter READABLE_DATE =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss", Locale.US);

    public enum ExportFormat {
        JSON(".json", "application/json"),
        CSV(".csv", "text/csv"),
        HTML(".html", "text/html"),
        TEXT(".txt", "text/plain"),
        XML(".xml", "application/xml");

        public final String extension;
        public final String mimeType;

        ExportFormat(String extension, String mimeType) {
            this.extension = extension;
            this.mimeType = mimeType;
        }
    }

    public static class ExportResult {
        public final boolean success;
        public final File file;
        public final String error;

        private ExportResult(boolean success, File file, String error) {
            this.success = success;
            this.file = file;
            this.error = error;
        }

        public static ExportResult success(File file) {
            return new ExportResult(true, file, null);
        }

        public static ExportResult failure(String error) {
            return new ExportResult(false, null, error);
        }
    }

    private ScanExporter() {}

    // ==================== Main Export Methods ====================

    /**
     * Export targets to specified format
     *
     * @param targets list of targets to export
     * @param format export format
     * @param outputDir output directory
     * @return ExportResult with file path or error
     */
    public static ExportResult export(List<Target> targets, ExportFormat format, File outputDir) {
        String filename = "csploit_scan_" + LocalDateTime.now().format(DATE_FORMAT) + format.extension;
        File outputFile = new File(outputDir, filename);

        try {
            String content;
            switch (format) {
                case JSON:
                    content = exportToJson(targets);
                    break;
                case CSV:
                    content = exportToCsv(targets);
                    break;
                case HTML:
                    content = exportToHtml(targets);
                    break;
                case XML:
                    content = exportToXml(targets);
                    break;
                case TEXT:
                default:
                    content = exportToText(targets);
                    break;
            }

            writeToFile(outputFile, content);
            return ExportResult.success(outputFile);
        } catch (IOException e) {
            LoggingHelper.e(TAG, "Export failed", e);
            return ExportResult.failure(e.getMessage());
        }
    }

    /**
     * Export to default location
     */
    public static ExportResult export(List<Target> targets, ExportFormat format) {
        File outputDir = new File(Environment.getExternalStorageDirectory(), "cSploit/exports");
        if (!outputDir.exists()) {
            outputDir.mkdirs();
        }
        return export(targets, format, outputDir);
    }

    // ==================== Format-Specific Exports ====================

    /**
     * Export to JSON format
     */
    public static String exportToJson(List<Target> targets) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"scan_info\": {\n");
        sb.append("    \"timestamp\": \"").append(LocalDateTime.now().format(READABLE_DATE)).append("\",\n");
        sb.append("    \"total_targets\": ").append(targets.size()).append(",\n");
        sb.append("    \"app_version\": \"").append(AppHelper.getVersionName(null)).append("\"\n");
        sb.append("  },\n");
        sb.append("  \"targets\": [\n");

        for (int i = 0; i < targets.size(); i++) {
            Target t = targets.get(i);
            sb.append("    {\n");
            sb.append("      \"type\": \"").append(escapeJson(t.getType().toString())).append("\",\n");
            sb.append("      \"address\": \"").append(escapeJson(getTargetAddress(t))).append("\",\n");
            sb.append("      \"alias\": \"").append(escapeJson(t.getAlias() != null ? t.getAlias() : "")).append("\",\n");
            sb.append("      \"hostname\": \"").append(escapeJson(t.getHostname() != null ? t.getHostname() : "")).append("\",\n");
            sb.append("      \"mac\": \"").append(escapeJson(getMacString(t))).append("\",\n");
            sb.append("      \"connected\": ").append(t.isConnected()).append(",\n");

            // Ports
            sb.append("      \"ports\": [");
            List<Target.Port> ports = t.getOpenPorts();
            if (ports != null && !ports.isEmpty()) {
                for (int j = 0; j < ports.size(); j++) {
                    if (j > 0) sb.append(", ");
                    Target.Port port = ports.get(j);
                    sb.append("{\"number\": ").append(port.number);
                    if (port.service != null) {
                        sb.append(", \"service\": \"").append(escapeJson(port.service)).append("\"");
                    }
                    sb.append("}");
                }
            }
            sb.append("],\n");

            // Vulnerabilities count
            Collection<?> exploits = t.getExploits();
            sb.append("      \"vulnerabilities\": ").append(exploits != null ? exploits.size() : 0).append("\n");

            sb.append("    }");
            if (i < targets.size() - 1) {
                sb.append(",");
            }
            sb.append("\n");
        }

        sb.append("  ]\n");
        sb.append("}\n");
        return sb.toString();
    }

    /**
     * Export to CSV format
     */
    public static String exportToCsv(List<Target> targets) {
        StringBuilder sb = new StringBuilder();

        // Header
        sb.append("Type,Address,Alias,Hostname,MAC,Connected,Open Ports,Vulnerabilities\n");

        for (Target t : targets) {
            sb.append(escapeCsv(t.getType().toString())).append(",");
            sb.append(escapeCsv(getTargetAddress(t))).append(",");
            sb.append(escapeCsv(t.getAlias() != null ? t.getAlias() : "")).append(",");
            sb.append(escapeCsv(t.getHostname() != null ? t.getHostname() : "")).append(",");
            sb.append(escapeCsv(getMacString(t))).append(",");
            sb.append(t.isConnected()).append(",");

            // Ports as semicolon-separated list
            List<Target.Port> ports = t.getOpenPorts();
            if (ports != null && !ports.isEmpty()) {
                StringBuilder portSb = new StringBuilder();
                for (int i = 0; i < ports.size(); i++) {
                    if (i > 0) portSb.append(";");
                    Target.Port port = ports.get(i);
                    portSb.append(port.number);
                    if (port.service != null) {
                        portSb.append("/").append(port.service);
                    }
                }
                sb.append(escapeCsv(portSb.toString()));
            }
            sb.append(",");

            Collection<?> exploits = t.getExploits();
            sb.append(exploits != null ? exploits.size() : 0);
            sb.append("\n");
        }

        return sb.toString();
    }

    /**
     * Export to HTML report format
     */
    public static String exportToHtml(List<Target> targets) {
        StringBuilder sb = new StringBuilder();
        String timestamp = LocalDateTime.now().format(READABLE_DATE);

        sb.append("<!DOCTYPE html>\n");
        sb.append("<html lang=\"en\">\n");
        sb.append("<head>\n");
        sb.append("  <meta charset=\"UTF-8\">\n");
        sb.append("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        sb.append("  <title>cSploit Scan Report - ").append(timestamp).append("</title>\n");
        sb.append("  <style>\n");
        sb.append("    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; ");
        sb.append("margin: 20px; background: #f5f5f5; }\n");
        sb.append("    .container { max-width: 1200px; margin: 0 auto; }\n");
        sb.append("    h1 { color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }\n");
        sb.append("    .summary { background: #fff; padding: 20px; border-radius: 8px; ");
        sb.append("margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }\n");
        sb.append("    .target { background: #fff; padding: 15px; margin-bottom: 15px; ");
        sb.append("border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }\n");
        sb.append("    .target-header { font-size: 18px; font-weight: bold; color: #333; }\n");
        sb.append("    .target-type { display: inline-block; padding: 2px 8px; border-radius: 4px; ");
        sb.append("font-size: 12px; background: #e0e0e0; margin-left: 10px; }\n");
        sb.append("    .target-details { margin-top: 10px; color: #666; }\n");
        sb.append("    .ports { margin-top: 10px; }\n");
        sb.append("    .port { display: inline-block; padding: 3px 8px; margin: 2px; ");
        sb.append("background: #4CAF50; color: white; border-radius: 4px; font-size: 12px; }\n");
        sb.append("    .vuln-count { color: #f44336; font-weight: bold; }\n");
        sb.append("    .connected { color: #4CAF50; }\n");
        sb.append("    .disconnected { color: #9e9e9e; }\n");
        sb.append("    table { width: 100%; border-collapse: collapse; margin-top: 10px; }\n");
        sb.append("    th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }\n");
        sb.append("    th { background: #f5f5f5; }\n");
        sb.append("  </style>\n");
        sb.append("</head>\n");
        sb.append("<body>\n");
        sb.append("  <div class=\"container\">\n");
        sb.append("    <h1>cSploit Network Scan Report</h1>\n");

        // Summary
        sb.append("    <div class=\"summary\">\n");
        sb.append("      <h2>Scan Summary</h2>\n");
        sb.append("      <p><strong>Timestamp:</strong> ").append(timestamp).append("</p>\n");
        sb.append("      <p><strong>Total Targets:</strong> ").append(targets.size()).append("</p>\n");

        int connected = 0, withPorts = 0, withVulns = 0;
        for (Target t : targets) {
            if (t.isConnected()) connected++;
            List<Target.Port> ports = t.getOpenPorts();
            if (ports != null && !ports.isEmpty()) withPorts++;
            Collection<?> exploits = t.getExploits();
            if (exploits != null && !exploits.isEmpty()) withVulns++;
        }
        sb.append("      <p><strong>Connected:</strong> ").append(connected).append("</p>\n");
        sb.append("      <p><strong>With Open Ports:</strong> ").append(withPorts).append("</p>\n");
        sb.append("      <p><strong>With Vulnerabilities:</strong> ").append(withVulns).append("</p>\n");
        sb.append("    </div>\n");

        // Target list
        sb.append("    <h2>Discovered Targets</h2>\n");
        for (Target t : targets) {
            sb.append("    <div class=\"target\">\n");
            sb.append("      <div class=\"target-header\">\n");
            sb.append("        ").append(escapeHtml(getTargetAddress(t)));
            if (t.getAlias() != null && !t.getAlias().isEmpty()) {
                sb.append(" (").append(escapeHtml(t.getAlias())).append(")");
            }
            sb.append("        <span class=\"target-type\">").append(t.getType()).append("</span>\n");
            sb.append("        <span class=\"").append(t.isConnected() ? "connected" : "disconnected").append("\">");
            sb.append(t.isConnected() ? " [Connected]" : " [Offline]").append("</span>\n");
            sb.append("      </div>\n");

            sb.append("      <div class=\"target-details\">\n");
            if (t.getHostname() != null) {
                sb.append("        <p><strong>Hostname:</strong> ").append(escapeHtml(t.getHostname())).append("</p>\n");
            }
            String mac = getMacString(t);
            if (!mac.isEmpty()) {
                sb.append("        <p><strong>MAC:</strong> ").append(escapeHtml(mac)).append("</p>\n");
            }
            sb.append("      </div>\n");

            // Ports
            List<Target.Port> ports = t.getOpenPorts();
            if (ports != null && !ports.isEmpty()) {
                sb.append("      <div class=\"ports\">\n");
                sb.append("        <strong>Open Ports:</strong><br>\n");
                for (Target.Port port : ports) {
                    sb.append("        <span class=\"port\">").append(port.number);
                    if (port.service != null) {
                        sb.append(" (").append(escapeHtml(port.service)).append(")");
                    }
                    sb.append("</span>\n");
                }
                sb.append("      </div>\n");
            }

            // Vulnerabilities
            Collection<?> exploits = t.getExploits();
            if (exploits != null && !exploits.isEmpty()) {
                sb.append("      <p class=\"vuln-count\">Vulnerabilities: ").append(exploits.size()).append("</p>\n");
            }

            sb.append("    </div>\n");
        }

        sb.append("  </div>\n");
        sb.append("</body>\n");
        sb.append("</html>\n");

        return sb.toString();
    }

    /**
     * Export to plain text format
     */
    public static String exportToText(List<Target> targets) {
        StringBuilder sb = new StringBuilder();
        String timestamp = LocalDateTime.now().format(READABLE_DATE);

        sb.append("cSploit Network Scan Report\n");
        sb.append("===========================\n");
        sb.append("Timestamp: ").append(timestamp).append("\n");
        sb.append("Total Targets: ").append(targets.size()).append("\n");
        sb.append("\n");

        for (Target t : targets) {
            sb.append("----------------------------------------\n");
            sb.append("Address: ").append(getTargetAddress(t)).append("\n");
            sb.append("Type: ").append(t.getType()).append("\n");
            sb.append("Status: ").append(t.isConnected() ? "Connected" : "Offline").append("\n");

            if (t.getAlias() != null && !t.getAlias().isEmpty()) {
                sb.append("Alias: ").append(t.getAlias()).append("\n");
            }
            if (t.getHostname() != null) {
                sb.append("Hostname: ").append(t.getHostname()).append("\n");
            }
            String mac = getMacString(t);
            if (!mac.isEmpty()) {
                sb.append("MAC: ").append(mac).append("\n");
            }

            List<Target.Port> ports = t.getOpenPorts();
            if (ports != null && !ports.isEmpty()) {
                sb.append("Open Ports: ");
                for (int i = 0; i < ports.size(); i++) {
                    if (i > 0) sb.append(", ");
                    Target.Port port = ports.get(i);
                    sb.append(port.number);
                    if (port.service != null) {
                        sb.append("/").append(port.service);
                    }
                }
                sb.append("\n");
            }

            Collection<?> exploits = t.getExploits();
            if (exploits != null && !exploits.isEmpty()) {
                sb.append("Vulnerabilities: ").append(exploits.size()).append("\n");
            }
            sb.append("\n");
        }

        return sb.toString();
    }

    /**
     * Export to XML format
     */
    public static String exportToXml(List<Target> targets) {
        StringBuilder sb = new StringBuilder();
        String timestamp = LocalDateTime.now().format(READABLE_DATE);

        sb.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        sb.append("<csploit_scan>\n");
        sb.append("  <scan_info>\n");
        sb.append("    <timestamp>").append(timestamp).append("</timestamp>\n");
        sb.append("    <total_targets>").append(targets.size()).append("</total_targets>\n");
        sb.append("  </scan_info>\n");
        sb.append("  <targets>\n");

        for (Target t : targets) {
            sb.append("    <target>\n");
            sb.append("      <type>").append(escapeXml(t.getType().toString())).append("</type>\n");
            sb.append("      <address>").append(escapeXml(getTargetAddress(t))).append("</address>\n");
            if (t.getAlias() != null) {
                sb.append("      <alias>").append(escapeXml(t.getAlias())).append("</alias>\n");
            }
            if (t.getHostname() != null) {
                sb.append("      <hostname>").append(escapeXml(t.getHostname())).append("</hostname>\n");
            }
            String mac = getMacString(t);
            if (!mac.isEmpty()) {
                sb.append("      <mac>").append(escapeXml(mac)).append("</mac>\n");
            }
            sb.append("      <connected>").append(t.isConnected()).append("</connected>\n");

            List<Target.Port> ports = t.getOpenPorts();
            if (ports != null && !ports.isEmpty()) {
                sb.append("      <ports>\n");
                for (Target.Port port : ports) {
                    sb.append("        <port number=\"").append(port.number).append("\"");
                    if (port.service != null) {
                        sb.append(" service=\"").append(escapeXml(port.service)).append("\"");
                    }
                    sb.append("/>\n");
                }
                sb.append("      </ports>\n");
            }

            Collection<?> exploits = t.getExploits();
            sb.append("      <vulnerabilities>").append(exploits != null ? exploits.size() : 0).append("</vulnerabilities>\n");
            sb.append("    </target>\n");
        }

        sb.append("  </targets>\n");
        sb.append("</csploit_scan>\n");

        return sb.toString();
    }

    // ==================== Share Functionality ====================

    /**
     * Share exported file via Android share intent
     *
     * @param context Android context
     * @param file file to share
     * @param format export format (for MIME type)
     * @return share Intent
     */
    public static Intent createShareIntent(Context context, File file, ExportFormat format) {
        Uri fileUri = FileProvider.getUriForFile(context,
            context.getPackageName() + ".fileprovider", file);

        Intent shareIntent = new Intent(Intent.ACTION_SEND);
        shareIntent.setType(format.mimeType);
        shareIntent.putExtra(Intent.EXTRA_STREAM, fileUri);
        shareIntent.putExtra(Intent.EXTRA_SUBJECT, "cSploit Scan Report");
        shareIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);

        return Intent.createChooser(shareIntent, "Share Scan Report");
    }

    /**
     * Export and share in one step
     *
     * @param context Android context
     * @param targets targets to export
     * @param format export format
     * @return share Intent or null if export failed
     */
    public static Intent exportAndShare(Context context, List<Target> targets, ExportFormat format) {
        ExportResult result = export(targets, format);
        if (result.success) {
            return createShareIntent(context, result.file, format);
        }
        return null;
    }

    // ==================== Helper Methods ====================

    private static void writeToFile(File file, String content) throws IOException {
        // Ensure parent directory exists
        File parent = file.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
            writer.write(content);
        }
    }

    private static String getTargetAddress(Target t) {
        if (t.getAddress() != null) {
            return t.getAddress().getHostAddress();
        }
        if (t.getNetwork() != null) {
            return t.getNetwork().toString();
        }
        return "Unknown";
    }

    private static String getMacString(Target t) {
        byte[] mac = t.getHardwareAddress();
        if (mac != null) {
            return NetworkHelper.bytesToMac(mac);
        }
        return "";
    }

    // Escape functions for different formats
    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private static String escapeCsv(String s) {
        if (s == null) return "";
        if (s.contains(",") || s.contains("\"") || s.contains("\n")) {
            return "\"" + s.replace("\"", "\"\"") + "\"";
        }
        return s;
    }

    private static String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    private static String escapeXml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&apos;");
    }
}
