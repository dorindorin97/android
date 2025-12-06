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
import android.content.Intent;
import android.net.Uri;
import android.os.Environment;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.FileProvider;

import org.csploit.android.core.System;
import org.csploit.android.net.Target;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Date;
import java.util.Locale;

/**
 * ScanResultExporter - Export scan results to various formats
 * 
 * Supports:
 * - JSON export
 * - CSV export (for spreadsheet applications)
 * - HTML report generation
 * - Plain text export
 * - Share via Android sharing intent
 * 
 * Usage:
 * {@code
 * ScanResultExporter exporter = new ScanResultExporter(context);
 * File jsonFile = exporter.exportToJson(targets, "scan_results");
 * exporter.shareFile(jsonFile, "application/json");
 * }
 */
public final class ScanResultExporter {
    private static final String TAG = "ScanResultExporter";
    
    public enum ExportFormat {
        JSON,
        CSV,
        HTML,
        TXT
    }
    
    private final Context mContext;
    private final SimpleDateFormat mDateFormat;
    
    public ScanResultExporter(@NonNull Context context) {
        mContext = context.getApplicationContext();
        mDateFormat = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss", Locale.US);
    }
    
    /**
     * Export targets to JSON format
     * @param targets collection of targets to export
     * @param filename base filename (without extension)
     * @return exported file or null on failure
     */
    @Nullable
    public File exportToJson(@NonNull Collection<Target> targets, @NonNull String filename) {
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"exportDate\": \"").append(getCurrentTimestamp()).append("\",\n");
        json.append("  \"appVersion\": \"").append(System.getAppVersionName()).append("\",\n");
        json.append("  \"targetCount\": ").append(targets.size()).append(",\n");
        json.append("  \"targets\": [\n");
        
        boolean first = true;
        for (Target target : targets) {
            if (!first) {
                json.append(",\n");
            }
            first = false;
            json.append(targetToJson(target));
        }
        
        json.append("\n  ]\n");
        json.append("}\n");
        
        return writeToFile(filename + ".json", json.toString());
    }
    
    /**
     * Export targets to CSV format
     * @param targets collection of targets to export
     * @param filename base filename (without extension)
     * @return exported file or null on failure
     */
    @Nullable
    public File exportToCsv(@NonNull Collection<Target> targets, @NonNull String filename) {
        StringBuilder csv = new StringBuilder();
        
        // CSV Header
        csv.append("IP Address,MAC Address,Hostname,Alias,Device Type,OS,Open Ports,Vulnerabilities\n");
        
        for (Target target : targets) {
            csv.append(escapeCsv(target.getCommandLineRepresentation())).append(",");
            csv.append(escapeCsv(target.getHardwareAddress() != null ? 
                    bytesToMac(target.getHardwareAddress()) : "")).append(",");
            csv.append(escapeCsv(target.getHostname() != null ? target.getHostname() : "")).append(",");
            csv.append(escapeCsv(target.getAlias() != null ? target.getAlias() : "")).append(",");
            csv.append(escapeCsv(target.getDeviceType() != null ? target.getDeviceType() : "")).append(",");
            csv.append(escapeCsv(target.getDeviceOS() != null ? target.getDeviceOS() : "")).append(",");
            csv.append(escapeCsv(formatPorts(target))).append(",");
            csv.append(escapeCsv(String.valueOf(target.getExploits().size())));
            csv.append("\n");
        }
        
        return writeToFile(filename + ".csv", csv.toString());
    }
    
    /**
     * Export targets to HTML report
     * @param targets collection of targets to export
     * @param filename base filename (without extension)
     * @return exported file or null on failure
     */
    @Nullable
    public File exportToHtml(@NonNull Collection<Target> targets, @NonNull String filename) {
        StringBuilder html = new StringBuilder();
        
        html.append("<!DOCTYPE html>\n<html>\n<head>\n");
        html.append("<meta charset=\"UTF-8\">\n");
        html.append("<title>cSploit Scan Report - ").append(getCurrentTimestamp()).append("</title>\n");
        html.append("<style>\n");
        html.append("body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }\n");
        html.append("h1 { color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }\n");
        html.append("h2 { color: #4CAF50; }\n");
        html.append(".target { background: white; margin: 10px 0; padding: 15px; ");
        html.append("border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }\n");
        html.append(".target-header { font-weight: bold; font-size: 1.2em; color: #333; }\n");
        html.append(".target-info { margin: 5px 0; color: #666; }\n");
        html.append(".ports { background: #e8f5e9; padding: 10px; border-radius: 3px; margin-top: 10px; }\n");
        html.append(".port-item { display: inline-block; background: #4CAF50; color: white; ");
        html.append("padding: 3px 8px; margin: 2px; border-radius: 3px; font-size: 0.9em; }\n");
        html.append(".vulnerabilities { background: #ffebee; padding: 10px; border-radius: 3px; margin-top: 10px; }\n");
        html.append(".footer { margin-top: 30px; text-align: center; color: #999; font-size: 0.8em; }\n");
        html.append("</style>\n</head>\n<body>\n");
        
        html.append("<h1>🔍 cSploit Network Scan Report</h1>\n");
        html.append("<p><strong>Generated:</strong> ").append(getCurrentTimestamp()).append("</p>\n");
        html.append("<p><strong>App Version:</strong> ").append(System.getAppVersionName()).append("</p>\n");
        html.append("<p><strong>Total Targets:</strong> ").append(targets.size()).append("</p>\n");
        
        html.append("<h2>Discovered Targets</h2>\n");
        
        for (Target target : targets) {
            html.append("<div class=\"target\">\n");
            html.append("<div class=\"target-header\">").append(escapeHtml(target.toString())).append("</div>\n");
            
            if (target.getHostname() != null) {
                html.append("<div class=\"target-info\">Hostname: ").append(escapeHtml(target.getHostname())).append("</div>\n");
            }
            if (target.getHardwareAddress() != null) {
                html.append("<div class=\"target-info\">MAC: ").append(bytesToMac(target.getHardwareAddress())).append("</div>\n");
            }
            if (target.getDeviceType() != null) {
                html.append("<div class=\"target-info\">Type: ").append(escapeHtml(target.getDeviceType())).append("</div>\n");
            }
            if (target.getDeviceOS() != null) {
                html.append("<div class=\"target-info\">OS: ").append(escapeHtml(target.getDeviceOS())).append("</div>\n");
            }
            
            if (target.hasOpenPorts()) {
                html.append("<div class=\"ports\"><strong>Open Ports:</strong><br>\n");
                for (Target.Port port : target.getOpenPorts()) {
                    html.append("<span class=\"port-item\">").append(port.getNumber());
                    if (port.getService() != null) {
                        html.append(" (").append(escapeHtml(port.getService())).append(")");
                    }
                    html.append("</span>\n");
                }
                html.append("</div>\n");
            }
            
            if (!target.getExploits().isEmpty()) {
                html.append("<div class=\"vulnerabilities\"><strong>⚠️ Potential Vulnerabilities:</strong> ");
                html.append(target.getExploits().size()).append(" found</div>\n");
            }
            
            html.append("</div>\n");
        }
        
        html.append("<div class=\"footer\">Generated by cSploit - Network Security Testing Tool</div>\n");
        html.append("</body>\n</html>");
        
        return writeToFile(filename + ".html", html.toString());
    }
    
    /**
     * Export targets to plain text
     * @param targets collection of targets to export
     * @param filename base filename (without extension)
     * @return exported file or null on failure
     */
    @Nullable
    public File exportToTxt(@NonNull Collection<Target> targets, @NonNull String filename) {
        StringBuilder txt = new StringBuilder();
        
        txt.append("cSploit Scan Report\n");
        txt.append("===================\n");
        txt.append("Generated: ").append(getCurrentTimestamp()).append("\n");
        txt.append("Version: ").append(System.getAppVersionName()).append("\n");
        txt.append("Total Targets: ").append(targets.size()).append("\n");
        txt.append("\n");
        
        for (Target target : targets) {
            txt.append("-----------------------------------\n");
            txt.append("Target: ").append(target.toString()).append("\n");
            if (target.getHostname() != null) {
                txt.append("Hostname: ").append(target.getHostname()).append("\n");
            }
            if (target.getHardwareAddress() != null) {
                txt.append("MAC: ").append(bytesToMac(target.getHardwareAddress())).append("\n");
            }
            if (target.getDeviceType() != null) {
                txt.append("Type: ").append(target.getDeviceType()).append("\n");
            }
            if (target.getDeviceOS() != null) {
                txt.append("OS: ").append(target.getDeviceOS()).append("\n");
            }
            if (target.hasOpenPorts()) {
                txt.append("Open Ports: ").append(formatPorts(target)).append("\n");
            }
            if (!target.getExploits().isEmpty()) {
                txt.append("Vulnerabilities: ").append(target.getExploits().size()).append(" found\n");
            }
            txt.append("\n");
        }
        
        return writeToFile(filename + ".txt", txt.toString());
    }
    
    /**
     * Share a file using Android's share intent
     * @param file file to share
     * @param mimeType MIME type of the file
     */
    public void shareFile(@NonNull File file, @NonNull String mimeType) {
        try {
            Uri uri = FileProvider.getUriForFile(mContext, 
                    mContext.getPackageName() + ".fileprovider", file);
            
            Intent shareIntent = new Intent(Intent.ACTION_SEND);
            shareIntent.setType(mimeType);
            shareIntent.putExtra(Intent.EXTRA_STREAM, uri);
            shareIntent.putExtra(Intent.EXTRA_SUBJECT, "cSploit Scan Report");
            shareIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            shareIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            
            mContext.startActivity(Intent.createChooser(shareIntent, "Share Scan Results")
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
        } catch (Exception e) {
            LoggingHelper.e(TAG, "Failed to share file", e);
        }
    }
    
    /**
     * Get the export directory
     * @return export directory File
     */
    @NonNull
    public File getExportDirectory() {
        File exportDir = new File(System.getStoragePath(), "exports");
        if (!exportDir.exists()) {
            exportDir.mkdirs();
        }
        return exportDir;
    }
    
    private String targetToJson(Target target) {
        StringBuilder json = new StringBuilder();
        json.append("    {\n");
        json.append("      \"address\": \"").append(escapeJson(target.getCommandLineRepresentation())).append("\",\n");
        json.append("      \"type\": \"").append(target.getType().toString()).append("\",\n");
        
        if (target.getHostname() != null) {
            json.append("      \"hostname\": \"").append(escapeJson(target.getHostname())).append("\",\n");
        }
        if (target.getAlias() != null) {
            json.append("      \"alias\": \"").append(escapeJson(target.getAlias())).append("\",\n");
        }
        if (target.getHardwareAddress() != null) {
            json.append("      \"mac\": \"").append(bytesToMac(target.getHardwareAddress())).append("\",\n");
        }
        if (target.getDeviceType() != null) {
            json.append("      \"deviceType\": \"").append(escapeJson(target.getDeviceType())).append("\",\n");
        }
        if (target.getDeviceOS() != null) {
            json.append("      \"os\": \"").append(escapeJson(target.getDeviceOS())).append("\",\n");
        }
        
        json.append("      \"openPorts\": [");
        if (target.hasOpenPorts()) {
            boolean first = true;
            for (Target.Port port : target.getOpenPorts()) {
                if (!first) json.append(", ");
                first = false;
                json.append("{\"port\": ").append(port.getNumber());
                json.append(", \"protocol\": \"").append(port.getProtocol().toString()).append("\"");
                if (port.getService() != null) {
                    json.append(", \"service\": \"").append(escapeJson(port.getService())).append("\"");
                }
                json.append("}");
            }
        }
        json.append("],\n");
        
        json.append("      \"exploitCount\": ").append(target.getExploits().size()).append("\n");
        json.append("    }");
        
        return json.toString();
    }
    
    @Nullable
    private File writeToFile(String filename, String content) {
        File file = new File(getExportDirectory(), filename);
        BufferedWriter writer = null;
        
        try {
            writer = new BufferedWriter(new FileWriter(file));
            writer.write(content);
            writer.flush();
            LoggingHelper.d(TAG, "Exported to: " + file.getAbsolutePath());
            return file;
        } catch (IOException e) {
            LoggingHelper.e(TAG, "Failed to write export file", e);
            return null;
        } finally {
            if (writer != null) {
                try {
                    writer.close();
                } catch (IOException e) {
                    LoggingHelper.w(TAG, "Failed to close writer: " + e.getMessage());
                }
            }
        }
    }
    
    private String getCurrentTimestamp() {
        return mDateFormat.format(new Date());
    }
    
    private String formatPorts(Target target) {
        if (!target.hasOpenPorts()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (Target.Port port : target.getOpenPorts()) {
            if (!first) sb.append(", ");
            first = false;
            sb.append(port.getNumber());
            if (port.getService() != null) {
                sb.append(" (").append(port.getService()).append(")");
            }
        }
        return sb.toString();
    }
    
    private String bytesToMac(byte[] bytes) {
        if (bytes == null || bytes.length != 6) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) sb.append(":");
            sb.append(String.format("%02X", bytes[i]));
        }
        return sb.toString();
    }
    
    private String escapeJson(String text) {
        if (text == null) return "";
        return text.replace("\\", "\\\\")
                   .replace("\"", "\\\"")
                   .replace("\n", "\\n")
                   .replace("\r", "\\r")
                   .replace("\t", "\\t");
    }
    
    private String escapeCsv(String text) {
        if (text == null) return "";
        if (text.contains(",") || text.contains("\"") || text.contains("\n")) {
            return "\"" + text.replace("\"", "\"\"") + "\"";
        }
        return text;
    }
    
    private String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#39;");
    }
}
