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

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

/**
 * OutputFormatter - Formats tool output for display.
 * 
 * Provides:
 * - Colorization of output
 * - Structured formatting
 * - Time/size formatting
 * - Table generation
 * - Progress indicators
 * 
 * Usage:
 * {@code
 * // Format scan output
 * String formatted = OutputFormatter.formatScanResult(ip, ports, os);
 * 
 * // Format table
 * String table = OutputFormatter.formatTable(headers, rows);
 * 
 * // Format time
 * String time = OutputFormatter.formatDuration(125000); // "2m 5s"
 * }
 */
public final class OutputFormatter {
    
    public static final String TAG = "OutputFormatter";
    
    // ANSI color codes (for terminal output)
    public static final String RESET = "\u001B[0m";
    public static final String RED = "\u001B[31m";
    public static final String GREEN = "\u001B[32m";
    public static final String YELLOW = "\u001B[33m";
    public static final String BLUE = "\u001B[34m";
    public static final String MAGENTA = "\u001B[35m";
    public static final String CYAN = "\u001B[36m";
    public static final String WHITE = "\u001B[37m";
    public static final String BOLD = "\u001B[1m";
    
    // Box drawing characters
    private static final char BOX_HORIZONTAL = '─';
    private static final char BOX_VERTICAL = '│';
    private static final char BOX_TOP_LEFT = '┌';
    private static final char BOX_TOP_RIGHT = '┐';
    private static final char BOX_BOTTOM_LEFT = '└';
    private static final char BOX_BOTTOM_RIGHT = '┘';
    private static final char BOX_T_DOWN = '┬';
    private static final char BOX_T_UP = '┴';
    private static final char BOX_T_RIGHT = '├';
    private static final char BOX_T_LEFT = '┤';
    private static final char BOX_CROSS = '┼';
    
    private OutputFormatter() {}
    
    /**
     * Format a scan result summary.
     */
    @NonNull
    public static String formatScanResult(@NonNull String ip, @NonNull List<Integer> openPorts,
                                          @Nullable String os, @Nullable String hostname) {
        StringBuilder sb = new StringBuilder();
        
        sb.append("═══════════════════════════════════════\n");
        sb.append(String.format("  Target: %s\n", ip));
        
        if (hostname != null && !hostname.isEmpty()) {
            sb.append(String.format("  Hostname: %s\n", hostname));
        }
        
        if (os != null && !os.isEmpty()) {
            sb.append(String.format("  OS: %s\n", os));
        }
        
        sb.append("───────────────────────────────────────\n");
        sb.append(String.format("  Open Ports: %d\n", openPorts.size()));
        
        if (!openPorts.isEmpty()) {
            sb.append("  ");
            for (int i = 0; i < openPorts.size(); i++) {
                if (i > 0) sb.append(", ");
                sb.append(openPorts.get(i));
            }
            sb.append("\n");
        }
        
        sb.append("═══════════════════════════════════════");
        
        return sb.toString();
    }
    
    /**
     * Format a table with headers and rows.
     */
    @NonNull
    public static String formatTable(@NonNull String[] headers, @NonNull List<String[]> rows) {
        if (headers.length == 0) return "";
        
        // Calculate column widths
        int[] widths = new int[headers.length];
        for (int i = 0; i < headers.length; i++) {
            widths[i] = headers[i].length();
        }
        
        for (String[] row : rows) {
            for (int i = 0; i < Math.min(row.length, headers.length); i++) {
                widths[i] = Math.max(widths[i], row[i] != null ? row[i].length() : 0);
            }
        }
        
        StringBuilder sb = new StringBuilder();
        
        // Top border
        sb.append(BOX_TOP_LEFT);
        for (int i = 0; i < widths.length; i++) {
            sb.append(repeat(BOX_HORIZONTAL, widths[i] + 2));
            sb.append(i < widths.length - 1 ? BOX_T_DOWN : BOX_TOP_RIGHT);
        }
        sb.append("\n");
        
        // Headers
        sb.append(BOX_VERTICAL);
        for (int i = 0; i < headers.length; i++) {
            sb.append(" ").append(padRight(headers[i], widths[i])).append(" ");
            sb.append(BOX_VERTICAL);
        }
        sb.append("\n");
        
        // Header separator
        sb.append(BOX_T_RIGHT);
        for (int i = 0; i < widths.length; i++) {
            sb.append(repeat(BOX_HORIZONTAL, widths[i] + 2));
            sb.append(i < widths.length - 1 ? BOX_CROSS : BOX_T_LEFT);
        }
        sb.append("\n");
        
        // Rows
        for (String[] row : rows) {
            sb.append(BOX_VERTICAL);
            for (int i = 0; i < headers.length; i++) {
                String value = i < row.length && row[i] != null ? row[i] : "";
                sb.append(" ").append(padRight(value, widths[i])).append(" ");
                sb.append(BOX_VERTICAL);
            }
            sb.append("\n");
        }
        
        // Bottom border
        sb.append(BOX_BOTTOM_LEFT);
        for (int i = 0; i < widths.length; i++) {
            sb.append(repeat(BOX_HORIZONTAL, widths[i] + 2));
            sb.append(i < widths.length - 1 ? BOX_T_UP : BOX_BOTTOM_RIGHT);
        }
        
        return sb.toString();
    }
    
    /**
     * Format a simple list.
     */
    @NonNull
    public static String formatList(@NonNull List<String> items, @Nullable String title) {
        StringBuilder sb = new StringBuilder();
        
        if (title != null) {
            sb.append(title).append(":\n");
        }
        
        for (int i = 0; i < items.size(); i++) {
            sb.append(String.format("  %d. %s\n", i + 1, items.get(i)));
        }
        
        return sb.toString();
    }
    
    /**
     * Format a bullet list.
     */
    @NonNull
    public static String formatBulletList(@NonNull List<String> items) {
        StringBuilder sb = new StringBuilder();
        for (String item : items) {
            sb.append("  • ").append(item).append("\n");
        }
        return sb.toString();
    }
    
    /**
     * Format duration in human-readable form.
     */
    @NonNull
    public static String formatDuration(long millis) {
        if (millis < 0) return "N/A";
        
        if (millis < 1000) {
            return millis + "ms";
        }
        
        long seconds = TimeUnit.MILLISECONDS.toSeconds(millis);
        long minutes = TimeUnit.MILLISECONDS.toMinutes(millis);
        long hours = TimeUnit.MILLISECONDS.toHours(millis);
        long days = TimeUnit.MILLISECONDS.toDays(millis);
        
        if (days > 0) {
            return String.format(Locale.US, "%dd %dh", days, hours % 24);
        } else if (hours > 0) {
            return String.format(Locale.US, "%dh %dm", hours, minutes % 60);
        } else if (minutes > 0) {
            return String.format(Locale.US, "%dm %ds", minutes, seconds % 60);
        } else {
            return String.format(Locale.US, "%ds", seconds);
        }
    }
    
    /**
     * Format byte size in human-readable form.
     */
    @NonNull
    public static String formatBytes(long bytes) {
        if (bytes < 0) return "N/A";
        
        if (bytes < 1024) {
            return bytes + " B";
        }
        
        String[] units = {"KB", "MB", "GB", "TB"};
        double size = bytes;
        int unitIndex = -1;
        
        while (size >= 1024 && unitIndex < units.length - 1) {
            size /= 1024;
            unitIndex++;
        }
        
        return String.format(Locale.US, "%.1f %s", size, units[unitIndex]);
    }
    
    /**
     * Format bandwidth in human-readable form.
     */
    @NonNull
    public static String formatBandwidth(long bytesPerSecond) {
        return formatBytes(bytesPerSecond) + "/s";
    }
    
    /**
     * Format a percentage.
     */
    @NonNull
    public static String formatPercent(double value) {
        return String.format(Locale.US, "%.1f%%", value * 100);
    }
    
    /**
     * Format IP address with port.
     */
    @NonNull
    public static String formatAddress(@NonNull String ip, int port) {
        if (ip.contains(":")) {
            // IPv6
            return String.format("[%s]:%d", ip, port);
        }
        return String.format("%s:%d", ip, port);
    }
    
    /**
     * Create a progress bar string.
     */
    @NonNull
    public static String formatProgressBar(double progress, int width) {
        int filled = (int) (progress * width);
        int empty = width - filled;
        
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        sb.append(repeat('█', filled));
        sb.append(repeat('░', empty));
        sb.append("] ");
        sb.append(String.format(Locale.US, "%.1f%%", progress * 100));
        
        return sb.toString();
    }
    
    /**
     * Format a key-value pair.
     */
    @NonNull
    public static String formatKeyValue(@NonNull String key, @Nullable Object value) {
        return String.format("%-20s: %s", key, value != null ? value.toString() : "N/A");
    }
    
    /**
     * Format multiple key-value pairs.
     */
    @NonNull
    public static String formatKeyValues(@NonNull String[][] pairs) {
        int maxKeyLength = 0;
        for (String[] pair : pairs) {
            if (pair.length > 0 && pair[0] != null) {
                maxKeyLength = Math.max(maxKeyLength, pair[0].length());
            }
        }
        
        StringBuilder sb = new StringBuilder();
        String format = "%-" + maxKeyLength + "s : %s\n";
        
        for (String[] pair : pairs) {
            if (pair.length >= 2) {
                sb.append(String.format(format, pair[0], pair[1] != null ? pair[1] : "N/A"));
            }
        }
        
        return sb.toString();
    }
    
    /**
     * Add color to text (for terminal output).
     */
    @NonNull
    public static String colorize(@NonNull String text, @NonNull String color) {
        return color + text + RESET;
    }
    
    /**
     * Format status indicator.
     */
    @NonNull
    public static String formatStatus(boolean success) {
        return success ? "[✓]" : "[✗]";
    }
    
    /**
     * Format status indicator with color.
     */
    @NonNull
    public static String formatStatusColored(boolean success) {
        return success ? colorize("[✓]", GREEN) : colorize("[✗]", RED);
    }
    
    /**
     * Format a section header.
     */
    @NonNull
    public static String formatHeader(@NonNull String title) {
        int width = Math.max(title.length() + 4, 40);
        StringBuilder sb = new StringBuilder();
        
        sb.append(repeat('═', width)).append("\n");
        sb.append("  ").append(title).append("\n");
        sb.append(repeat('═', width));
        
        return sb.toString();
    }
    
    /**
     * Format a subsection header.
     */
    @NonNull
    public static String formatSubheader(@NonNull String title) {
        return "── " + title + " " + repeat('─', 30);
    }
    
    /**
     * Format port scan result line.
     */
    @NonNull
    public static String formatPortResult(int port, @NonNull String state, 
                                          @Nullable String service, @Nullable String version) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("%-7d", port));
        sb.append(String.format("%-10s", state));
        sb.append(String.format("%-15s", service != null ? service : "unknown"));
        if (version != null) {
            sb.append(version);
        }
        return sb.toString();
    }
    
    /**
     * Wrap text to specified width.
     */
    @NonNull
    public static String wrapText(@NonNull String text, int maxWidth) {
        if (text.length() <= maxWidth) {
            return text;
        }
        
        StringBuilder sb = new StringBuilder();
        String[] words = text.split(" ");
        int currentLineLength = 0;
        
        for (String word : words) {
            if (currentLineLength + word.length() > maxWidth) {
                sb.append("\n");
                currentLineLength = 0;
            } else if (currentLineLength > 0) {
                sb.append(" ");
                currentLineLength++;
            }
            sb.append(word);
            currentLineLength += word.length();
        }
        
        return sb.toString();
    }
    
    /**
     * Indent text.
     */
    @NonNull
    public static String indent(@NonNull String text, int spaces) {
        String indent = repeat(' ', spaces);
        return indent + text.replace("\n", "\n" + indent);
    }
    
    /**
     * Truncate text with ellipsis.
     */
    @NonNull
    public static String truncate(@NonNull String text, int maxLength) {
        if (text.length() <= maxLength) {
            return text;
        }
        return text.substring(0, maxLength - 3) + "...";
    }
    
    // Helper methods
    
    private static String repeat(char c, int count) {
        if (count <= 0) return "";
        StringBuilder sb = new StringBuilder(count);
        for (int i = 0; i < count; i++) {
            sb.append(c);
        }
        return sb.toString();
    }
    
    private static String padRight(String s, int width) {
        if (s.length() >= width) return s;
        StringBuilder sb = new StringBuilder(s);
        while (sb.length() < width) {
            sb.append(' ');
        }
        return sb.toString();
    }
}
