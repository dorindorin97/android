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

import android.text.Spannable;
import android.text.SpannableString;
import android.text.SpannableStringBuilder;
import android.text.style.ForegroundColorSpan;
import android.text.style.StyleSpan;
import android.text.style.TypefaceSpan;

import androidx.annotation.ColorInt;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * TextFormattingHelper - Rich text formatting utilities for terminal output and logs.
 * 
 * Provides methods for:
 * - ANSI color code parsing
 * - Syntax highlighting for common patterns
 * - IP address highlighting
 * - Port/service highlighting
 * - Error/warning highlighting
 * - Log level formatting
 * 
 * Usage:
 * {@code
 * // Highlight IPs in text
 * Spannable formatted = TextFormattingHelper.highlightIpAddresses(text, Color.CYAN);
 * 
 * // Format log line with colors
 * Spannable log = TextFormattingHelper.formatLogLine(logText);
 * 
 * // Parse ANSI codes
 * Spannable colored = TextFormattingHelper.parseAnsiColors(ansiText);
 * }
 */
public final class TextFormattingHelper {
    
    public static final String TAG = "TextFormattingHelper";
    
    // Common regex patterns
    private static final Pattern IP_PATTERN = Pattern.compile(
            "\\b(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\b");
    
    private static final Pattern MAC_PATTERN = Pattern.compile(
            "\\b([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\\b");
    
    private static final Pattern PORT_PATTERN = Pattern.compile(
            "\\b(\\d{1,5})/?(tcp|udp)?\\b", Pattern.CASE_INSENSITIVE);
    
    private static final Pattern URL_PATTERN = Pattern.compile(
            "(https?://[\\w\\-._~:/?#\\[\\]@!$&'()*+,;=%]+)", Pattern.CASE_INSENSITIVE);
    
    private static final Pattern LOG_LEVEL_PATTERN = Pattern.compile(
            "\\b(ERROR|WARN|WARNING|INFO|DEBUG|TRACE|VERBOSE)\\b", Pattern.CASE_INSENSITIVE);
    
    // ANSI escape pattern
    private static final Pattern ANSI_PATTERN = Pattern.compile(
            "\\x1b\\[(\\d+(?:;\\d+)*)m");
    
    // Default colors
    private static final int COLOR_IP = 0xFF00BFFF;        // Deep sky blue
    private static final int COLOR_MAC = 0xFFFFD700;       // Gold
    private static final int COLOR_PORT = 0xFF32CD32;      // Lime green
    private static final int COLOR_URL = 0xFF1E90FF;       // Dodger blue
    private static final int COLOR_ERROR = 0xFFFF4444;     // Red
    private static final int COLOR_WARNING = 0xFFFFBB33;   // Orange
    private static final int COLOR_INFO = 0xFF33B5E5;      // Blue
    private static final int COLOR_DEBUG = 0xFF99CC00;     // Green
    private static final int COLOR_SUCCESS = 0xFF00FF00;   // Bright green
    
    private TextFormattingHelper() {}
    
    /**
     * Highlight IP addresses in text.
     * 
     * @param text input text
     * @param color highlight color
     * @return formatted text
     */
    @NonNull
    public static Spannable highlightIpAddresses(@NonNull CharSequence text, @ColorInt int color) {
        return highlightPattern(text, IP_PATTERN, color);
    }
    
    /**
     * Highlight IP addresses with default color.
     */
    @NonNull
    public static Spannable highlightIpAddresses(@NonNull CharSequence text) {
        return highlightIpAddresses(text, COLOR_IP);
    }
    
    /**
     * Highlight MAC addresses in text.
     * 
     * @param text input text
     * @param color highlight color
     * @return formatted text
     */
    @NonNull
    public static Spannable highlightMacAddresses(@NonNull CharSequence text, @ColorInt int color) {
        return highlightPattern(text, MAC_PATTERN, color);
    }
    
    /**
     * Highlight MAC addresses with default color.
     */
    @NonNull
    public static Spannable highlightMacAddresses(@NonNull CharSequence text) {
        return highlightMacAddresses(text, COLOR_MAC);
    }
    
    /**
     * Highlight ports in text.
     * 
     * @param text input text
     * @param color highlight color
     * @return formatted text
     */
    @NonNull
    public static Spannable highlightPorts(@NonNull CharSequence text, @ColorInt int color) {
        return highlightPattern(text, PORT_PATTERN, color);
    }
    
    /**
     * Highlight ports with default color.
     */
    @NonNull
    public static Spannable highlightPorts(@NonNull CharSequence text) {
        return highlightPorts(text, COLOR_PORT);
    }
    
    /**
     * Highlight URLs in text.
     * 
     * @param text input text
     * @param color highlight color
     * @return formatted text
     */
    @NonNull
    public static Spannable highlightUrls(@NonNull CharSequence text, @ColorInt int color) {
        return highlightPattern(text, URL_PATTERN, color);
    }
    
    /**
     * Highlight URLs with default color.
     */
    @NonNull
    public static Spannable highlightUrls(@NonNull CharSequence text) {
        return highlightUrls(text, COLOR_URL);
    }
    
    /**
     * Highlight text matching a pattern.
     * 
     * @param text input text
     * @param pattern regex pattern
     * @param color highlight color
     * @return formatted text
     */
    @NonNull
    public static Spannable highlightPattern(@NonNull CharSequence text, 
                                             @NonNull Pattern pattern, 
                                             @ColorInt int color) {
        SpannableString spannable = new SpannableString(text);
        Matcher matcher = pattern.matcher(text);
        
        while (matcher.find()) {
            spannable.setSpan(
                    new ForegroundColorSpan(color),
                    matcher.start(),
                    matcher.end(),
                    Spannable.SPAN_EXCLUSIVE_EXCLUSIVE
            );
        }
        
        return spannable;
    }
    
    /**
     * Apply multiple highlights to text.
     * 
     * @param text input text
     * @return formatted text with IP, MAC, port, and URL highlights
     */
    @NonNull
    public static Spannable highlightAll(@NonNull CharSequence text) {
        SpannableStringBuilder builder = new SpannableStringBuilder(text);
        
        // Apply highlights in order (later ones take precedence)
        applyPatternHighlight(builder, IP_PATTERN, COLOR_IP);
        applyPatternHighlight(builder, MAC_PATTERN, COLOR_MAC);
        applyPatternHighlight(builder, PORT_PATTERN, COLOR_PORT);
        applyPatternHighlight(builder, URL_PATTERN, COLOR_URL);
        
        return builder;
    }
    
    /**
     * Apply pattern highlight to a SpannableStringBuilder.
     */
    private static void applyPatternHighlight(@NonNull SpannableStringBuilder builder,
                                              @NonNull Pattern pattern,
                                              @ColorInt int color) {
        Matcher matcher = pattern.matcher(builder);
        while (matcher.find()) {
            builder.setSpan(
                    new ForegroundColorSpan(color),
                    matcher.start(),
                    matcher.end(),
                    Spannable.SPAN_EXCLUSIVE_EXCLUSIVE
            );
        }
    }
    
    /**
     * Format a log line with level-based coloring.
     * 
     * @param text log line
     * @return formatted log line
     */
    @NonNull
    public static Spannable formatLogLine(@NonNull CharSequence text) {
        SpannableStringBuilder builder = new SpannableStringBuilder(text);
        Matcher matcher = LOG_LEVEL_PATTERN.matcher(text);
        
        while (matcher.find()) {
            String level = matcher.group(1).toUpperCase();
            int color = getLogLevelColor(level);
            
            builder.setSpan(
                    new ForegroundColorSpan(color),
                    matcher.start(),
                    matcher.end(),
                    Spannable.SPAN_EXCLUSIVE_EXCLUSIVE
            );
            builder.setSpan(
                    new StyleSpan(android.graphics.Typeface.BOLD),
                    matcher.start(),
                    matcher.end(),
                    Spannable.SPAN_EXCLUSIVE_EXCLUSIVE
            );
        }
        
        return builder;
    }
    
    /**
     * Get color for log level.
     */
    @ColorInt
    private static int getLogLevelColor(@NonNull String level) {
        switch (level) {
            case "ERROR":
                return COLOR_ERROR;
            case "WARN":
            case "WARNING":
                return COLOR_WARNING;
            case "INFO":
                return COLOR_INFO;
            case "DEBUG":
            case "TRACE":
            case "VERBOSE":
                return COLOR_DEBUG;
            default:
                return 0xFFFFFFFF;
        }
    }
    
    /**
     * Parse ANSI color codes and apply Android spans.
     * Supports basic ANSI colors (30-37, 40-47, 90-97, 100-107).
     * 
     * @param text text with ANSI codes
     * @return formatted text without ANSI codes
     */
    @NonNull
    public static Spannable parseAnsiColors(@NonNull CharSequence text) {
        SpannableStringBuilder builder = new SpannableStringBuilder();
        Matcher matcher = ANSI_PATTERN.matcher(text);
        
        int lastEnd = 0;
        int currentColor = 0xFFFFFFFF;
        
        while (matcher.find()) {
            // Append text before this escape sequence
            if (matcher.start() > lastEnd) {
                int segmentStart = builder.length();
                builder.append(text.subSequence(lastEnd, matcher.start()));
                
                if (currentColor != 0xFFFFFFFF) {
                    builder.setSpan(
                            new ForegroundColorSpan(currentColor),
                            segmentStart,
                            builder.length(),
                            Spannable.SPAN_EXCLUSIVE_EXCLUSIVE
                    );
                }
            }
            
            // Parse ANSI code
            String codes = matcher.group(1);
            currentColor = parseAnsiCode(codes);
            lastEnd = matcher.end();
        }
        
        // Append remaining text
        if (lastEnd < text.length()) {
            int segmentStart = builder.length();
            builder.append(text.subSequence(lastEnd, text.length()));
            
            if (currentColor != 0xFFFFFFFF) {
                builder.setSpan(
                        new ForegroundColorSpan(currentColor),
                        segmentStart,
                        builder.length(),
                        Spannable.SPAN_EXCLUSIVE_EXCLUSIVE
                );
            }
        }
        
        return builder;
    }
    
    /**
     * Parse ANSI code string and return color.
     */
    @ColorInt
    private static int parseAnsiCode(@NonNull String codes) {
        String[] parts = codes.split(";");
        
        for (String part : parts) {
            try {
                int code = Integer.parseInt(part);
                int color = ansiCodeToColor(code);
                if (color != 0) {
                    return color;
                }
            } catch (NumberFormatException e) {
                // Invalid ANSI code format, skip this part
            }
        }
        
        return 0xFFFFFFFF;
    }
    
    /**
     * Convert ANSI code to Android color.
     */
    @ColorInt
    private static int ansiCodeToColor(int code) {
        // Standard foreground colors (30-37)
        switch (code) {
            case 0:  return 0xFFFFFFFF; // Reset
            case 30: return 0xFF000000; // Black
            case 31: return 0xFFCC0000; // Red
            case 32: return 0xFF00CC00; // Green
            case 33: return 0xFFCCCC00; // Yellow
            case 34: return 0xFF0000CC; // Blue
            case 35: return 0xFFCC00CC; // Magenta
            case 36: return 0xFF00CCCC; // Cyan
            case 37: return 0xFFCCCCCC; // White
            
            // Bright foreground colors (90-97)
            case 90: return 0xFF666666; // Bright Black
            case 91: return 0xFFFF0000; // Bright Red
            case 92: return 0xFF00FF00; // Bright Green
            case 93: return 0xFFFFFF00; // Bright Yellow
            case 94: return 0xFF0000FF; // Bright Blue
            case 95: return 0xFFFF00FF; // Bright Magenta
            case 96: return 0xFF00FFFF; // Bright Cyan
            case 97: return 0xFFFFFFFF; // Bright White
            
            default: return 0;
        }
    }
    
    /**
     * Strip all ANSI codes from text.
     * 
     * @param text text with ANSI codes
     * @return plain text without ANSI codes
     */
    @NonNull
    public static String stripAnsiCodes(@NonNull CharSequence text) {
        return ANSI_PATTERN.matcher(text).replaceAll("");
    }
    
    /**
     * Create text with monospace font.
     * 
     * @param text input text
     * @return text with monospace typeface
     */
    @NonNull
    public static Spannable monospace(@NonNull CharSequence text) {
        SpannableString spannable = new SpannableString(text);
        spannable.setSpan(
                new TypefaceSpan("monospace"),
                0,
                text.length(),
                Spannable.SPAN_EXCLUSIVE_EXCLUSIVE
        );
        return spannable;
    }
    
    /**
     * Create bold text.
     * 
     * @param text input text
     * @return bold text
     */
    @NonNull
    public static Spannable bold(@NonNull CharSequence text) {
        SpannableString spannable = new SpannableString(text);
        spannable.setSpan(
                new StyleSpan(android.graphics.Typeface.BOLD),
                0,
                text.length(),
                Spannable.SPAN_EXCLUSIVE_EXCLUSIVE
        );
        return spannable;
    }
    
    /**
     * Create colored text.
     * 
     * @param text input text
     * @param color text color
     * @return colored text
     */
    @NonNull
    public static Spannable colored(@NonNull CharSequence text, @ColorInt int color) {
        SpannableString spannable = new SpannableString(text);
        spannable.setSpan(
                new ForegroundColorSpan(color),
                0,
                text.length(),
                Spannable.SPAN_EXCLUSIVE_EXCLUSIVE
        );
        return spannable;
    }
    
    /**
     * Create success styled text (green).
     */
    @NonNull
    public static Spannable success(@NonNull CharSequence text) {
        return colored(text, COLOR_SUCCESS);
    }
    
    /**
     * Create error styled text (red).
     */
    @NonNull
    public static Spannable error(@NonNull CharSequence text) {
        return colored(text, COLOR_ERROR);
    }
    
    /**
     * Create warning styled text (orange).
     */
    @NonNull
    public static Spannable warning(@NonNull CharSequence text) {
        return colored(text, COLOR_WARNING);
    }
    
    /**
     * Create info styled text (blue).
     */
    @NonNull
    public static Spannable info(@NonNull CharSequence text) {
        return colored(text, COLOR_INFO);
    }
}
