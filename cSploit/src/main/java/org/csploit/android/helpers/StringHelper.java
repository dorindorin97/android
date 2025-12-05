package org.csploit.android.helpers;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

/**
 * String manipulation and formatting utilities.
 * Provides convenient methods for common string operations.
 */
public final class StringHelper {

    /**
     * Capitalize first letter of a string
     */
    @NonNull
    public static String capitalize(@Nullable String str) {
        if (ValidationHelper.isEmpty(str)) {
            return "";
        }
        return str.substring(0, 1).toUpperCase() + str.substring(1);
    }

    /**
     * Convert camelCase to snake_case
     */
    @NonNull
    public static String camelToSnake(@Nullable String str) {
        if (ValidationHelper.isEmpty(str)) {
            return "";
        }
        return str.replaceAll("([a-z])([A-Z]+)", "$1_$2").toLowerCase();
    }

    /**
     * Convert snake_case to camelCase
     */
    @NonNull
    public static String snakeToCamel(@Nullable String str) {
        if (ValidationHelper.isEmpty(str)) {
            return "";
        }

        StringBuilder result = new StringBuilder();
        String[] parts = str.split("_");
        
        for (int i = 0; i < parts.length; i++) {
            if (i == 0) {
                result.append(parts[i]);
            } else {
                result.append(capitalize(parts[i]));
            }
        }
        
        return result.toString();
    }

    /**
     * Repeat a string n times
     */
    @NonNull
    public static String repeat(@Nullable String str, int count) {
        if (ValidationHelper.isEmpty(str) || count <= 0) {
            return "";
        }

        StringBuilder result = new StringBuilder();
        for (int i = 0; i < count; i++) {
            result.append(str);
        }
        return result.toString();
    }

    /**
     * Truncate string to max length with ellipsis
     */
    @NonNull
    public static String truncate(@Nullable String str, int maxLength) {
        if (ValidationHelper.isEmpty(str)) {
            return "";
        }

        if (str.length() <= maxLength) {
            return str;
        }

        return str.substring(0, maxLength - 3) + "...";
    }

    /**
     * Format bytes to human readable size
     */
    @NonNull
    public static String formatBytes(long bytes) {
        if (bytes <= 0) return "0 B";
        final String[] units = new String[]{"B", "KB", "MB", "GB", "TB"};
        int digitGroups = (int) (Math.log10(bytes) / Math.log10(1024));
        return String.format("%.1f %s", bytes / Math.pow(1024, digitGroups), units[digitGroups]);
    }

    /**
     * Format duration in milliseconds to human readable format
     */
    @NonNull
    public static String formatDuration(long millis) {
        if (millis < 0) return "0ms";
        
        if (millis < 1000) {
            return millis + "ms";
        } else if (millis < 60000) {
            return String.format("%.1fs", millis / 1000.0);
        } else if (millis < 3600000) {
            long minutes = millis / 60000;
            long seconds = (millis % 60000) / 1000;
            return String.format("%dm %ds", minutes, seconds);
        } else {
            long hours = millis / 3600000;
            long minutes = (millis % 3600000) / 60000;
            return String.format("%dh %dm", hours, minutes);
        }
    }

    /**
     * Join strings with separator
     */
    @NonNull
    public static String join(@Nullable String separator, @Nullable Object... items) {
        if (items == null || items.length == 0) {
            return "";
        }

        String sep = separator != null ? separator : "";
        StringBuilder result = new StringBuilder();
        
        for (int i = 0; i < items.length; i++) {
            if (i > 0) {
                result.append(sep);
            }
            result.append(items[i] != null ? items[i].toString() : "");
        }
        
        return result.toString();
    }

    /**
     * Split string by pattern and trim each part
     */
    @NonNull
    public static String[] splitAndTrim(@Nullable String str, @NonNull String delimiter) {
        if (ValidationHelper.isEmpty(str)) {
            return new String[0];
        }

        String[] parts = str.split(delimiter);
        for (int i = 0; i < parts.length; i++) {
            parts[i] = parts[i].trim();
        }
        return parts;
    }

    /**
     * Check if string contains any of the given substrings
     */
    public static boolean containsAny(@Nullable String str, @NonNull String... substrings) {
        if (ValidationHelper.isEmpty(str) || substrings.length == 0) {
            return false;
        }

        for (String substring : substrings) {
            if (str.contains(substring)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if string contains all of the given substrings
     */
    public static boolean containsAll(@Nullable String str, @NonNull String... substrings) {
        if (ValidationHelper.isEmpty(str) || substrings.length == 0) {
            return false;
        }

        for (String substring : substrings) {
            if (!str.contains(substring)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Sanitize string by removing special characters
     */
    @NonNull
    public static String sanitize(@Nullable String str) {
        if (ValidationHelper.isEmpty(str)) {
            return "";
        }

        return str.replaceAll("[^a-zA-Z0-9._-]", "");
    }

    /**
     * Reverse a string
     */
    @NonNull
    public static String reverse(@Nullable String str) {
        if (ValidationHelper.isEmpty(str)) {
            return "";
        }

        return new StringBuilder(str).reverse().toString();
    }

    /**
     * Check if string is palindrome
     */
    public static boolean isPalindrome(@Nullable String str) {
        if (ValidationHelper.isEmpty(str)) {
            return false;
        }

        String cleaned = str.replaceAll("\\s+", "").toLowerCase();
        return cleaned.equals(reverse(cleaned));
    }
}
