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

    /**
     * Count occurrences of substring in string
     */
    public static int countOccurrences(@Nullable String str, @Nullable String substring) {
        if (ValidationHelper.isEmpty(str) || ValidationHelper.isEmpty(substring)) {
            return 0;
        }

        int count = 0;
        int idx = 0;
        while ((idx = str.indexOf(substring, idx)) != -1) {
            count++;
            idx += substring.length();
        }
        return count;
    }

    /**
     * Left pad string to target length
     */
    @NonNull
    public static String leftPad(@Nullable String str, int length, char padChar) {
        if (str == null) str = "";
        if (str.length() >= length) return str;

        StringBuilder sb = new StringBuilder();
        for (int i = str.length(); i < length; i++) {
            sb.append(padChar);
        }
        sb.append(str);
        return sb.toString();
    }

    /**
     * Right pad string to target length
     */
    @NonNull
    public static String rightPad(@Nullable String str, int length, char padChar) {
        if (str == null) str = "";
        if (str.length() >= length) return str;

        StringBuilder sb = new StringBuilder(str);
        while (sb.length() < length) {
            sb.append(padChar);
        }
        return sb.toString();
    }

    /**
     * Center string within target length
     */
    @NonNull
    public static String center(@Nullable String str, int length, char padChar) {
        if (str == null) str = "";
        if (str.length() >= length) return str;

        int padding = length - str.length();
        int leftPadding = padding / 2;
        int rightPadding = padding - leftPadding;

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < leftPadding; i++) sb.append(padChar);
        sb.append(str);
        for (int i = 0; i < rightPadding; i++) sb.append(padChar);
        return sb.toString();
    }

    /**
     * Extract substring between two delimiters
     */
    @Nullable
    public static String extractBetween(@Nullable String str, @NonNull String start, @NonNull String end) {
        if (ValidationHelper.isEmpty(str)) return null;

        int startIdx = str.indexOf(start);
        if (startIdx == -1) return null;

        startIdx += start.length();
        int endIdx = str.indexOf(end, startIdx);
        if (endIdx == -1) return null;

        return str.substring(startIdx, endIdx);
    }

    /**
     * Remove all whitespace from string
     */
    @NonNull
    public static String removeWhitespace(@Nullable String str) {
        if (ValidationHelper.isEmpty(str)) return "";
        return str.replaceAll("\\s+", "");
    }

    /**
     * Normalize whitespace (replace multiple spaces with single space)
     */
    @NonNull
    public static String normalizeWhitespace(@Nullable String str) {
        if (ValidationHelper.isEmpty(str)) return "";
        return str.replaceAll("\\s+", " ").trim();
    }

    /**
     * Check if string is numeric
     */
    public static boolean isNumeric(@Nullable String str) {
        if (ValidationHelper.isEmpty(str)) return false;
        return str.matches("-?\\d+(\\.\\d+)?");
    }

    /**
     * Check if string is alphanumeric
     */
    public static boolean isAlphanumeric(@Nullable String str) {
        if (ValidationHelper.isEmpty(str)) return false;
        return str.matches("[a-zA-Z0-9]+");
    }

    /**
     * Convert string to title case
     */
    @NonNull
    public static String toTitleCase(@Nullable String str) {
        if (ValidationHelper.isEmpty(str)) return "";

        StringBuilder result = new StringBuilder();
        boolean capitalizeNext = true;

        for (char c : str.toCharArray()) {
            if (Character.isWhitespace(c)) {
                capitalizeNext = true;
                result.append(c);
            } else if (capitalizeNext) {
                result.append(Character.toUpperCase(c));
                capitalizeNext = false;
            } else {
                result.append(Character.toLowerCase(c));
            }
        }

        return result.toString();
    }

    /**
     * Abbreviate string to max length with custom suffix
     */
    @NonNull
    public static String abbreviate(@Nullable String str, int maxLength, @NonNull String suffix) {
        if (ValidationHelper.isEmpty(str)) return "";
        if (str.length() <= maxLength) return str;
        if (maxLength <= suffix.length()) return suffix.substring(0, maxLength);

        return str.substring(0, maxLength - suffix.length()) + suffix;
    }

    /**
     * Escape HTML special characters
     */
    @NonNull
    public static String escapeHtml(@Nullable String str) {
        if (ValidationHelper.isEmpty(str)) return "";

        return str
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    /**
     * Wrap text at specified width
     */
    @NonNull
    public static String wordWrap(@Nullable String str, int width) {
        if (ValidationHelper.isEmpty(str) || width <= 0) return str != null ? str : "";

        StringBuilder result = new StringBuilder();
        int lineLength = 0;

        String[] words = str.split("\\s+");
        for (String word : words) {
            if (lineLength + word.length() > width) {
                result.append("\n");
                lineLength = 0;
            } else if (lineLength > 0) {
                result.append(" ");
                lineLength++;
            }
            result.append(word);
            lineLength += word.length();
        }

        return result.toString();
    }

    /**
     * Generate random alphanumeric string
     */
    @NonNull
    public static String randomAlphanumeric(int length) {
        if (length <= 0) return "";

        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder sb = new StringBuilder(length);
        java.util.Random random = new java.util.Random();

        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }

        return sb.toString();
    }

    /**
     * Mask sensitive data (show only last N characters)
     */
    @NonNull
    public static String maskSensitive(@Nullable String str, int visibleChars, char maskChar) {
        if (ValidationHelper.isEmpty(str)) return "";
        if (str.length() <= visibleChars) return str;

        int maskLength = str.length() - visibleChars;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < maskLength; i++) {
            sb.append(maskChar);
        }
        sb.append(str.substring(maskLength));
        return sb.toString();
    }
}
