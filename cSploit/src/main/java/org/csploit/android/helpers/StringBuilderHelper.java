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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with cSploit.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.csploit.android.helpers;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.Collection;
import java.util.Iterator;

/**
 * Helper class for efficient string building operations.
 * Provides utilities for common string manipulation tasks using StringBuilder
 * to avoid inefficient string concatenation patterns.
 *
 * This addresses performance issues with string concatenation in loops:
 * String result = "";
 * for (item : items) result += item; // BAD - O(n²) complexity
 */
public final class StringBuilderHelper {

    private static final String DEFAULT_SEPARATOR = ", ";
    private static final String DEFAULT_LINE_SEPARATOR = "\n";

    /**
     * Join items with a separator.
     *
     * @param items Collection of items
     * @param separator The separator string
     * @param <T> Item type
     * @return Joined string
     */
    @NonNull
    public static <T> String join(@Nullable Collection<T> items, @NonNull String separator) {
        if (items == null || items.isEmpty()) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        Iterator<T> iterator = items.iterator();

        if (iterator.hasNext()) {
            sb.append(iterator.next());
        }

        while (iterator.hasNext()) {
            sb.append(separator);
            sb.append(iterator.next());
        }

        return sb.toString();
    }

    /**
     * Join items with a comma separator.
     *
     * @param items Collection of items
     * @param <T> Item type
     * @return Comma-separated string
     */
    @NonNull
    public static <T> String joinWithComma(@Nullable Collection<T> items) {
        return join(items, DEFAULT_SEPARATOR);
    }

    /**
     * Join items with newline separator.
     *
     * @param items Collection of items
     * @param <T> Item type
     * @return Newline-separated string
     */
    @NonNull
    public static <T> String joinWithNewline(@Nullable Collection<T> items) {
        return join(items, DEFAULT_LINE_SEPARATOR);
    }

    /**
     * Join array items with a separator.
     *
     * @param items Array of items
     * @param separator The separator string
     * @param <T> Item type
     * @return Joined string
     */
    @NonNull
    public static <T> String join(@Nullable T[] items, @NonNull String separator) {
        if (items == null || items.length == 0) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        sb.append(items[0]);

        for (int i = 1; i < items.length; i++) {
            sb.append(separator);
            sb.append(items[i]);
        }

        return sb.toString();
    }

    /**
     * Build a string from multiple parts.
     *
     * @param parts The parts to concatenate
     * @return Concatenated string
     */
    @NonNull
    public static String concat(@NonNull Object... parts) {
        StringBuilder sb = new StringBuilder();
        for (Object part : parts) {
            if (part != null) {
                sb.append(part);
            }
        }
        return sb.toString();
    }

    /**
     * Build a string with separator between parts.
     *
     * @param separator The separator
     * @param parts The parts to join
     * @return Joined string
     */
    @NonNull
    public static String concatWithSeparator(@NonNull String separator, @NonNull Object... parts) {
        if (parts.length == 0) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        boolean first = true;

        for (Object part : parts) {
            if (part != null) {
                if (!first) {
                    sb.append(separator);
                }
                sb.append(part);
                first = false;
            }
        }

        return sb.toString();
    }

    /**
     * Repeat a string n times.
     *
     * @param str The string to repeat
     * @param times Number of times to repeat
     * @return Repeated string
     */
    @NonNull
    public static String repeat(@NonNull String str, int times) {
        if (times <= 0) {
            return "";
        }
        if (times == 1) {
            return str;
        }

        StringBuilder sb = new StringBuilder(str.length() * times);
        for (int i = 0; i < times; i++) {
            sb.append(str);
        }
        return sb.toString();
    }

    /**
     * Repeat a character n times.
     *
     * @param c The character to repeat
     * @param times Number of times to repeat
     * @return String of repeated characters
     */
    @NonNull
    public static String repeat(char c, int times) {
        if (times <= 0) {
            return "";
        }

        StringBuilder sb = new StringBuilder(times);
        for (int i = 0; i < times; i++) {
            sb.append(c);
        }
        return sb.toString();
    }

    /**
     * Pad a string on the left to reach a minimum length.
     *
     * @param str The string to pad
     * @param minLength Minimum length
     * @param padChar Character to pad with
     * @return Padded string
     */
    @NonNull
    public static String padLeft(@Nullable String str, int minLength, char padChar) {
        if (str == null) {
            str = "";
        }
        if (str.length() >= minLength) {
            return str;
        }

        StringBuilder sb = new StringBuilder(minLength);
        for (int i = str.length(); i < minLength; i++) {
            sb.append(padChar);
        }
        sb.append(str);
        return sb.toString();
    }

    /**
     * Pad a string on the right to reach a minimum length.
     *
     * @param str The string to pad
     * @param minLength Minimum length
     * @param padChar Character to pad with
     * @return Padded string
     */
    @NonNull
    public static String padRight(@Nullable String str, int minLength, char padChar) {
        if (str == null) {
            str = "";
        }
        if (str.length() >= minLength) {
            return str;
        }

        StringBuilder sb = new StringBuilder(minLength);
        sb.append(str);
        for (int i = str.length(); i < minLength; i++) {
            sb.append(padChar);
        }
        return sb.toString();
    }

    /**
     * Center a string to reach a minimum length.
     *
     * @param str The string to center
     * @param minLength Minimum length
     * @param padChar Character to pad with
     * @return Centered string
     */
    @NonNull
    public static String center(@Nullable String str, int minLength, char padChar) {
        if (str == null) {
            str = "";
        }
        if (str.length() >= minLength) {
            return str;
        }

        int totalPadding = minLength - str.length();
        int leftPadding = totalPadding / 2;
        int rightPadding = totalPadding - leftPadding;

        StringBuilder sb = new StringBuilder(minLength);
        for (int i = 0; i < leftPadding; i++) {
            sb.append(padChar);
        }
        sb.append(str);
        for (int i = 0; i < rightPadding; i++) {
            sb.append(padChar);
        }
        return sb.toString();
    }

    /**
     * Format a key-value pair for logging or display.
     *
     * @param key The key
     * @param value The value
     * @return Formatted string like "key=value"
     */
    @NonNull
    public static String keyValue(@NonNull String key, @Nullable Object value) {
        StringBuilder sb = new StringBuilder();
        sb.append(key);
        sb.append("=");
        sb.append(value);
        return sb.toString();
    }

    /**
     * Format multiple key-value pairs for logging.
     *
     * @param pairs Key-value pairs (must be even number)
     * @return Formatted string like "key1=value1, key2=value2"
     */
    @NonNull
    public static String keyValues(@NonNull Object... pairs) {
        if (pairs.length == 0 || pairs.length % 2 != 0) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < pairs.length; i += 2) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(pairs[i]);
            sb.append("=");
            sb.append(pairs[i + 1]);
        }
        return sb.toString();
    }

    /**
     * Wrap a string with prefix and suffix.
     *
     * @param str The string to wrap
     * @param prefix Prefix to add
     * @param suffix Suffix to add
     * @return Wrapped string
     */
    @NonNull
    public static String wrap(@Nullable String str, @NonNull String prefix, @NonNull String suffix) {
        StringBuilder sb = new StringBuilder();
        sb.append(prefix);
        if (str != null) {
            sb.append(str);
        }
        sb.append(suffix);
        return sb.toString();
    }

    /**
     * Wrap a string in brackets.
     *
     * @param str The string to wrap
     * @return String wrapped in []
     */
    @NonNull
    public static String bracket(@Nullable String str) {
        return wrap(str, "[", "]");
    }

    /**
     * Wrap a string in parentheses.
     *
     * @param str The string to wrap
     * @return String wrapped in ()
     */
    @NonNull
    public static String parentheses(@Nullable String str) {
        return wrap(str, "(", ")");
    }

    /**
     * Wrap a string in quotes.
     *
     * @param str The string to wrap
     * @return String wrapped in ""
     */
    @NonNull
    public static String quote(@Nullable String str) {
        return wrap(str, "\"", "\"");
    }

    /**
     * Truncate a string to max length, adding ellipsis if needed.
     *
     * @param str The string to truncate
     * @param maxLength Maximum length (including ellipsis)
     * @return Truncated string
     */
    @NonNull
    public static String truncate(@Nullable String str, int maxLength) {
        if (str == null || str.length() <= maxLength) {
            return str != null ? str : "";
        }
        if (maxLength <= 3) {
            return str.substring(0, maxLength);
        }
        return str.substring(0, maxLength - 3) + "...";
    }

    /**
     * Create a line of repeated characters (useful for dividers).
     *
     * @param c The character
     * @param length Length of the line
     * @return Line string
     */
    @NonNull
    public static String line(char c, int length) {
        return repeat(c, length);
    }

    /**
     * Create a dashed line divider.
     *
     * @param length Length of the line
     * @return Dashed line
     */
    @NonNull
    public static String dashedLine(int length) {
        return line('-', length);
    }

    /**
     * Format bytes as human-readable string.
     *
     * @param bytes Number of bytes
     * @return Human-readable string (e.g., "1.5 MB")
     */
    @NonNull
    public static String formatBytes(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        }

        String[] units = {"KB", "MB", "GB", "TB"};
        double value = bytes;
        int unitIndex = -1;

        while (value >= 1024 && unitIndex < units.length - 1) {
            value /= 1024;
            unitIndex++;
        }

        return String.format("%.1f %s", value, units[unitIndex]);
    }

    /**
     * Format duration in milliseconds to human-readable string.
     *
     * @param millis Duration in milliseconds
     * @return Human-readable string (e.g., "1h 23m 45s")
     */
    @NonNull
    public static String formatDuration(long millis) {
        if (millis < 1000) {
            return millis + "ms";
        }

        long seconds = millis / 1000;
        long minutes = seconds / 60;
        long hours = minutes / 60;
        long days = hours / 24;

        seconds %= 60;
        minutes %= 60;
        hours %= 24;

        StringBuilder sb = new StringBuilder();
        if (days > 0) {
            sb.append(days).append("d ");
        }
        if (hours > 0) {
            sb.append(hours).append("h ");
        }
        if (minutes > 0) {
            sb.append(minutes).append("m ");
        }
        if (seconds > 0 || sb.length() == 0) {
            sb.append(seconds).append("s");
        }

        return sb.toString().trim();
    }

    private StringBuilderHelper() {
        // Prevent instantiation
    }
}
