package org.csploit.android.helpers;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.regex.Pattern;

/**
 * Utility class for sanitizing user input to prevent injection attacks.
 */
public class InputSanitizer {

    private static final Pattern SHELL_DANGEROUS = Pattern.compile("[;|`$&<>(){}\\\\\"'\\*\\?\\[\\]#!]|\\$\\(|\\$\\{");
    private static final Pattern PATH_TRAVERSAL = Pattern.compile("(\\.\\.|\\.\\./)");
    private static final Pattern HOSTNAME_SAFE = Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9.\\-]*$");
    private static final Pattern ALPHANUMERIC_SAFE = Pattern.compile("^[a-zA-Z0-9_\\-.]+$");

    private InputSanitizer() {}

    // ==================== Shell ====================

    /**
     * Remove dangerous shell characters from the input, keeping only safe substrings.
     * Splits at dangerous characters and returns the first safe token.
     */
    public static String sanitizeForShell(String input) {
        if (input == null || input.isEmpty()) return "";
        // Split at dangerous characters; return the first segment trimmed
        String[] parts = input.split("[;|`$&<>(){}\"'\\\\]|\\$\\(|\\$\\{");
        return parts.length > 0 ? parts[0].trim() : "";
    }

    /**
     * Escape input for use inside single-quoted shell arguments.
     * Replaces single quotes with '"'"' (end quote, literal quote, restart quote).
     */
    public static String escapeForShell(String input) {
        if (input == null) return "";
        return input.replace("'", "'\"'\"'");
    }

    /** Return true if the input contains shell-dangerous characters. */
    public static boolean containsShellDangerousChars(String input) {
        if (input == null || input.isEmpty()) return false;
        return input.matches(".*[;|`&<>(){}\"'\\\\].*") ||
               input.contains("$(") || input.contains("${");
    }

    // ==================== File path ====================

    /** Remove path traversal sequences, keeping the resolved absolute path. */
    public static String sanitizeFilePath(String input) {
        if (input == null || input.isEmpty()) return "";
        // Remove all occurrences of ../ and ../
        String result = input;
        String prev;
        do {
            prev = result;
            result = result.replace("../", "/").replace("..\\", "/")
                           .replace("..", "");
        } while (!result.equals(prev));
        // Normalise double slashes
        result = result.replaceAll("/+", "/");
        return result;
    }

    /** Return true if the path contains traversal sequences. */
    public static boolean containsPathTraversal(String input) {
        if (input == null) return false;
        return input.contains("..") && (input.contains("../") || input.contains("..\\") ||
               input.endsWith("..") || input.contains("/../") || input.contains("/.."));
    }

    /**
     * Extract just the filename from a path, replacing unsafe characters with '_'.
     * Returns empty string for null input.
     */
    public static String extractSafeFilename(String input) {
        if (input == null) return "";
        // Get last path component (works for both / and \)
        String name = input.replaceAll(".*[/\\\\]", "");
        // Remove leading dots (hidden files / traversal)
        name = name.replaceAll("^\\.+", "");
        // Replace unsafe characters with _
        name = name.replaceAll("[^a-zA-Z0-9._\\-]", "_");
        return name;
    }

    // ==================== SQL ====================

    /**
     * Basic SQL sanitization: remove everything from the first statement terminator
     * onward, then escape single quotes by doubling them.
     */
    public static String sanitizeForSql(String input) {
        if (input == null) return "";
        // Take only the first SQL statement (split at semicolon)
        String result = input.split(";")[0].trim();
        // Escape single quotes by doubling them
        result = result.replace("'", "''");
        return result;
    }

    // ==================== Network ====================

    /** Return the hostname if it matches safe pattern, else empty string. */
    public static String sanitizeHostname(String input) {
        if (input == null || input.isEmpty()) return "";
        if (HOSTNAME_SAFE.matcher(input).matches()) return input;
        return "";
    }

    /** Return the port string if it is a valid port (1–65535), else empty string. */
    public static String sanitizePort(String input) {
        if (input == null || input.isEmpty()) return "";
        try {
            int port = Integer.parseInt(input.trim());
            if (port >= 1 && port <= 65535) return String.valueOf(port);
        } catch (NumberFormatException ignored) {}
        return "";
    }

    // ==================== URL ====================

    /** URL-encode the parameter value (percent-encoding). */
    public static String sanitizeUrlParam(String input) {
        if (input == null || input.isEmpty()) return "";
        try {
            return URLEncoder.encode(input, "UTF-8").replace("+", "%20");
        } catch (UnsupportedEncodingException e) {
            return "";
        }
    }

    // ==================== HTML ====================

    /**
     * Escape HTML special characters to prevent XSS.
     */
    public static String sanitizeHtml(String input) {
        if (input == null) return "";
        return input
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;")
                .replace("/", "&#x2F;");
    }

    // ==================== Validation ====================

    /** Return true if input contains only letters, digits, underscores, hyphens, and dots. */
    public static boolean isSafeAlphanumeric(String input) {
        if (input == null || input.isEmpty()) return false;
        return ALPHANUMERIC_SAFE.matcher(input).matches();
    }

    // ==================== Control characters ====================

    /**
     * Strip control characters (ASCII 0x00–0x08, 0x0B–0x0C, 0x0E–0x1F) from the input.
     * Newline (0x0A) and carriage return (0x0D) are preserved.
     */
    public static String stripControlChars(String input) {
        if (input == null) return "";
        return input.replaceAll("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F]", "");
    }

    // ==================== Length ====================

    /** Return the input truncated to maxLength characters, or empty if null. */
    public static String limitLength(String input, int maxLength) {
        if (input == null) return "";
        if (maxLength <= 0) return "";
        return input.length() <= maxLength ? input : input.substring(0, maxLength);
    }
}
