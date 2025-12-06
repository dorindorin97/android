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

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.regex.Pattern;

/**
 * InputSanitizer - Security-focused input validation and sanitization.
 *
 * Provides methods to sanitize user input to prevent:
 * - Command injection
 * - Path traversal attacks
 * - SQL injection (basic)
 * - XSS (basic)
 *
 * Usage:
 * {@code
 * String safeCommand = InputSanitizer.sanitizeForShell(userInput);
 * String safePath = InputSanitizer.sanitizeFilePath(userInput);
 * }
 */
public final class InputSanitizer {

    private static final String TAG = "InputSanitizer";

    // Dangerous shell characters
    private static final Pattern SHELL_DANGEROUS = Pattern.compile("[;&|`$(){}\\[\\]<>!\\\\\"'\\n\\r]");

    // Path traversal patterns
    private static final Pattern PATH_TRAVERSAL = Pattern.compile("(\\.\\./|\\.\\.\\\\|\\.\\.%2f|\\.\\.%5c)", Pattern.CASE_INSENSITIVE);

    // SQL injection patterns (basic)
    private static final Pattern SQL_INJECTION = Pattern.compile("('|--|;|/\\*|\\*/|xp_|@@|char\\(|nchar\\()", Pattern.CASE_INSENSITIVE);

    // Valid hostname pattern
    private static final Pattern VALID_HOSTNAME = Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$");

    // Valid alphanumeric with common safe chars
    private static final Pattern ALPHANUMERIC_PLUS = Pattern.compile("^[a-zA-Z0-9._-]+$");

    private InputSanitizer() {}

    /**
     * Sanitize input for safe use in shell commands.
     * Removes or escapes dangerous shell metacharacters.
     *
     * @param input the user input to sanitize
     * @return sanitized string safe for shell use
     */
    @NonNull
    public static String sanitizeForShell(@Nullable String input) {
        if (input == null || input.isEmpty()) {
            return "";
        }
        // Remove all dangerous characters
        return SHELL_DANGEROUS.matcher(input).replaceAll("");
    }

    /**
     * Escape input for safe use in shell commands (quote-wrapped).
     * Escapes special characters instead of removing them.
     *
     * @param input the user input to escape
     * @return escaped string that can be safely wrapped in single quotes
     */
    @NonNull
    public static String escapeForShell(@Nullable String input) {
        if (input == null || input.isEmpty()) {
            return "";
        }
        // Escape single quotes by ending quote, adding escaped quote, starting new quote
        return input.replace("'", "'\"'\"'");
    }

    /**
     * Sanitize file path to prevent path traversal attacks.
     *
     * @param path the file path to sanitize
     * @return sanitized path without traversal sequences
     */
    @NonNull
    public static String sanitizeFilePath(@Nullable String path) {
        if (path == null || path.isEmpty()) {
            return "";
        }
        // Remove path traversal patterns
        String sanitized = PATH_TRAVERSAL.matcher(path).replaceAll("");
        // Also remove any remaining ".." sequences
        while (sanitized.contains("..")) {
            sanitized = sanitized.replace("..", "");
        }
        // Normalize slashes
        sanitized = sanitized.replace("\\", "/");
        // Remove double slashes
        while (sanitized.contains("//")) {
            sanitized = sanitized.replace("//", "/");
        }
        return sanitized;
    }

    /**
     * Validate and extract a safe filename from a path.
     *
     * @param path the path or filename
     * @return just the filename without path components, or empty if invalid
     */
    @NonNull
    public static String extractSafeFilename(@Nullable String path) {
        if (path == null || path.isEmpty()) {
            return "";
        }
        // Get just the filename part
        String filename = path;
        int lastSlash = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'));
        if (lastSlash >= 0 && lastSlash < path.length() - 1) {
            filename = path.substring(lastSlash + 1);
        }
        // Remove any path traversal
        filename = filename.replace("..", "");
        // Only allow safe characters in filename
        if (!ALPHANUMERIC_PLUS.matcher(filename).matches()) {
            // Remove unsafe characters
            filename = filename.replaceAll("[^a-zA-Z0-9._-]", "_");
        }
        return filename;
    }

    /**
     * Sanitize input for SQL (basic protection).
     * Note: Prefer prepared statements over string sanitization.
     *
     * @param input the input to sanitize
     * @return sanitized string
     */
    @NonNull
    public static String sanitizeForSql(@Nullable String input) {
        if (input == null || input.isEmpty()) {
            return "";
        }
        // Escape single quotes
        String sanitized = input.replace("'", "''");
        // Remove SQL injection patterns
        sanitized = SQL_INJECTION.matcher(sanitized).replaceAll("");
        return sanitized;
    }

    /**
     * Sanitize hostname/IP for network operations.
     *
     * @param host the hostname or IP address
     * @return sanitized hostname, or empty if invalid
     */
    @NonNull
    public static String sanitizeHostname(@Nullable String host) {
        if (host == null || host.isEmpty()) {
            return "";
        }
        host = host.trim().toLowerCase();
        // Remove any shell dangerous chars first
        host = SHELL_DANGEROUS.matcher(host).replaceAll("");
        // Validate format
        if (NetworkHelper.isValidIP(host) || VALID_HOSTNAME.matcher(host).matches()) {
            return host;
        }
        return "";
    }

    /**
     * Sanitize port number string.
     *
     * @param portStr the port string
     * @return valid port number as string, or empty if invalid
     */
    @NonNull
    public static String sanitizePort(@Nullable String portStr) {
        if (portStr == null || portStr.isEmpty()) {
            return "";
        }
        try {
            int port = Integer.parseInt(portStr.trim());
            if (NetworkHelper.isValidPort(port)) {
                return String.valueOf(port);
            }
        } catch (NumberFormatException e) {
            // Invalid port
        }
        return "";
    }

    /**
     * Sanitize URL parameter value.
     *
     * @param value the parameter value
     * @return URL-safe sanitized value
     */
    @NonNull
    public static String sanitizeUrlParam(@Nullable String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        try {
            return java.net.URLEncoder.encode(value, "UTF-8");
        } catch (Exception e) {
            // Fallback: remove potentially dangerous chars
            return value.replaceAll("[^a-zA-Z0-9._~-]", "");
        }
    }

    /**
     * Sanitize HTML content to prevent XSS (basic).
     *
     * @param html the HTML content
     * @return sanitized content with HTML entities escaped
     */
    @NonNull
    public static String sanitizeHtml(@Nullable String html) {
        if (html == null || html.isEmpty()) {
            return "";
        }
        return html
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;")
                .replace("/", "&#x2F;");
    }

    /**
     * Check if input contains potentially dangerous characters for shell.
     *
     * @param input the input to check
     * @return true if input contains dangerous characters
     */
    public static boolean containsShellDangerousChars(@Nullable String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }
        return SHELL_DANGEROUS.matcher(input).find();
    }

    /**
     * Check if path contains traversal attempts.
     *
     * @param path the path to check
     * @return true if path contains traversal patterns
     */
    public static boolean containsPathTraversal(@Nullable String path) {
        if (path == null || path.isEmpty()) {
            return false;
        }
        return PATH_TRAVERSAL.matcher(path).find() || path.contains("..");
    }

    /**
     * Validate if input is safe alphanumeric (letters, digits, underscore, dash, dot).
     *
     * @param input the input to validate
     * @return true if input contains only safe characters
     */
    public static boolean isSafeAlphanumeric(@Nullable String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }
        return ALPHANUMERIC_PLUS.matcher(input).matches();
    }

    /**
     * Strip null bytes and control characters from input.
     *
     * @param input the input to clean
     * @return input without null bytes and control chars
     */
    @NonNull
    public static String stripControlChars(@Nullable String input) {
        if (input == null || input.isEmpty()) {
            return "";
        }
        // Remove null bytes and control characters (except newline, tab)
        return input.replaceAll("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]", "");
    }

    /**
     * Limit string length to prevent buffer overflow attacks.
     *
     * @param input the input string
     * @param maxLength maximum allowed length
     * @return truncated string if needed
     */
    @NonNull
    public static String limitLength(@Nullable String input, int maxLength) {
        if (input == null || input.isEmpty()) {
            return "";
        }
        if (maxLength <= 0) {
            return "";
        }
        if (input.length() <= maxLength) {
            return input;
        }
        return input.substring(0, maxLength);
    }
}
