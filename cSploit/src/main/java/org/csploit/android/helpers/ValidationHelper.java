package org.csploit.android.helpers;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

/**
 * Validation and input checking utilities for common operations.
 * Provides methods for validating network data, strings, and collections.
 */
public final class ValidationHelper {

    /**
     * Check if a string is null or empty
     */
    public static boolean isEmpty(@Nullable String str) {
        return str == null || str.trim().isEmpty();
    }

    /**
     * Check if a string is valid and not empty
     */
    public static boolean isValid(@Nullable String str) {
        return !isEmpty(str);
    }

    /**
     * Validate IP address format (IPv4)
     */
    public static boolean isValidIPv4(@Nullable String ip) {
        if (isEmpty(ip)) {
            return false;
        }

        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            return false;
        }

        try {
            for (String part : parts) {
                int num = Integer.parseInt(part);
                if (num < 0 || num > 255) {
                    return false;
                }
            }
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * Validate MAC address format
     */
    public static boolean isValidMacAddress(@Nullable String mac) {
        if (isEmpty(mac)) {
            return false;
        }

        // Support both formats: AA:BB:CC:DD:EE:FF and AABBCCDDEEFF
        String cleanMac = mac.replaceAll(":", "").replaceAll("-", "");
        
        if (cleanMac.length() != 12) {
            return false;
        }

        try {
            Long.parseLong(cleanMac, 16);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * Validate port number
     */
    public static boolean isValidPort(int port) {
        return port > 0 && port <= 65535;
    }

    /**
     * Validate port number from string
     */
    public static boolean isValidPort(@Nullable String port) {
        if (isEmpty(port)) {
            return false;
        }

        try {
            return isValidPort(Integer.parseInt(port));
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * Validate URL format
     */
    public static boolean isValidUrl(@Nullable String url) {
        if (isEmpty(url)) {
            return false;
        }

        try {
            new java.net.URL(url);
            return true;
        } catch (java.net.MalformedURLException e) {
            return false;
        }
    }

    /**
     * Validate email format (basic)
     */
    public static boolean isValidEmail(@Nullable String email) {
        if (isEmpty(email)) {
            return false;
        }

        String emailPattern = "[a-zA-Z0-9._%-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}";
        return email.matches(emailPattern);
    }

    /**
     * Check if a collection is null or empty
     */
    public static boolean isEmpty(@Nullable java.util.Collection<?> collection) {
        return collection == null || collection.isEmpty();
    }

    /**
     * Check if an array is null or empty
     */
    public static boolean isEmpty(@Nullable Object[] array) {
        return array == null || array.length == 0;
    }

    /**
     * Validate hostname (DNS)
     */
    public static boolean isValidHostname(@Nullable String hostname) {
        if (isEmpty(hostname)) {
            return false;
        }

        // Check length
        if (hostname.length() > 253) {
            return false;
        }

        // Check format
        String hostnamePattern = 
            "^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])(\\." +
            "([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]))*$";
        
        return hostname.matches(hostnamePattern);
    }

    /**
     * Validate that a string matches a pattern
     */
    public static boolean matches(@Nullable String str, @NonNull String pattern) {
        if (isEmpty(str)) {
            return false;
        }

        try {
            return str.matches(pattern);
        } catch (java.util.regex.PatternSyntaxException e) {
            return false;
        }
    }

    /**
     * Ensure non-null with default value
     */
    @NonNull
    public static <T> T getOrDefault(@Nullable T value, @NonNull T defaultValue) {
        return value != null ? value : defaultValue;
    }

    /**
     * Check if string is numeric (digits only)
     */
    public static boolean isNumeric(@Nullable String str) {
        if (isEmpty(str)) {
            return false;
        }

        return str.matches("\\d+");
    }

    /**
     * Check if string is alphanumeric
     */
    public static boolean isAlphanumeric(@Nullable String str) {
        if (isEmpty(str)) {
            return false;
        }

        return str.matches("[a-zA-Z0-9]+");
    }
}
