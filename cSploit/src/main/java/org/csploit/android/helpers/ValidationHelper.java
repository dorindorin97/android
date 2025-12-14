package org.csploit.android.helpers;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

/**
 * Validation and input checking utilities for common operations.
 * Provides methods for validating network data, strings, and collections.
 *
 * Note: For specialized network validation (IPv4, IPv6, MAC), this class
 * delegates to IpAddressHelper, IPv6Helper, and MacAddressHelper respectively.
 * Those helpers provide additional protocol-specific operations beyond validation.
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
     * Validate IP address format (IPv4).
     * Delegates to IpAddressHelper for implementation.
     * @see IpAddressHelper#isValidIpv4(String)
     */
    public static boolean isValidIPv4(@Nullable String ip) {
        return IpAddressHelper.isValidIpv4(ip);
    }

    /**
     * Validate MAC address format.
     * Delegates to MacAddressHelper for implementation.
     * @see MacAddressHelper#isValidMac(String)
     */
    public static boolean isValidMacAddress(@Nullable String mac) {
        return MacAddressHelper.isValidMac(mac);
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

    /**
     * Validate IPv6 address format.
     * Delegates to IPv6Helper for implementation.
     * @see IPv6Helper#isValidIPv6(String)
     */
    public static boolean isValidIPv6(@Nullable String ip) {
        return IPv6Helper.isValidIPv6(ip);
    }

    /**
     * Validate IP address (both IPv4 and IPv6)
     */
    public static boolean isValidIP(@Nullable String ip) {
        return IpAddressHelper.isValidIpv4(ip) || IPv6Helper.isValidIPv6(ip);
    }

    /**
     * Validate CIDR notation (e.g., "192.168.1.0/24")
     */
    public static boolean isValidCIDR(@Nullable String cidr) {
        if (isEmpty(cidr)) {
            return false;
        }

        String[] parts = cidr.split("/");
        if (parts.length != 2) {
            return false;
        }

        if (!isValidIPv4(parts[0])) {
            return false;
        }

        try {
            int prefix = Integer.parseInt(parts[1]);
            return prefix >= 0 && prefix <= 32;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * Validate port range (e.g., "1-1024" or "80,443,8080")
     */
    public static boolean isValidPortRange(@Nullable String portRange) {
        if (isEmpty(portRange)) {
            return false;
        }

        // Check for range format (1-1024)
        if (portRange.contains("-")) {
            String[] parts = portRange.split("-");
            if (parts.length != 2) {
                return false;
            }
            try {
                int start = Integer.parseInt(parts[0].trim());
                int end = Integer.parseInt(parts[1].trim());
                return isValidPort(start) && isValidPort(end) && start <= end;
            } catch (NumberFormatException e) {
                return false;
            }
        }

        // Check for comma-separated list (80,443,8080)
        if (portRange.contains(",")) {
            String[] ports = portRange.split(",");
            for (String port : ports) {
                if (!isValidPort(port.trim())) {
                    return false;
                }
            }
            return true;
        }

        // Single port
        return isValidPort(portRange);
    }

    /**
     * Check if a number is in a given range
     */
    public static boolean isInRange(int value, int min, int max) {
        return value >= min && value <= max;
    }

    /**
     * Check if a long value is in a given range
     */
    public static boolean isInRange(long value, long min, long max) {
        return value >= min && value <= max;
    }

    /**
     * Check if a string length is in a given range
     */
    public static boolean isLengthInRange(@Nullable String str, int minLength, int maxLength) {
        if (str == null) {
            return minLength == 0;
        }
        int length = str.length();
        return length >= minLength && length <= maxLength;
    }

    /**
     * Validate that string contains only hexadecimal characters
     */
    public static boolean isHexadecimal(@Nullable String str) {
        if (isEmpty(str)) {
            return false;
        }
        return str.matches("[0-9a-fA-F]+");
    }

    /**
     * Check if string is a valid integer
     */
    public static boolean isInteger(@Nullable String str) {
        if (isEmpty(str)) {
            return false;
        }
        try {
            Integer.parseInt(str);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * Check if string is a valid long
     */
    public static boolean isLong(@Nullable String str) {
        if (isEmpty(str)) {
            return false;
        }
        try {
            Long.parseLong(str);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * Check if string is a valid double/float
     */
    public static boolean isDecimal(@Nullable String str) {
        if (isEmpty(str)) {
            return false;
        }
        try {
            Double.parseDouble(str);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * Check if a byte array is null or empty
     */
    public static boolean isEmpty(@Nullable byte[] array) {
        return array == null || array.length == 0;
    }

    /**
     * Check if a map is null or empty
     */
    public static boolean isEmpty(@Nullable java.util.Map<?, ?> map) {
        return map == null || map.isEmpty();
    }

    /**
     * Validate that all required fields in a map are present
     */
    public static boolean hasRequiredFields(@Nullable java.util.Map<String, ?> map, @NonNull String... requiredKeys) {
        if (map == null) {
            return false;
        }
        for (String key : requiredKeys) {
            if (!map.containsKey(key) || map.get(key) == null) {
                return false;
            }
        }
        return true;
    }

    /**
     * Require non-null value or throw IllegalArgumentException
     */
    @NonNull
    public static <T> T requireNonNull(@Nullable T value, @NonNull String message) {
        if (value == null) {
            throw new IllegalArgumentException(message);
        }
        return value;
    }

    /**
     * Require non-empty string or throw IllegalArgumentException
     */
    @NonNull
    public static String requireNonEmpty(@Nullable String value, @NonNull String message) {
        if (isEmpty(value)) {
            throw new IllegalArgumentException(message);
        }
        return value;
    }

    private ValidationHelper() {
        // Prevent instantiation
    }
}
