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
import android.os.Build;
import android.provider.Settings;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.File;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.regex.Pattern;

/**
 * SecurityUtils - Security utilities for cSploit.
 *
 * Provides:
 * - Input validation and sanitization
 * - Secure random generation
 * - Root detection verification
 * - Hash utilities
 * - Security checks
 */
public final class SecurityUtils {

    private static final String TAG = "SecurityUtils";
    
    // Pattern for valid IP addresses
    private static final Pattern IP_PATTERN = Pattern.compile(
            "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
    
    // Pattern for valid MAC addresses
    private static final Pattern MAC_PATTERN = Pattern.compile(
            "^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$");
    
    // Pattern for valid hostnames
    private static final Pattern HOSTNAME_PATTERN = Pattern.compile(
            "^[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?)*$");

    // Pattern for valid port numbers
    private static final Pattern PORT_PATTERN = Pattern.compile("^(\\d{1,5})$");
    
    // Dangerous shell characters
    private static final String SHELL_DANGEROUS_CHARS = "|;&$`\\\"'<>(){}[]!#~*?";

    private SecurityUtils() {}

    // ==================== Input Validation ====================

    /**
     * Validate IP address format.
     */
    public static boolean isValidIpAddress(@Nullable String ip) {
        return ip != null && IP_PATTERN.matcher(ip).matches();
    }

    /**
     * Validate MAC address format.
     */
    public static boolean isValidMacAddress(@Nullable String mac) {
        return mac != null && MAC_PATTERN.matcher(mac).matches();
    }

    /**
     * Validate hostname format.
     */
    public static boolean isValidHostname(@Nullable String hostname) {
        return hostname != null && hostname.length() <= 253 && HOSTNAME_PATTERN.matcher(hostname).matches();
    }

    /**
     * Validate port number.
     */
    public static boolean isValidPort(@Nullable String port) {
        if (port == null || !PORT_PATTERN.matcher(port).matches()) {
            return false;
        }
        try {
            int portNum = Integer.parseInt(port);
            return portNum > 0 && portNum <= 65535;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * Validate port number.
     */
    public static boolean isValidPort(int port) {
        return port > 0 && port <= 65535;
    }

    // ==================== Input Sanitization ====================

    /**
     * Sanitize input for shell command use.
     * Removes or escapes dangerous characters.
     */
    @NonNull
    public static String sanitizeShellInput(@Nullable String input) {
        if (input == null || input.isEmpty()) {
            return "";
        }
        
        StringBuilder sanitized = new StringBuilder(input.length());
        for (char c : input.toCharArray()) {
            if (SHELL_DANGEROUS_CHARS.indexOf(c) == -1) {
                sanitized.append(c);
            }
        }
        return sanitized.toString();
    }

    /**
     * Escape shell special characters.
     */
    @NonNull
    public static String escapeShellArg(@Nullable String input) {
        if (input == null || input.isEmpty()) {
            return "''";
        }
        
        // If no special chars, return as is
        boolean needsEscape = false;
        for (char c : input.toCharArray()) {
            if (SHELL_DANGEROUS_CHARS.indexOf(c) != -1 || Character.isWhitespace(c)) {
                needsEscape = true;
                break;
            }
        }
        
        if (!needsEscape) {
            return input;
        }
        
        // Single quote escape: replace ' with '\''
        return "'" + input.replace("'", "'\\''") + "'";
    }

    /**
     * Sanitize filename by removing path separators and special characters.
     */
    @NonNull
    public static String sanitizeFilename(@Nullable String filename) {
        if (filename == null || filename.isEmpty()) {
            return "";
        }
        
        // Remove path separators and null bytes
        String sanitized = filename.replace("/", "")
                                   .replace("\\", "")
                                   .replace("\0", "");
        
        // Remove leading/trailing dots and spaces
        sanitized = sanitized.trim();
        while (sanitized.startsWith(".")) {
            sanitized = sanitized.substring(1);
        }
        
        return sanitized;
    }

    // ==================== Secure Random ====================

    /**
     * Generate secure random bytes.
     */
    @NonNull
    public static byte[] generateSecureBytes(int length) {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }

    /**
     * Generate secure random hex string.
     */
    @NonNull
    public static String generateSecureHex(int byteLength) {
        byte[] bytes = generateSecureBytes(byteLength);
        return bytesToHex(bytes);
    }

    /**
     * Generate secure random alphanumeric string.
     */
    @NonNull
    public static String generateSecureAlphanumeric(int length) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }
        return sb.toString();
    }

    // ==================== Hash Utilities ====================

    /**
     * Calculate SHA-256 hash.
     */
    @Nullable
    public static String sha256(@NonNull String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes("UTF-8"));
            return bytesToHex(hash);
        } catch (Exception e) {
            LoggingHelper.e(TAG, "SHA-256 failed", e);
            return null;
        }
    }

    /**
     * Calculate SHA-256 hash of bytes.
     */
    @Nullable
    public static String sha256(@NonNull byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input);
            return bytesToHex(hash);
        } catch (Exception e) {
            LoggingHelper.e(TAG, "SHA-256 failed", e);
            return null;
        }
    }

    /**
     * Calculate MD5 hash (for checksums, not security).
     */
    @Nullable
    public static String md5(@NonNull String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            byte[] hash = digest.digest(input.getBytes("UTF-8"));
            return bytesToHex(hash);
        } catch (Exception e) {
            LoggingHelper.e(TAG, "MD5 failed", e);
            return null;
        }
    }

    /**
     * Convert bytes to hex string.
     */
    @NonNull
    public static String bytesToHex(@NonNull byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    // ==================== Root Detection ====================

    /**
     * Check if device is rooted.
     */
    public static boolean isDeviceRooted() {
        return checkSuBinary() || checkRootApps() || checkDangerousProps();
    }

    private static boolean checkSuBinary() {
        String[] paths = {
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/system/su",
            "/system/bin/.ext/.su",
            "/system/usr/we-need-root/su-backup",
            "/system/xbin/mu",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/data/local/su"
        };
        
        for (String path : paths) {
            if (new File(path).exists()) {
                return true;
            }
        }
        return false;
    }

    private static boolean checkRootApps() {
        String[] packages = {
            "com.noshufou.android.su",
            "com.thirdparty.superuser",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.zachspong.temprootremovejb",
            "com.ramdroid.appquarantine",
            "com.topjohnwu.magisk"
        };
        
        // Check via build tags
        String buildTags = Build.TAGS;
        if (buildTags != null && buildTags.contains("test-keys")) {
            return true;
        }
        
        return false;
    }

    private static boolean checkDangerousProps() {
        String[] dangerousProps = {
            "ro.debuggable",
            "ro.secure"
        };
        
        try {
            for (String prop : dangerousProps) {
                String value = System.getProperty(prop);
                if ("1".equals(value) && prop.equals("ro.debuggable")) {
                    return true;
                }
                if ("0".equals(value) && prop.equals("ro.secure")) {
                    return true;
                }
            }
        } catch (Exception e) {
            // Ignore
        }
        
        return false;
    }

    // ==================== Security Checks ====================

    /**
     * Check if USB debugging is enabled.
     */
    public static boolean isUsbDebuggingEnabled(@NonNull Context context) {
        try {
            return Settings.Global.getInt(context.getContentResolver(),
                    Settings.Global.ADB_ENABLED, 0) == 1;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Check if device encryption is enabled.
     */
    public static boolean isDeviceEncrypted(@NonNull Context context) {
        try {
            android.app.admin.DevicePolicyManager dpm = 
                    (android.app.admin.DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
            if (dpm != null) {
                int status = dpm.getStorageEncryptionStatus();
                return status == android.app.admin.DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE ||
                       status == android.app.admin.DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY;
            }
        } catch (Exception e) {
            LoggingHelper.e(TAG, "Failed to check encryption status", e);
        }
        return false;
    }

    /**
     * Timing-safe string comparison to prevent timing attacks.
     */
    public static boolean timingSafeEquals(@Nullable String a, @Nullable String b) {
        if (a == null || b == null) {
            return a == b;
        }
        
        if (a.length() != b.length()) {
            return false;
        }
        
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }
}
