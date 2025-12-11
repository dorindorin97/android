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
import android.content.SharedPreferences;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.preference.PreferenceManager;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * ConfigHelper - Centralized configuration and settings management.
 * 
 * Provides:
 * - Type-safe preference access
 * - Default value management
 * - Configuration validation
 * - Settings migration support
 * - Configuration export/import
 * 
 * Usage:
 * {@code
 * // Initialize
 * ConfigHelper config = ConfigHelper.getInstance(context);
 * 
 * // Get settings with defaults
 * int scanTimeout = config.getScanTimeout();
 * boolean autoScan = config.isAutoScanEnabled();
 * 
 * // Set settings
 * config.setScanTimeout(5000);
 * }
 */
public final class ConfigHelper {
    
    public static final String TAG = "ConfigHelper";
    
    // Preference keys
    public static final String KEY_SCAN_TIMEOUT = "PREF_SCAN_TIMEOUT";
    public static final String KEY_AUTO_PORTSCAN = "PREF_AUTO_PORTSCAN";
    public static final String KEY_DARK_THEME = "PREF_DARK_THEME";
    public static final String KEY_NOTIFICATION_ENABLED = "PREF_NOTIFICATIONS";
    public static final String KEY_VIBRATION_ENABLED = "PREF_VIBRATION";
    public static final String KEY_SOUND_ENABLED = "PREF_SOUND";
    public static final String KEY_WIFI_ONLY = "PREF_WIFI_ONLY";
    public static final String KEY_SHOW_HOSTNAME = "PREF_SHOW_HOSTNAME";
    public static final String KEY_RESOLVE_HOSTNAMES = "PREF_RESOLVE_HOSTNAMES";
    public static final String KEY_CONCURRENT_SCANS = "PREF_CONCURRENT_SCANS";
    public static final String KEY_DEFAULT_PORTS = "PREF_DEFAULT_PORTS";
    public static final String KEY_LAST_NETWORK = "PREF_LAST_NETWORK";
    public static final String KEY_FIRST_RUN = "PREF_FIRST_RUN";
    public static final String KEY_CONFIG_VERSION = "PREF_CONFIG_VERSION";
    public static final String KEY_ANALYTICS_ENABLED = "PREF_ANALYTICS";
    public static final String KEY_CRASH_REPORTING = "PREF_CRASH_REPORTING";
    public static final String KEY_AUTO_UPDATE = "PREF_AUTO_UPDATE";
    public static final String KEY_MSF_ENABLED = "PREF_MSF_ENABLED";
    public static final String KEY_ROOT_GRANTED = "PREF_ROOT_GRANTED";
    
    // Network port constants
    public static final String KEY_HTTP_PROXY_PORT = "PREF_HTTP_PROXY_PORT";
    public static final String KEY_HTTP_SERVER_PORT = "PREF_HTTP_SERVER_PORT";
    public static final String KEY_HTTPS_REDIR_PORT = "PREF_HTTPS_REDIRECTOR_PORT";
    public static final String KEY_MSF_RPC_PORT = "MSF_RPC_PORT";

    // Default network ports
    public static final int DEFAULT_HTTP_PROXY_PORT = 8080;
    public static final int DEFAULT_HTTP_SERVER_PORT = 8081;
    public static final int DEFAULT_HTTPS_REDIR_PORT = 8082;
    public static final int DEFAULT_MSF_RPC_PORT = 55553;

    // System paths
    public static final String IPV4_FORWARD_FILEPATH = "/proc/sys/net/ipv4/ip_forward";

    // Default values
    public static final int DEFAULT_SCAN_TIMEOUT = 3000;
    public static final boolean DEFAULT_AUTO_PORTSCAN = true;
    public static final boolean DEFAULT_DARK_THEME = false;
    public static final boolean DEFAULT_NOTIFICATION_ENABLED = true;
    public static final boolean DEFAULT_VIBRATION_ENABLED = true;
    public static final boolean DEFAULT_SOUND_ENABLED = true;
    public static final boolean DEFAULT_WIFI_ONLY = false;
    public static final boolean DEFAULT_SHOW_HOSTNAME = true;
    public static final boolean DEFAULT_RESOLVE_HOSTNAMES = true;
    public static final int DEFAULT_CONCURRENT_SCANS = 50;
    public static final String DEFAULT_PORTS = "21,22,23,25,53,80,110,139,143,443,445,993,995,3306,3389,8080";
    public static final int CURRENT_CONFIG_VERSION = 1;
    
    private static volatile ConfigHelper instance;
    private final SharedPreferences prefs;
    private final SharedPreferences.Editor editor;
    private final Map<String, Object> cache;
    
    private ConfigHelper(@NonNull Context context) {
        this.prefs = PreferenceManager.getDefaultSharedPreferences(context);
        this.editor = prefs.edit();
        this.cache = new HashMap<>();
        
        // Run migrations if needed
        migrateIfNeeded();
    }
    
    /**
     * Get singleton instance.
     * 
     * @param context Android context
     * @return ConfigHelper instance
     */
    @NonNull
    public static ConfigHelper getInstance(@NonNull Context context) {
        if (instance == null) {
            synchronized (ConfigHelper.class) {
                if (instance == null) {
                    instance = new ConfigHelper(context.getApplicationContext());
                }
            }
        }
        return instance;
    }
    
    /**
     * Run configuration migrations if needed.
     */
    private void migrateIfNeeded() {
        int currentVersion = prefs.getInt(KEY_CONFIG_VERSION, 0);
        
        if (currentVersion < CURRENT_CONFIG_VERSION) {
            LoggingHelper.i(TAG, "Migrating config from v" + currentVersion + " to v" + CURRENT_CONFIG_VERSION);
            
            // Migration logic goes here for future versions
            // Example:
            // if (currentVersion < 1) { migrateToV1(); }
            // if (currentVersion < 2) { migrateToV2(); }
            
            editor.putInt(KEY_CONFIG_VERSION, CURRENT_CONFIG_VERSION);
            editor.apply();
        }
    }
    
    // ==================== Scan Settings ====================
    
    /**
     * Get scan timeout in milliseconds.
     */
    public int getScanTimeout() {
        return prefs.getInt(KEY_SCAN_TIMEOUT, DEFAULT_SCAN_TIMEOUT);
    }
    
    /**
     * Set scan timeout.
     * 
     * @param timeoutMs timeout in milliseconds (100-30000)
     */
    public void setScanTimeout(int timeoutMs) {
        timeoutMs = Math.max(100, Math.min(30000, timeoutMs));
        editor.putInt(KEY_SCAN_TIMEOUT, timeoutMs);
        editor.apply();
    }
    
    /**
     * Check if auto port scan is enabled.
     */
    public boolean isAutoPortScanEnabled() {
        return prefs.getBoolean(KEY_AUTO_PORTSCAN, DEFAULT_AUTO_PORTSCAN);
    }
    
    /**
     * Set auto port scan enabled.
     */
    public void setAutoPortScanEnabled(boolean enabled) {
        editor.putBoolean(KEY_AUTO_PORTSCAN, enabled);
        editor.apply();
    }
    
    /**
     * Get number of concurrent scans.
     */
    public int getConcurrentScans() {
        return prefs.getInt(KEY_CONCURRENT_SCANS, DEFAULT_CONCURRENT_SCANS);
    }
    
    /**
     * Set number of concurrent scans.
     * 
     * @param count number of concurrent scans (1-200)
     */
    public void setConcurrentScans(int count) {
        count = Math.max(1, Math.min(200, count));
        editor.putInt(KEY_CONCURRENT_SCANS, count);
        editor.apply();
    }
    
    /**
     * Get default ports for scanning.
     */
    @NonNull
    public String getDefaultPorts() {
        return prefs.getString(KEY_DEFAULT_PORTS, DEFAULT_PORTS);
    }
    
    /**
     * Get default ports as array.
     */
    @NonNull
    public int[] getDefaultPortsArray() {
        String portsStr = getDefaultPorts();
        String[] parts = portsStr.split(",");
        int[] ports = new int[parts.length];
        
        int idx = 0;
        for (String part : parts) {
            try {
                int port = Integer.parseInt(part.trim());
                if (port > 0 && port <= 65535) {
                    ports[idx++] = port;
                }
            } catch (NumberFormatException e) {
                    LoggingHelper.d(TAG, "Invalid port number: " + part.trim());
                }
        }
        
        // Return trimmed array
        int[] result = new int[idx];
        System.arraycopy(ports, 0, result, 0, idx);
        return result;
    }
    
    /**
     * Set default ports.
     */
    public void setDefaultPorts(@NonNull String ports) {
        editor.putString(KEY_DEFAULT_PORTS, ports);
        editor.apply();
    }
    
    // ==================== UI Settings ====================
    
    /**
     * Check if dark theme is enabled.
     */
    public boolean isDarkThemeEnabled() {
        return prefs.getBoolean(KEY_DARK_THEME, DEFAULT_DARK_THEME);
    }
    
    /**
     * Set dark theme enabled.
     */
    public void setDarkThemeEnabled(boolean enabled) {
        editor.putBoolean(KEY_DARK_THEME, enabled);
        editor.apply();
    }
    
    /**
     * Check if hostname display is enabled.
     */
    public boolean isShowHostnameEnabled() {
        return prefs.getBoolean(KEY_SHOW_HOSTNAME, DEFAULT_SHOW_HOSTNAME);
    }
    
    /**
     * Set show hostname enabled.
     */
    public void setShowHostnameEnabled(boolean enabled) {
        editor.putBoolean(KEY_SHOW_HOSTNAME, enabled);
        editor.apply();
    }
    
    /**
     * Check if hostname resolution is enabled.
     */
    public boolean isResolveHostnamesEnabled() {
        return prefs.getBoolean(KEY_RESOLVE_HOSTNAMES, DEFAULT_RESOLVE_HOSTNAMES);
    }
    
    /**
     * Set resolve hostnames enabled.
     */
    public void setResolveHostnamesEnabled(boolean enabled) {
        editor.putBoolean(KEY_RESOLVE_HOSTNAMES, enabled);
        editor.apply();
    }
    
    // ==================== Notification Settings ====================
    
    /**
     * Check if notifications are enabled.
     */
    public boolean isNotificationEnabled() {
        return prefs.getBoolean(KEY_NOTIFICATION_ENABLED, DEFAULT_NOTIFICATION_ENABLED);
    }
    
    /**
     * Set notifications enabled.
     */
    public void setNotificationEnabled(boolean enabled) {
        editor.putBoolean(KEY_NOTIFICATION_ENABLED, enabled);
        editor.apply();
    }
    
    /**
     * Check if vibration is enabled.
     */
    public boolean isVibrationEnabled() {
        return prefs.getBoolean(KEY_VIBRATION_ENABLED, DEFAULT_VIBRATION_ENABLED);
    }
    
    /**
     * Set vibration enabled.
     */
    public void setVibrationEnabled(boolean enabled) {
        editor.putBoolean(KEY_VIBRATION_ENABLED, enabled);
        editor.apply();
    }
    
    /**
     * Check if sound is enabled.
     */
    public boolean isSoundEnabled() {
        return prefs.getBoolean(KEY_SOUND_ENABLED, DEFAULT_SOUND_ENABLED);
    }
    
    /**
     * Set sound enabled.
     */
    public void setSoundEnabled(boolean enabled) {
        editor.putBoolean(KEY_SOUND_ENABLED, enabled);
        editor.apply();
    }
    
    // ==================== Network Settings ====================
    
    /**
     * Check if WiFi only mode is enabled.
     */
    public boolean isWifiOnlyEnabled() {
        return prefs.getBoolean(KEY_WIFI_ONLY, DEFAULT_WIFI_ONLY);
    }
    
    /**
     * Set WiFi only mode.
     */
    public void setWifiOnlyEnabled(boolean enabled) {
        editor.putBoolean(KEY_WIFI_ONLY, enabled);
        editor.apply();
    }
    
    /**
     * Get last connected network SSID.
     */
    @Nullable
    public String getLastNetwork() {
        return prefs.getString(KEY_LAST_NETWORK, null);
    }
    
    /**
     * Set last connected network.
     */
    public void setLastNetwork(@Nullable String ssid) {
        if (ssid != null) {
            editor.putString(KEY_LAST_NETWORK, ssid);
        } else {
            editor.remove(KEY_LAST_NETWORK);
        }
        editor.apply();
    }
    
    // ==================== Privacy Settings ====================
    
    /**
     * Check if analytics is enabled.
     */
    public boolean isAnalyticsEnabled() {
        return prefs.getBoolean(KEY_ANALYTICS_ENABLED, true);
    }
    
    /**
     * Set analytics enabled.
     */
    public void setAnalyticsEnabled(boolean enabled) {
        editor.putBoolean(KEY_ANALYTICS_ENABLED, enabled);
        editor.apply();
    }
    
    /**
     * Check if crash reporting is enabled.
     */
    public boolean isCrashReportingEnabled() {
        return prefs.getBoolean(KEY_CRASH_REPORTING, true);
    }
    
    /**
     * Set crash reporting enabled.
     */
    public void setCrashReportingEnabled(boolean enabled) {
        editor.putBoolean(KEY_CRASH_REPORTING, enabled);
        editor.apply();
    }
    
    // ==================== App State ====================
    
    /**
     * Check if this is the first run.
     */
    public boolean isFirstRun() {
        return prefs.getBoolean(KEY_FIRST_RUN, true);
    }
    
    /**
     * Mark first run as complete.
     */
    public void setFirstRunComplete() {
        editor.putBoolean(KEY_FIRST_RUN, false);
        editor.apply();
    }
    
    /**
     * Check if auto update is enabled.
     */
    public boolean isAutoUpdateEnabled() {
        return prefs.getBoolean(KEY_AUTO_UPDATE, true);
    }
    
    /**
     * Set auto update enabled.
     */
    public void setAutoUpdateEnabled(boolean enabled) {
        editor.putBoolean(KEY_AUTO_UPDATE, enabled);
        editor.apply();
    }
    
    /**
     * Check if MSF is enabled.
     */
    public boolean isMsfEnabled() {
        return prefs.getBoolean(KEY_MSF_ENABLED, false);
    }
    
    /**
     * Set MSF enabled.
     */
    public void setMsfEnabled(boolean enabled) {
        editor.putBoolean(KEY_MSF_ENABLED, enabled);
        editor.apply();
    }
    
    /**
     * Check if root has been granted.
     */
    public boolean isRootGranted() {
        return prefs.getBoolean(KEY_ROOT_GRANTED, false);
    }
    
    /**
     * Set root granted status.
     */
    public void setRootGranted(boolean granted) {
        editor.putBoolean(KEY_ROOT_GRANTED, granted);
        editor.apply();
    }
    
    // ==================== Network Ports ====================

    /**
     * Get HTTP proxy port.
     */
    public int getHttpProxyPort() {
        String portStr = prefs.getString(KEY_HTTP_PROXY_PORT, String.valueOf(DEFAULT_HTTP_PROXY_PORT));
        try {
            return Integer.parseInt(portStr);
        } catch (NumberFormatException e) {
            return DEFAULT_HTTP_PROXY_PORT;
        }
    }

    /**
     * Set HTTP proxy port.
     */
    public void setHttpProxyPort(int port) {
        port = Math.max(1, Math.min(65535, port));
        editor.putString(KEY_HTTP_PROXY_PORT, String.valueOf(port));
        editor.apply();
    }

    /**
     * Get HTTP server port.
     */
    public int getHttpServerPort() {
        String portStr = prefs.getString(KEY_HTTP_SERVER_PORT, String.valueOf(DEFAULT_HTTP_SERVER_PORT));
        try {
            return Integer.parseInt(portStr);
        } catch (NumberFormatException e) {
            return DEFAULT_HTTP_SERVER_PORT;
        }
    }

    /**
     * Set HTTP server port.
     */
    public void setHttpServerPort(int port) {
        port = Math.max(1, Math.min(65535, port));
        editor.putString(KEY_HTTP_SERVER_PORT, String.valueOf(port));
        editor.apply();
    }

    /**
     * Get HTTPS redirector port.
     */
    public int getHttpsRedirPort() {
        String portStr = prefs.getString(KEY_HTTPS_REDIR_PORT, String.valueOf(DEFAULT_HTTPS_REDIR_PORT));
        try {
            return Integer.parseInt(portStr);
        } catch (NumberFormatException e) {
            return DEFAULT_HTTPS_REDIR_PORT;
        }
    }

    /**
     * Set HTTPS redirector port.
     */
    public void setHttpsRedirPort(int port) {
        port = Math.max(1, Math.min(65535, port));
        editor.putString(KEY_HTTPS_REDIR_PORT, String.valueOf(port));
        editor.apply();
    }

    /**
     * Get MSF RPC port.
     */
    public int getMsfRpcPort() {
        String portStr = prefs.getString(KEY_MSF_RPC_PORT, String.valueOf(DEFAULT_MSF_RPC_PORT));
        try {
            return Integer.parseInt(portStr);
        } catch (NumberFormatException e) {
            return DEFAULT_MSF_RPC_PORT;
        }
    }

    /**
     * Set MSF RPC port.
     */
    public void setMsfRpcPort(int port) {
        port = Math.max(1, Math.min(65535, port));
        editor.putString(KEY_MSF_RPC_PORT, String.valueOf(port));
        editor.apply();
    }

    // ==================== Generic Methods ====================
    
    /**
     * Get a string preference.
     */
    @Nullable
    public String getString(@NonNull String key, @Nullable String defaultValue) {
        return prefs.getString(key, defaultValue);
    }
    
    /**
     * Set a string preference.
     */
    public void setString(@NonNull String key, @Nullable String value) {
        if (value != null) {
            editor.putString(key, value);
        } else {
            editor.remove(key);
        }
        editor.apply();
    }
    
    /**
     * Get a boolean preference.
     */
    public boolean getBoolean(@NonNull String key, boolean defaultValue) {
        return prefs.getBoolean(key, defaultValue);
    }
    
    /**
     * Set a boolean preference.
     */
    public void setBoolean(@NonNull String key, boolean value) {
        editor.putBoolean(key, value);
        editor.apply();
    }
    
    /**
     * Get an int preference.
     */
    public int getInt(@NonNull String key, int defaultValue) {
        return prefs.getInt(key, defaultValue);
    }
    
    /**
     * Set an int preference.
     */
    public void setInt(@NonNull String key, int value) {
        editor.putInt(key, value);
        editor.apply();
    }
    
    /**
     * Get a long preference.
     */
    public long getLong(@NonNull String key, long defaultValue) {
        return prefs.getLong(key, defaultValue);
    }
    
    /**
     * Set a long preference.
     */
    public void setLong(@NonNull String key, long value) {
        editor.putLong(key, value);
        editor.apply();
    }
    
    /**
     * Check if a preference exists.
     */
    public boolean contains(@NonNull String key) {
        return prefs.contains(key);
    }
    
    /**
     * Remove a preference.
     */
    public void remove(@NonNull String key) {
        editor.remove(key);
        editor.apply();
    }
    
    /**
     * Clear all preferences.
     */
    public void clear() {
        editor.clear();
        editor.apply();
        LoggingHelper.w(TAG, "All preferences cleared");
    }
    
    /**
     * Get all preferences as a map.
     */
    @NonNull
    public Map<String, ?> getAll() {
        return prefs.getAll();
    }
    
    /**
     * Export configuration to JSON string.
     */
    @NonNull
    public String exportToJson() {
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        
        Map<String, ?> all = prefs.getAll();
        int count = 0;
        for (Map.Entry<String, ?> entry : all.entrySet()) {
            if (count > 0) json.append(",\n");
            json.append("  \"").append(entry.getKey()).append("\": ");
            
            Object value = entry.getValue();
            if (value instanceof String) {
                json.append("\"").append(value).append("\"");
            } else if (value instanceof Boolean || value instanceof Number) {
                json.append(value);
            } else if (value instanceof Set) {
                json.append("[");
                Set<?> set = (Set<?>) value;
                int idx = 0;
                for (Object item : set) {
                    if (idx > 0) json.append(", ");
                    json.append("\"").append(item).append("\"");
                    idx++;
                }
                json.append("]");
            }
            count++;
        }
        
        json.append("\n}");
        return json.toString();
    }
    
    /**
     * Reset all settings to defaults.
     */
    public void resetToDefaults() {
        editor.clear();
        editor.putInt(KEY_SCAN_TIMEOUT, DEFAULT_SCAN_TIMEOUT);
        editor.putBoolean(KEY_AUTO_PORTSCAN, DEFAULT_AUTO_PORTSCAN);
        editor.putBoolean(KEY_DARK_THEME, DEFAULT_DARK_THEME);
        editor.putBoolean(KEY_NOTIFICATION_ENABLED, DEFAULT_NOTIFICATION_ENABLED);
        editor.putBoolean(KEY_VIBRATION_ENABLED, DEFAULT_VIBRATION_ENABLED);
        editor.putBoolean(KEY_SOUND_ENABLED, DEFAULT_SOUND_ENABLED);
        editor.putBoolean(KEY_WIFI_ONLY, DEFAULT_WIFI_ONLY);
        editor.putBoolean(KEY_SHOW_HOSTNAME, DEFAULT_SHOW_HOSTNAME);
        editor.putBoolean(KEY_RESOLVE_HOSTNAMES, DEFAULT_RESOLVE_HOSTNAMES);
        editor.putInt(KEY_CONCURRENT_SCANS, DEFAULT_CONCURRENT_SCANS);
        editor.putString(KEY_DEFAULT_PORTS, DEFAULT_PORTS);
        editor.putInt(KEY_CONFIG_VERSION, CURRENT_CONFIG_VERSION);
        editor.apply();
        
        LoggingHelper.i(TAG, "Configuration reset to defaults");
    }
}
