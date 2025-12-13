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

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Environment;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.preference.PreferenceManager;

import java.io.File;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Helper class for managing system configuration.
 * Provides centralized access to app settings with type-safe methods and caching.
 */
public final class SystemConfigHelper {

    private static final String TAG = "SystemConfigHelper";

    // Preference keys
    public static final String PREF_SAVE_PATH = "PREF_SAVE_PATH";
    public static final String PREF_HTTP_PROXY_PORT = "PREF_HTTP_PROXY_PORT";
    public static final String PREF_HTTP_SERVER_PORT = "PREF_HTTP_SERVER_PORT";
    public static final String PREF_HTTPS_REDIRECTOR_PORT = "PREF_HTTPS_REDIRECTOR_PORT";
    public static final String PREF_MSF_RPC_PORT = "MSF_RPC_PORT";
    public static final String PREF_WAKE_LOCK = "PREF_WAKE_LOCK";
    public static final String PREF_DEBUG_ERROR_LOGGING = "PREF_DEBUG_ERROR_LOGGING";
    public static final String PREF_CHECK_UPDATES = "PREF_CHECK_UPDATES";
    public static final String PREF_HTTPS_REDIRECT = "PREF_HTTPS_REDIRECT";
    public static final String PREF_DARK_THEME = "isDark";
    public static final String PREF_THEME_STORE = "THEME";

    // Default values
    public static final int DEFAULT_HTTP_PROXY_PORT = 8080;
    public static final int DEFAULT_HTTP_SERVER_PORT = 8081;
    public static final int DEFAULT_HTTPS_REDIR_PORT = 8082;
    public static final int DEFAULT_MSF_RPC_PORT = 55553;
    public static final boolean DEFAULT_WAKE_LOCK = true;
    public static final boolean DEFAULT_DEBUG_LOGGING = false;
    public static final boolean DEFAULT_CHECK_UPDATES = true;
    public static final boolean DEFAULT_HTTPS_REDIRECT = true;
    public static final boolean DEFAULT_DARK_THEME = false;

    // Cache
    private static final ConcurrentHashMap<String, Object> configCache = new ConcurrentHashMap<>();
    private static volatile SharedPreferences preferences = null;
    private static volatile SharedPreferences themePreferences = null;
    private static volatile Context appContext = null;

    private SystemConfigHelper() {
        // Prevent instantiation
    }

    /**
     * Initialize the config helper with application context.
     * Should be called once during app startup.
     *
     * @param context Application context
     */
    public static void init(@NonNull Context context) {
        appContext = context.getApplicationContext();
        preferences = PreferenceManager.getDefaultSharedPreferences(appContext);
        themePreferences = appContext.getSharedPreferences(PREF_THEME_STORE, Context.MODE_PRIVATE);
        // Pre-load commonly used values
        preloadCommonConfig();
    }

    /**
     * Pre-load commonly used configuration values.
     */
    private static void preloadCommonConfig() {
        getHttpProxyPort();
        getHttpServerPort();
        getHttpsRedirectorPort();
        getMsfRpcPort();
        isWakeLockEnabled();
        isDarkThemeEnabled();
    }

    /**
     * Get SharedPreferences instance.
     */
    @Nullable
    public static SharedPreferences getPreferences() {
        return preferences;
    }

    /**
     * Get application context.
     */
    @Nullable
    public static Context getContext() {
        return appContext;
    }

    // Port configuration

    /**
     * Get HTTP proxy port.
     */
    public static int getHttpProxyPort() {
        return getIntConfig(PREF_HTTP_PROXY_PORT, DEFAULT_HTTP_PROXY_PORT);
    }

    /**
     * Set HTTP proxy port.
     */
    public static void setHttpProxyPort(int port) {
        setIntConfig(PREF_HTTP_PROXY_PORT, port);
    }

    /**
     * Get HTTP server port.
     */
    public static int getHttpServerPort() {
        return getIntConfig(PREF_HTTP_SERVER_PORT, DEFAULT_HTTP_SERVER_PORT);
    }

    /**
     * Set HTTP server port.
     */
    public static void setHttpServerPort(int port) {
        setIntConfig(PREF_HTTP_SERVER_PORT, port);
    }

    /**
     * Get HTTPS redirector port.
     */
    public static int getHttpsRedirectorPort() {
        return getIntConfig(PREF_HTTPS_REDIRECTOR_PORT, DEFAULT_HTTPS_REDIR_PORT);
    }

    /**
     * Set HTTPS redirector port.
     */
    public static void setHttpsRedirectorPort(int port) {
        setIntConfig(PREF_HTTPS_REDIRECTOR_PORT, port);
    }

    /**
     * Get MSF RPC port.
     */
    public static int getMsfRpcPort() {
        return getIntConfig(PREF_MSF_RPC_PORT, DEFAULT_MSF_RPC_PORT);
    }

    /**
     * Set MSF RPC port.
     */
    public static void setMsfRpcPort(int port) {
        setIntConfig(PREF_MSF_RPC_PORT, port);
    }

    // Boolean configurations

    /**
     * Check if wake lock is enabled.
     */
    public static boolean isWakeLockEnabled() {
        return getBooleanConfig(PREF_WAKE_LOCK, DEFAULT_WAKE_LOCK);
    }

    /**
     * Set wake lock enabled.
     */
    public static void setWakeLockEnabled(boolean enabled) {
        setBooleanConfig(PREF_WAKE_LOCK, enabled);
    }

    /**
     * Check if debug error logging is enabled.
     */
    public static boolean isDebugLoggingEnabled() {
        return getBooleanConfig(PREF_DEBUG_ERROR_LOGGING, DEFAULT_DEBUG_LOGGING);
    }

    /**
     * Set debug error logging enabled.
     */
    public static void setDebugLoggingEnabled(boolean enabled) {
        setBooleanConfig(PREF_DEBUG_ERROR_LOGGING, enabled);
    }

    /**
     * Check if update checking is enabled.
     */
    public static boolean isUpdateCheckEnabled() {
        return getBooleanConfig(PREF_CHECK_UPDATES, DEFAULT_CHECK_UPDATES);
    }

    /**
     * Set update checking enabled.
     */
    public static void setUpdateCheckEnabled(boolean enabled) {
        setBooleanConfig(PREF_CHECK_UPDATES, enabled);
    }

    /**
     * Check if HTTPS redirect is enabled.
     */
    public static boolean isHttpsRedirectEnabled() {
        return getBooleanConfig(PREF_HTTPS_REDIRECT, DEFAULT_HTTPS_REDIRECT);
    }

    /**
     * Set HTTPS redirect enabled.
     */
    public static void setHttpsRedirectEnabled(boolean enabled) {
        setBooleanConfig(PREF_HTTPS_REDIRECT, enabled);
    }

    /**
     * Check if dark theme is enabled.
     */
    public static boolean isDarkThemeEnabled() {
        if (themePreferences == null) {
            return DEFAULT_DARK_THEME;
        }
        Object cached = configCache.get(PREF_DARK_THEME);
        if (cached != null) {
            return (Boolean) cached;
        }
        boolean value = themePreferences.getBoolean(PREF_DARK_THEME, DEFAULT_DARK_THEME);
        configCache.put(PREF_DARK_THEME, value);
        return value;
    }

    /**
     * Set dark theme enabled.
     */
    public static void setDarkThemeEnabled(boolean enabled) {
        if (themePreferences != null) {
            themePreferences.edit().putBoolean(PREF_DARK_THEME, enabled).apply();
            configCache.put(PREF_DARK_THEME, enabled);
        }
    }

    // Path configuration

    /**
     * Get save path.
     */
    @NonNull
    public static String getSavePath() {
        return getStringConfig(PREF_SAVE_PATH, getDefaultSavePath());
    }

    /**
     * Set save path.
     */
    public static void setSavePath(@NonNull String path) {
        setStringConfig(PREF_SAVE_PATH, path);
    }

    /**
     * Get default save path.
     */
    @NonNull
    public static String getDefaultSavePath() {
        return Environment.getExternalStorageDirectory().toString();
    }

    /**
     * Get files directory path.
     */
    @Nullable
    public static String getFilesPath() {
        return appContext != null ? appContext.getFilesDir().getAbsolutePath() : null;
    }

    /**
     * Get cache directory path.
     */
    @Nullable
    public static String getCachePath() {
        return appContext != null ? appContext.getCacheDir().getAbsolutePath() : null;
    }

    // Generic config methods

    /**
     * Get string configuration value.
     */
    @NonNull
    public static String getStringConfig(@NonNull String key, @NonNull String defaultValue) {
        if (preferences == null) {
            return defaultValue;
        }
        Object cached = configCache.get(key);
        if (cached instanceof String) {
            return (String) cached;
        }
        String value = preferences.getString(key, defaultValue);
        if (value == null) {
            value = defaultValue;
        }
        configCache.put(key, value);
        return value;
    }

    /**
     * Set string configuration value.
     */
    public static void setStringConfig(@NonNull String key, @NonNull String value) {
        if (preferences != null) {
            preferences.edit().putString(key, value).apply();
            configCache.put(key, value);
        }
    }

    /**
     * Get integer configuration value.
     */
    public static int getIntConfig(@NonNull String key, int defaultValue) {
        if (preferences == null) {
            return defaultValue;
        }
        Object cached = configCache.get(key);
        if (cached instanceof Integer) {
            return (Integer) cached;
        }
        // Try string first (for EditTextPreference stored as string)
        String strValue = preferences.getString(key, null);
        int value = defaultValue;
        if (strValue != null) {
            try {
                value = Integer.parseInt(strValue);
            } catch (NumberFormatException e) {
                value = defaultValue;
            }
        }
        configCache.put(key, value);
        return value;
    }

    /**
     * Set integer configuration value.
     */
    public static void setIntConfig(@NonNull String key, int value) {
        if (preferences != null) {
            preferences.edit().putString(key, String.valueOf(value)).apply();
            configCache.put(key, value);
        }
    }

    /**
     * Get boolean configuration value.
     */
    public static boolean getBooleanConfig(@NonNull String key, boolean defaultValue) {
        if (preferences == null) {
            return defaultValue;
        }
        Object cached = configCache.get(key);
        if (cached instanceof Boolean) {
            return (Boolean) cached;
        }
        boolean value = preferences.getBoolean(key, defaultValue);
        configCache.put(key, value);
        return value;
    }

    /**
     * Set boolean configuration value.
     */
    public static void setBooleanConfig(@NonNull String key, boolean value) {
        if (preferences != null) {
            preferences.edit().putBoolean(key, value).apply();
            configCache.put(key, value);
        }
    }

    /**
     * Get long configuration value.
     */
    public static long getLongConfig(@NonNull String key, long defaultValue) {
        if (preferences == null) {
            return defaultValue;
        }
        Object cached = configCache.get(key);
        if (cached instanceof Long) {
            return (Long) cached;
        }
        long value = preferences.getLong(key, defaultValue);
        configCache.put(key, value);
        return value;
    }

    /**
     * Set long configuration value.
     */
    public static void setLongConfig(@NonNull String key, long value) {
        if (preferences != null) {
            preferences.edit().putLong(key, value).apply();
            configCache.put(key, value);
        }
    }

    /**
     * Remove a configuration value.
     */
    public static void removeConfig(@NonNull String key) {
        if (preferences != null) {
            preferences.edit().remove(key).apply();
            configCache.remove(key);
        }
    }

    /**
     * Clear all configuration cache.
     */
    public static void clearCache() {
        configCache.clear();
    }

    /**
     * Get all configuration as a map.
     */
    @NonNull
    public static Map<String, ?> getAllConfig() {
        if (preferences == null) {
            return new HashMap<>();
        }
        return new HashMap<>(preferences.getAll());
    }

    // Device information

    /**
     * Get device model.
     */
    @NonNull
    public static String getDeviceModel() {
        return Build.MODEL;
    }

    /**
     * Get device manufacturer.
     */
    @NonNull
    public static String getDeviceManufacturer() {
        return Build.MANUFACTURER;
    }

    /**
     * Get Android API level.
     */
    public static int getApiLevel() {
        return Build.VERSION.SDK_INT;
    }

    /**
     * Get Android version string.
     */
    @NonNull
    public static String getAndroidVersion() {
        return Build.VERSION.RELEASE;
    }

    /**
     * Get device fingerprint.
     */
    @NonNull
    public static String getDeviceFingerprint() {
        return Build.FINGERPRINT;
    }

    /**
     * Get CPU ABI.
     */
    @NonNull
    public static String getCpuAbi() {
        return Build.CPU_ABI;
    }

    /**
     * Check if device is ARM architecture.
     */
    public static boolean isArm() {
        return Build.CPU_ABI.toLowerCase().startsWith("armeabi");
    }

    /**
     * Check if device is ARM64 architecture.
     */
    public static boolean isArm64() {
        return Build.CPU_ABI.toLowerCase().contains("arm64") ||
               Build.CPU_ABI.toLowerCase().contains("aarch64");
    }

    /**
     * Check if device is x86 architecture.
     */
    public static boolean isX86() {
        return Build.CPU_ABI.toLowerCase().startsWith("x86");
    }

    /**
     * Get platform string for cSploit.
     */
    @NonNull
    public static String getPlatformString() {
        return String.format("android%d.%s", getApiLevel(), getCpuAbi());
    }

    /**
     * Validate and create directory if needed.
     */
    public static boolean ensureDirectory(@NonNull String path) {
        File dir = new File(path);
        if (dir.exists()) {
            return dir.isDirectory();
        }
        return dir.mkdirs();
    }

    /**
     * Get debug information string.
     */
    @NonNull
    public static String getDebugInfo() {
        StringBuilder sb = new StringBuilder();
        sb.append("Device: ").append(getDeviceManufacturer()).append(" ").append(getDeviceModel()).append("\n");
        sb.append("Android: ").append(getAndroidVersion()).append(" (API ").append(getApiLevel()).append(")\n");
        sb.append("CPU: ").append(getCpuAbi()).append("\n");
        sb.append("Platform: ").append(getPlatformString()).append("\n");
        sb.append("Save Path: ").append(getSavePath()).append("\n");
        sb.append("Files Path: ").append(getFilesPath()).append("\n");
        sb.append("Wake Lock: ").append(isWakeLockEnabled()).append("\n");
        sb.append("Debug Logging: ").append(isDebugLoggingEnabled()).append("\n");
        sb.append("Dark Theme: ").append(isDarkThemeEnabled()).append("\n");
        return sb.toString();
    }
}
