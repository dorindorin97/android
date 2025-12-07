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
import org.csploit.android.helpers.LoggingHelper;
import android.content.SharedPreferences;
import org.csploit.android.helpers.LoggingHelper;
import androidx.annotation.NonNull;
import org.csploit.android.helpers.LoggingHelper;
import androidx.annotation.Nullable;
import org.csploit.android.helpers.LoggingHelper;

import java.util.Set;
import org.csploit.android.helpers.LoggingHelper;

/**
 * Enhanced preferences helper with type-safe operations and default values.
 * Provides a centralized way to manage app preferences with proper error handling.
 */
public class EnhancedPreferencesHelper {
    
    private static final String TAG = "EnhancedPreferencesHelper";
    private static final String PREF_NAME = "cSploit_Preferences";
    
    // Preference keys
    public static final String KEY_DARK_MODE = "dark_mode_enabled";
    public static final String KEY_AUTO_SCAN = "auto_scan_enabled";
    public static final String KEY_SCAN_INTERVAL = "scan_interval_hours";
    public static final String KEY_NOTIFICATION_ENABLED = "notifications_enabled";
    public static final String KEY_CRASH_REPORTING = "crash_reporting_enabled";
    public static final String KEY_LAST_UPDATE_CHECK = "last_update_check";
    public static final String KEY_OFFLINE_MODE = "offline_mode";
    public static final String KEY_FIRST_RUN = "first_run";
    
    // Default values
    private static final boolean DEFAULT_DARK_MODE = false;
    private static final boolean DEFAULT_AUTO_SCAN = false;
    private static final long DEFAULT_SCAN_INTERVAL = 24; // hours
    private static final boolean DEFAULT_NOTIFICATION = true;
    private static final boolean DEFAULT_CRASH_REPORTING = false;
    private static final boolean DEFAULT_OFFLINE_MODE = false;
    private static final boolean DEFAULT_FIRST_RUN = true;
    
    private final SharedPreferences prefs;
    
    /**
     * Create an instance of EnhancedPreferencesHelper.
     * 
     * @param context Application context
     */
    public EnhancedPreferencesHelper(@NonNull Context context) {
        this.prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
    }
    
    /**
     * Get the global instance using PreferencesHelper.
     * 
     * @param context Android context
     * @return SharedPreferences instance
     */
    public static SharedPreferences getGlobalPreferences(@NonNull Context context) {
        return context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
    }
    
    // Dark Mode
    public boolean isDarkModeEnabled() {
        return prefs.getBoolean(KEY_DARK_MODE, DEFAULT_DARK_MODE);
    }
    
    public void setDarkModeEnabled(boolean enabled) {
        prefs.edit().putBoolean(KEY_DARK_MODE, enabled).apply();
    }
    
    // Auto Scan
    public boolean isAutoScanEnabled() {
        return prefs.getBoolean(KEY_AUTO_SCAN, DEFAULT_AUTO_SCAN);
    }
    
    public void setAutoScanEnabled(boolean enabled) {
        prefs.edit().putBoolean(KEY_AUTO_SCAN, enabled).apply();
    }
    
    // Scan Interval
    public long getScanIntervalHours() {
        return prefs.getLong(KEY_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL);
    }
    
    public void setScanIntervalHours(long hours) {
        if (hours < 1) {
            LoggingHelper.w(TAG, "Scan interval must be at least 1 hour");
            hours = 1;
        }
        prefs.edit().putLong(KEY_SCAN_INTERVAL, hours).apply();
    }
    
    // Notifications
    public boolean areNotificationsEnabled() {
        return prefs.getBoolean(KEY_NOTIFICATION_ENABLED, DEFAULT_NOTIFICATION);
    }
    
    public void setNotificationsEnabled(boolean enabled) {
        prefs.edit().putBoolean(KEY_NOTIFICATION_ENABLED, enabled).apply();
    }
    
    // Crash Reporting
    public boolean isCrashReportingEnabled() {
        return prefs.getBoolean(KEY_CRASH_REPORTING, DEFAULT_CRASH_REPORTING);
    }
    
    public void setCrashReportingEnabled(boolean enabled) {
        prefs.edit().putBoolean(KEY_CRASH_REPORTING, enabled).apply();
    }
    
    // Last Update Check
    public long getLastUpdateCheckTime() {
        return prefs.getLong(KEY_LAST_UPDATE_CHECK, 0);
    }
    
    public void setLastUpdateCheckTime(long timestamp) {
        prefs.edit().putLong(KEY_LAST_UPDATE_CHECK, timestamp).apply();
    }
    
    // Offline Mode
    public boolean isOfflineModeEnabled() {
        return prefs.getBoolean(KEY_OFFLINE_MODE, DEFAULT_OFFLINE_MODE);
    }
    
    public void setOfflineModeEnabled(boolean enabled) {
        prefs.edit().putBoolean(KEY_OFFLINE_MODE, enabled).apply();
    }
    
    // First Run
    public boolean isFirstRun() {
        return prefs.getBoolean(KEY_FIRST_RUN, DEFAULT_FIRST_RUN);
    }
    
    public void setFirstRun(boolean firstRun) {
        prefs.edit().putBoolean(KEY_FIRST_RUN, firstRun).apply();
    }
    
    /**
     * Clear all preferences.
     */
    public void clearAll() {
        prefs.edit().clear().apply();
        LoggingHelper.i(TAG, "All preferences cleared");
    }
    
    /**
     * Check if a preference key exists.
     * 
     * @param key Preference key
     * @return true if key exists
     */
    public boolean contains(@NonNull String key) {
        return prefs.contains(key);
    }
    
    /**
     * Remove a specific preference.
     * 
     * @param key Preference key to remove
     */
    public void remove(@NonNull String key) {
        prefs.edit().remove(key).apply();
    }
    
    /**
     * Get string preference.
     * 
     * @param key Preference key
     * @param defaultValue Default value if key doesn't exist
     * @return String value
     */
    @Nullable
    public String getString(@NonNull String key, @Nullable String defaultValue) {
        return prefs.getString(key, defaultValue);
    }
    
    /**
     * Set string preference.
     * 
     * @param key Preference key
     * @param value Value to set
     */
    public void setString(@NonNull String key, @Nullable String value) {
        prefs.edit().putString(key, value).apply();
    }
    
    /**
     * Get int preference.
     * 
     * @param key Preference key
     * @param defaultValue Default value if key doesn't exist
     * @return int value
     */
    public int getInt(@NonNull String key, int defaultValue) {
        return prefs.getInt(key, defaultValue);
    }
    
    /**
     * Set int preference.
     * 
     * @param key Preference key
     * @param value Value to set
     */
    public void setInt(@NonNull String key, int value) {
        prefs.edit().putInt(key, value).apply();
    }
    
    /**
     * Get long preference.
     * 
     * @param key Preference key
     * @param defaultValue Default value if key doesn't exist
     * @return long value
     */
    public long getLong(@NonNull String key, long defaultValue) {
        return prefs.getLong(key, defaultValue);
    }
    
    /**
     * Set long preference.
     * 
     * @param key Preference key
     * @param value Value to set
     */
    public void setLong(@NonNull String key, long value) {
        prefs.edit().putLong(key, value).apply();
    }
    
    /**
     * Get boolean preference.
     * 
     * @param key Preference key
     * @param defaultValue Default value if key doesn't exist
     * @return boolean value
     */
    public boolean getBoolean(@NonNull String key, boolean defaultValue) {
        return prefs.getBoolean(key, defaultValue);
    }
    
    /**
     * Set boolean preference.
     * 
     * @param key Preference key
     * @param value Value to set
     */
    public void setBoolean(@NonNull String key, boolean value) {
        prefs.edit().putBoolean(key, value).apply();
    }
}
