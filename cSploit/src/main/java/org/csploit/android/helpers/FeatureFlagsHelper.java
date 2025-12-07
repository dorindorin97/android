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
import android.os.Build;
import org.csploit.android.helpers.LoggingHelper;
import androidx.annotation.NonNull;
import org.csploit.android.helpers.LoggingHelper;

/**
 * Helper class for tracking and managing feature flags.
 * Enables gradual rollout of features and A/B testing.
 */
public class FeatureFlagsHelper {
    
    private static final String TAG = "FeatureFlagsHelper";
    private static final String PREFS_NAME = "feature_flags";
    
    // Feature flag keys
    public static final String FLAG_NEW_SCANNER = "flag_new_scanner";
    public static final String FLAG_DARK_MODE_AUTO = "flag_dark_mode_auto";
    public static final String FLAG_BACKGROUND_SCAN = "flag_background_scan";
    public static final String FLAG_ENHANCED_LOGGING = "flag_enhanced_logging";
    public static final String FLAG_ANALYTICS = "flag_analytics";
    public static final String FLAG_PERFORMANCE_MONITOR = "flag_performance_monitor";
    public static final String FLAG_ADVANCED_EXPLOITS = "flag_advanced_exploits";
    public static final String FLAG_SCHEDULED_SCANS = "flag_scheduled_scans";
    public static final String FLAG_TARGET_HISTORY = "flag_target_history";
    public static final String FLAG_OFFLINE_MODE = "flag_offline_mode";
    
    private static FeatureFlagsHelper instance;
    private final SharedPreferences prefs;
    
    private FeatureFlagsHelper(@NonNull Context context) {
        this.prefs = context.getApplicationContext()
                .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        initializeDefaultFlags();
    }
    
    /**
     * Get singleton instance.
     * 
     * @param context Application context
     * @return FeatureFlagsHelper instance
     */
    public static synchronized FeatureFlagsHelper getInstance(@NonNull Context context) {
        if (instance == null) {
            instance = new FeatureFlagsHelper(context);
        }
        return instance;
    }
    
    /**
     * Initialize default flag values based on build type and SDK version.
     */
    private void initializeDefaultFlags() {
        // Only set defaults if not already initialized
        if (!prefs.contains("initialized")) {
            SharedPreferences.Editor editor = prefs.edit();
            
            // Default flags - conservative settings
            editor.putBoolean(FLAG_NEW_SCANNER, true);
            editor.putBoolean(FLAG_DARK_MODE_AUTO, Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q);
            editor.putBoolean(FLAG_BACKGROUND_SCAN, false);
            editor.putBoolean(FLAG_ENHANCED_LOGGING, org.csploit.android.BuildConfig.DEBUG);
            editor.putBoolean(FLAG_ANALYTICS, false);
            editor.putBoolean(FLAG_PERFORMANCE_MONITOR, org.csploit.android.BuildConfig.DEBUG);
            editor.putBoolean(FLAG_ADVANCED_EXPLOITS, false);
            editor.putBoolean(FLAG_SCHEDULED_SCANS, false);
            editor.putBoolean(FLAG_TARGET_HISTORY, true);
            editor.putBoolean(FLAG_OFFLINE_MODE, false);
            
            editor.putBoolean("initialized", true);
            editor.apply();
            
            LoggingHelper.i(TAG, "Feature flags initialized with defaults");
        }
    }
    
    /**
     * Check if a feature flag is enabled.
     * 
     * @param flagKey Feature flag key
     * @return true if enabled
     */
    public boolean isEnabled(@NonNull String flagKey) {
        return prefs.getBoolean(flagKey, false);
    }
    
    /**
     * Check if a feature flag is enabled with a custom default.
     * 
     * @param flagKey Feature flag key
     * @param defaultValue Default value if flag not set
     * @return true if enabled
     */
    public boolean isEnabled(@NonNull String flagKey, boolean defaultValue) {
        return prefs.getBoolean(flagKey, defaultValue);
    }
    
    /**
     * Enable a feature flag.
     * 
     * @param flagKey Feature flag key
     */
    public void enable(@NonNull String flagKey) {
        prefs.edit().putBoolean(flagKey, true).apply();
        LoggingHelper.d(TAG, "Feature enabled: " + flagKey);
    }
    
    /**
     * Disable a feature flag.
     * 
     * @param flagKey Feature flag key
     */
    public void disable(@NonNull String flagKey) {
        prefs.edit().putBoolean(flagKey, false).apply();
        LoggingHelper.d(TAG, "Feature disabled: " + flagKey);
    }
    
    /**
     * Toggle a feature flag.
     * 
     * @param flagKey Feature flag key
     * @return New state of the flag
     */
    public boolean toggle(@NonNull String flagKey) {
        boolean currentValue = isEnabled(flagKey);
        boolean newValue = !currentValue;
        prefs.edit().putBoolean(flagKey, newValue).apply();
        LoggingHelper.d(TAG, "Feature toggled: " + flagKey + " -> " + newValue);
        return newValue;
    }
    
    /**
     * Set a feature flag value.
     * 
     * @param flagKey Feature flag key
     * @param enabled Whether the flag should be enabled
     */
    public void setEnabled(@NonNull String flagKey, boolean enabled) {
        prefs.edit().putBoolean(flagKey, enabled).apply();
        LoggingHelper.d(TAG, "Feature set: " + flagKey + " = " + enabled);
    }
    
    /**
     * Reset all flags to defaults.
     */
    public void resetToDefaults() {
        prefs.edit().clear().apply();
        initializeDefaultFlags();
        LoggingHelper.i(TAG, "All feature flags reset to defaults");
    }
    
    // Convenience methods for specific features
    
    public boolean isNewScannerEnabled() {
        return isEnabled(FLAG_NEW_SCANNER);
    }
    
    public boolean isDarkModeAutoEnabled() {
        return isEnabled(FLAG_DARK_MODE_AUTO);
    }
    
    public boolean isBackgroundScanEnabled() {
        return isEnabled(FLAG_BACKGROUND_SCAN);
    }
    
    public boolean isEnhancedLoggingEnabled() {
        return isEnabled(FLAG_ENHANCED_LOGGING);
    }
    
    public boolean isAnalyticsEnabled() {
        return isEnabled(FLAG_ANALYTICS);
    }
    
    public boolean isPerformanceMonitorEnabled() {
        return isEnabled(FLAG_PERFORMANCE_MONITOR);
    }
    
    public boolean isAdvancedExploitsEnabled() {
        return isEnabled(FLAG_ADVANCED_EXPLOITS);
    }
    
    public boolean isScheduledScansEnabled() {
        return isEnabled(FLAG_SCHEDULED_SCANS);
    }
    
    public boolean isTargetHistoryEnabled() {
        return isEnabled(FLAG_TARGET_HISTORY);
    }
    
    public boolean isOfflineModeEnabled() {
        return isEnabled(FLAG_OFFLINE_MODE);
    }
    
    /**
     * Get all flag states as a formatted string (for debugging).
     * 
     * @return Formatted flag states
     */
    @NonNull
    public String getAllFlagsString() {
        StringBuilder sb = new StringBuilder("Feature Flags:\n");
        sb.append(FLAG_NEW_SCANNER + ": ").append(isNewScannerEnabled()).append("\n");
        sb.append(FLAG_DARK_MODE_AUTO + ": ").append(isDarkModeAutoEnabled()).append("\n");
        sb.append(FLAG_BACKGROUND_SCAN + ": ").append(isBackgroundScanEnabled()).append("\n");
        sb.append(FLAG_ENHANCED_LOGGING + ": ").append(isEnhancedLoggingEnabled()).append("\n");
        sb.append(FLAG_ANALYTICS + ": ").append(isAnalyticsEnabled()).append("\n");
        sb.append(FLAG_PERFORMANCE_MONITOR + ": ").append(isPerformanceMonitorEnabled()).append("\n");
        sb.append(FLAG_ADVANCED_EXPLOITS + ": ").append(isAdvancedExploitsEnabled()).append("\n");
        sb.append(FLAG_SCHEDULED_SCANS + ": ").append(isScheduledScansEnabled()).append("\n");
        sb.append(FLAG_TARGET_HISTORY + ": ").append(isTargetHistoryEnabled()).append("\n");
        sb.append(FLAG_OFFLINE_MODE + ": ").append(isOfflineModeEnabled()).append("\n");
        return sb.toString();
    }
}
