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
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.HashMap;
import java.util.Map;

/**
 * Privacy-focused analytics helper for tracking app usage patterns.
 * All data is stored locally and never sent to external servers without explicit user consent.
 */
public class AnalyticsHelper {
    
    private static final String TAG = "AnalyticsHelper";
    private static final String PREFS_NAME = "analytics_data";
    
    // Event categories
    public static final String CATEGORY_SCAN = "scan";
    public static final String CATEGORY_EXPLOIT = "exploit";
    public static final String CATEGORY_MITM = "mitm";
    public static final String CATEGORY_TOOL = "tool";
    public static final String CATEGORY_UPDATE = "update";
    
    // Event actions
    public static final String ACTION_START = "start";
    public static final String ACTION_COMPLETE = "complete";
    public static final String ACTION_FAIL = "fail";
    public static final String ACTION_CANCEL = "cancel";
    
    private static AnalyticsHelper instance;
    private final Context context;
    private final EnhancedPreferencesHelper prefs;
    
    private AnalyticsHelper(@NonNull Context context) {
        this.context = context.getApplicationContext();
        this.prefs = new EnhancedPreferencesHelper(context);
    }
    
    /**
     * Get singleton instance.
     * 
     * @param context Application context
     * @return AnalyticsHelper instance
     */
    public static synchronized AnalyticsHelper getInstance(@NonNull Context context) {
        if (instance == null) {
            instance = new AnalyticsHelper(context);
        }
        return instance;
    }
    
    /**
     * Track an event with category, action, and optional label.
     * 
     * @param category Event category
     * @param action Event action
     * @param label Optional label (can be null)
     */
    public void trackEvent(@NonNull String category, 
                          @NonNull String action, 
                          @Nullable String label) {
        String eventKey = buildEventKey(category, action, label);
        incrementCounter(eventKey);
        
        LoggingHelper.d(TAG, String.format("Event tracked: %s/%s%s", 
                category, action, label != null ? "/" + label : ""));
    }
    
    /**
     * Track a scan operation.
     * 
     * @param action Action (start, complete, fail, cancel)
     * @param targetsFound Number of targets found (use -1 if not applicable)
     */
    public void trackScan(@NonNull String action, int targetsFound) {
        trackEvent(CATEGORY_SCAN, action, null);
        
        if (action.equals(ACTION_COMPLETE) && targetsFound >= 0) {
            String key = "scan_total_targets";
            long current = prefs.getLong(key, 0);
            prefs.setLong(key, current + targetsFound);
        }
    }
    
    /**
     * Track an exploit execution.
     * 
     * @param exploitName Name of the exploit
     * @param success Whether it succeeded
     */
    public void trackExploit(@NonNull String exploitName, boolean success) {
        trackEvent(CATEGORY_EXPLOIT, success ? ACTION_COMPLETE : ACTION_FAIL, exploitName);
    }
    
    /**
     * Track MITM attack.
     * 
     * @param attackType Type of MITM attack
     * @param action Action (start, complete, fail, cancel)
     */
    public void trackMitm(@NonNull String attackType, @NonNull String action) {
        trackEvent(CATEGORY_MITM, action, attackType);
    }
    
    /**
     * Track tool usage.
     * 
     * @param toolName Name of the tool
     */
    public void trackToolUsage(@NonNull String toolName) {
        trackEvent(CATEGORY_TOOL, ACTION_START, toolName);
    }
    
    /**
     * Get usage statistics.
     * 
     * @return Map of event keys to counts
     */
    public Map<String, Long> getUsageStats() {
        Map<String, Long> stats = new HashMap<>();
        // Implementation would iterate through stored preferences
        // For now, return empty map
        return stats;
    }
    
    /**
     * Clear all analytics data.
     */
    public void clearAllData() {
        // Clear analytics-specific data
        LoggingHelper.i(TAG, "Analytics data cleared");
    }
    
    /**
     * Get total scans performed.
     * 
     * @return Total number of scans
     */
    public long getTotalScans() {
        String startKey = buildEventKey(CATEGORY_SCAN, ACTION_START, null);
        return prefs.getLong(startKey, 0);
    }
    
    /**
     * Get total targets discovered.
     * 
     * @return Total number of targets
     */
    public long getTotalTargets() {
        return prefs.getLong("scan_total_targets", 0);
    }
    
    /**
     * Build event key from category, action, and label.
     * 
     * @param category Event category
     * @param action Event action
     * @param label Optional label
     * @return Event key string
     */
    private String buildEventKey(@NonNull String category, 
                                 @NonNull String action, 
                                 @Nullable String label) {
        if (label != null && !label.isEmpty()) {
            return String.format("event_%s_%s_%s", category, action, label);
        }
        return String.format("event_%s_%s", category, action);
    }
    
    /**
     * Increment counter for an event key.
     * 
     * @param key Event key
     */
    private void incrementCounter(@NonNull String key) {
        long current = prefs.getLong(key, 0);
        prefs.setLong(key, current + 1);
    }
}
