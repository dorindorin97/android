/*
 * This file is part of the cSploit.
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

import org.csploit.android.net.Target;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Helper for tracking and persisting target history.
 *
 * Provides:
 * - History of discovered targets across sessions
 * - Target metadata persistence (OS, services, vulnerabilities)
 * - First/last seen timestamps
 * - Target change detection
 */
public final class TargetHistoryHelper {

    private static final String TAG = "TargetHistoryHelper";
    private static final String PREFS_NAME = "target_history_prefs";
    private static final String KEY_HISTORY = "target_history";
    private static final int MAX_HISTORY_SIZE = 500;

    private static TargetHistoryHelper sInstance;
    private WeakReference<Context> mContext;
    private List<HistoryEntry> mHistory;

    /**
     * Represents a historical target entry.
     */
    public static class HistoryEntry {
        public final String ipAddress;
        public final String macAddress;
        public final String hostname;
        public final String alias;
        public final String deviceType;
        public final String deviceOS;
        public final int openPortCount;
        public final long firstSeen;
        public final long lastSeen;
        public final int timesDiscovered;

        private HistoryEntry(Builder builder) {
            this.ipAddress = builder.ipAddress;
            this.macAddress = builder.macAddress;
            this.hostname = builder.hostname;
            this.alias = builder.alias;
            this.deviceType = builder.deviceType;
            this.deviceOS = builder.deviceOS;
            this.openPortCount = builder.openPortCount;
            this.firstSeen = builder.firstSeen;
            this.lastSeen = builder.lastSeen;
            this.timesDiscovered = builder.timesDiscovered;
        }

        public JSONObject toJson() throws JSONException {
            JSONObject obj = new JSONObject();
            obj.put("ip", ipAddress);
            obj.put("mac", macAddress);
            obj.put("hostname", hostname);
            obj.put("alias", alias);
            obj.put("deviceType", deviceType);
            obj.put("deviceOS", deviceOS);
            obj.put("ports", openPortCount);
            obj.put("firstSeen", firstSeen);
            obj.put("lastSeen", lastSeen);
            obj.put("times", timesDiscovered);
            return obj;
        }

        public static HistoryEntry fromJson(JSONObject obj) throws JSONException {
            return new Builder()
                    .ipAddress(obj.optString("ip", ""))
                    .macAddress(obj.optString("mac", ""))
                    .hostname(obj.optString("hostname", ""))
                    .alias(obj.optString("alias", ""))
                    .deviceType(obj.optString("deviceType", ""))
                    .deviceOS(obj.optString("deviceOS", ""))
                    .openPortCount(obj.optInt("ports", 0))
                    .firstSeen(obj.optLong("firstSeen", 0))
                    .lastSeen(obj.optLong("lastSeen", 0))
                    .timesDiscovered(obj.optInt("times", 1))
                    .build();
        }

        public static class Builder {
            private String ipAddress = "";
            private String macAddress = "";
            private String hostname = "";
            private String alias = "";
            private String deviceType = "";
            private String deviceOS = "";
            private int openPortCount = 0;
            private long firstSeen = 0;
            private long lastSeen = 0;
            private int timesDiscovered = 1;

            public Builder ipAddress(String ip) { this.ipAddress = ip; return this; }
            public Builder macAddress(String mac) { this.macAddress = mac; return this; }
            public Builder hostname(String host) { this.hostname = host; return this; }
            public Builder alias(String alias) { this.alias = alias; return this; }
            public Builder deviceType(String type) { this.deviceType = type; return this; }
            public Builder deviceOS(String os) { this.deviceOS = os; return this; }
            public Builder openPortCount(int count) { this.openPortCount = count; return this; }
            public Builder firstSeen(long time) { this.firstSeen = time; return this; }
            public Builder lastSeen(long time) { this.lastSeen = time; return this; }
            public Builder timesDiscovered(int times) { this.timesDiscovered = times; return this; }

            public HistoryEntry build() {
                return new HistoryEntry(this);
            }
        }
    }

    private TargetHistoryHelper(Context context) {
        mContext = new WeakReference<>(context.getApplicationContext());
        mHistory = new ArrayList<>();
        loadHistory();
    }

    /**
     * Get the singleton instance.
     *
     * @param context Application context
     * @return TargetHistoryHelper instance
     */
    public static synchronized TargetHistoryHelper getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new TargetHistoryHelper(context);
        }
        return sInstance;
    }

    /**
     * Record a target in history.
     *
     * @param target Target to record
     */
    public synchronized void recordTarget(Target target) {
        if (target == null) {
            return;
        }

        String ipAddress = target.getAddress() != null ? target.getAddress().getHostAddress() : "";
        if (ipAddress.isEmpty()) {
            return;
        }

        long now = java.lang.System.currentTimeMillis();

        // Check if target exists in history
        HistoryEntry existing = findByIp(ipAddress);
        if (existing != null) {
            // Update existing entry
            HistoryEntry updated = new HistoryEntry.Builder()
                    .ipAddress(ipAddress)
                    .macAddress(getMacFromTarget(target))
                    .hostname(target.getHostname() != null ? target.getHostname() : existing.hostname)
                    .alias(target.getAlias() != null ? target.getAlias() : existing.alias)
                    .deviceType(target.getDeviceType() != null ? target.getDeviceType() : existing.deviceType)
                    .deviceOS(target.getDeviceOS() != null ? target.getDeviceOS() : existing.deviceOS)
                    .openPortCount(target.getOpenPorts().size())
                    .firstSeen(existing.firstSeen)
                    .lastSeen(now)
                    .timesDiscovered(existing.timesDiscovered + 1)
                    .build();

            mHistory.remove(existing);
            mHistory.add(0, updated);
        } else {
            // Add new entry
            HistoryEntry entry = new HistoryEntry.Builder()
                    .ipAddress(ipAddress)
                    .macAddress(getMacFromTarget(target))
                    .hostname(target.getHostname() != null ? target.getHostname() : "")
                    .alias(target.getAlias() != null ? target.getAlias() : "")
                    .deviceType(target.getDeviceType() != null ? target.getDeviceType() : "")
                    .deviceOS(target.getDeviceOS() != null ? target.getDeviceOS() : "")
                    .openPortCount(target.getOpenPorts().size())
                    .firstSeen(now)
                    .lastSeen(now)
                    .timesDiscovered(1)
                    .build();

            mHistory.add(0, entry);

            // Trim history if too large
            while (mHistory.size() > MAX_HISTORY_SIZE) {
                mHistory.remove(mHistory.size() - 1);
            }
        }

        saveHistory();
    }

    private String getMacFromTarget(Target target) {
        byte[] hw = target.getHardwareAddress();
        if (hw != null && hw.length >= 6) {
            return String.format("%02X:%02X:%02X:%02X:%02X:%02X",
                    hw[0], hw[1], hw[2], hw[3], hw[4], hw[5]);
        }
        return "";
    }

    /**
     * Get all history entries.
     *
     * @return Unmodifiable list of history entries
     */
    public List<HistoryEntry> getHistory() {
        return Collections.unmodifiableList(mHistory);
    }

    /**
     * Get recently seen targets (last 24 hours).
     *
     * @return List of recent entries
     */
    public List<HistoryEntry> getRecentTargets() {
        long cutoff = java.lang.System.currentTimeMillis() - (24 * 60 * 60 * 1000);
        List<HistoryEntry> recent = new ArrayList<>();
        for (HistoryEntry entry : mHistory) {
            if (entry.lastSeen >= cutoff) {
                recent.add(entry);
            }
        }
        return recent;
    }

    /**
     * Get frequently discovered targets.
     *
     * @param minTimes Minimum number of times discovered
     * @return List of frequent entries
     */
    public List<HistoryEntry> getFrequentTargets(int minTimes) {
        List<HistoryEntry> frequent = new ArrayList<>();
        for (HistoryEntry entry : mHistory) {
            if (entry.timesDiscovered >= minTimes) {
                frequent.add(entry);
            }
        }
        return frequent;
    }

    /**
     * Find a history entry by IP address.
     *
     * @param ip IP address to search for
     * @return HistoryEntry or null if not found
     */
    public HistoryEntry findByIp(String ip) {
        for (HistoryEntry entry : mHistory) {
            if (entry.ipAddress.equals(ip)) {
                return entry;
            }
        }
        return null;
    }

    /**
     * Find a history entry by MAC address.
     *
     * @param mac MAC address to search for
     * @return HistoryEntry or null if not found
     */
    public HistoryEntry findByMac(String mac) {
        for (HistoryEntry entry : mHistory) {
            if (entry.macAddress.equals(mac)) {
                return entry;
            }
        }
        return null;
    }

    /**
     * Search history by keyword (matches IP, hostname, alias, OS).
     *
     * @param keyword Keyword to search for
     * @return List of matching entries
     */
    public List<HistoryEntry> search(String keyword) {
        if (keyword == null || keyword.isEmpty()) {
            return new ArrayList<>(mHistory);
        }

        String lowerKeyword = keyword.toLowerCase();
        List<HistoryEntry> results = new ArrayList<>();

        for (HistoryEntry entry : mHistory) {
            if (entry.ipAddress.toLowerCase().contains(lowerKeyword) ||
                    entry.hostname.toLowerCase().contains(lowerKeyword) ||
                    entry.alias.toLowerCase().contains(lowerKeyword) ||
                    entry.deviceOS.toLowerCase().contains(lowerKeyword) ||
                    entry.deviceType.toLowerCase().contains(lowerKeyword)) {
                results.add(entry);
            }
        }

        return results;
    }

    /**
     * Get the total number of unique targets ever discovered.
     *
     * @return Total unique targets
     */
    public int getTotalUniqueTargets() {
        return mHistory.size();
    }

    /**
     * Clear all history.
     */
    public synchronized void clearHistory() {
        mHistory.clear();
        saveHistory();
    }

    /**
     * Remove a specific entry from history.
     *
     * @param ip IP address to remove
     */
    public synchronized void removeEntry(String ip) {
        HistoryEntry entry = findByIp(ip);
        if (entry != null) {
            mHistory.remove(entry);
            saveHistory();
        }
    }

    private void loadHistory() {
        SharedPreferences prefs = getPrefs();
        if (prefs == null) {
            return;
        }

        String json = prefs.getString(KEY_HISTORY, "[]");
        try {
            JSONArray array = new JSONArray(json);
            mHistory.clear();
            for (int i = 0; i < array.length(); i++) {
                HistoryEntry entry = HistoryEntry.fromJson(array.getJSONObject(i));
                mHistory.add(entry);
            }
            LoggingHelper.d(TAG, "Loaded " + mHistory.size() + " history entries");
        } catch (JSONException e) {
            LoggingHelper.e(TAG, "Failed to load history", e);
        }
    }

    private void saveHistory() {
        SharedPreferences prefs = getPrefs();
        if (prefs == null) {
            return;
        }

        try {
            JSONArray array = new JSONArray();
            for (HistoryEntry entry : mHistory) {
                array.put(entry.toJson());
            }
            prefs.edit().putString(KEY_HISTORY, array.toString()).apply();
        } catch (JSONException e) {
            LoggingHelper.e(TAG, "Failed to save history", e);
        }
    }

    private SharedPreferences getPrefs() {
        Context ctx = mContext.get();
        return ctx != null ? ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE) : null;
    }

    /**
     * Export history to JSON string.
     *
     * @return JSON string of history
     */
    public String exportToJson() {
        try {
            JSONArray array = new JSONArray();
            for (HistoryEntry entry : mHistory) {
                array.put(entry.toJson());
            }
            return array.toString(2);
        } catch (JSONException e) {
            LoggingHelper.e(TAG, "Failed to export history", e);
            return "[]";
        }
    }
}
