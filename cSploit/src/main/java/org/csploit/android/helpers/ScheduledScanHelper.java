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
import android.content.SharedPreferences;

import org.csploit.android.core.System;

import java.lang.ref.WeakReference;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Helper for scheduling and managing periodic network scans.
 *
 * Provides:
 * - Periodic network scanning with configurable intervals
 * - Scan pause/resume functionality
 * - Battery-aware scanning options
 * - Scan history and statistics
 */
public final class ScheduledScanHelper {

    private static final String TAG = "ScheduledScanHelper";
    private static final String PREFS_NAME = "scheduled_scan_prefs";
    private static final String KEY_SCAN_INTERVAL = "scan_interval_minutes";
    private static final String KEY_SCAN_ENABLED = "scheduled_scan_enabled";
    private static final String KEY_LAST_SCAN_TIME = "last_scan_time";
    private static final String KEY_TOTAL_SCANS = "total_scheduled_scans";
    private static final String KEY_BATTERY_AWARE = "battery_aware_scanning";

    private static final int DEFAULT_SCAN_INTERVAL = 15; // minutes
    private static final int MIN_SCAN_INTERVAL = 1;
    private static final int MAX_SCAN_INTERVAL = 1440; // 24 hours

    private static ScheduledScanHelper sInstance;
    private WeakReference<Context> mContext;
    private ScheduledFuture<?> mScheduledScan;
    private final AtomicBoolean mIsScanning = new AtomicBoolean(false);
    private ScanCallback mCallback;

    /**
     * Callback interface for scan events.
     */
    public interface ScanCallback {
        void onScanStarted();
        void onScanCompleted(int targetsFound);
        void onScanFailed(String reason);
        void onScanSkipped(String reason);
    }

    private ScheduledScanHelper(Context context) {
        mContext = new WeakReference<>(context.getApplicationContext());
    }

    /**
     * Get the singleton instance.
     *
     * @param context Application context
     * @return ScheduledScanHelper instance
     */
    public static synchronized ScheduledScanHelper getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new ScheduledScanHelper(context);
        }
        return sInstance;
    }

    /**
     * Set the callback for scan events.
     *
     * @param callback Callback instance
     */
    public void setCallback(ScanCallback callback) {
        mCallback = callback;
    }

    /**
     * Start scheduled scanning with the configured interval.
     */
    public void startScheduledScanning() {
        if (mScheduledScan != null && !mScheduledScan.isCancelled()) {
            LoggingHelper.d(TAG, "Scheduled scanning already running");
            return;
        }

        int intervalMinutes = getScanInterval();
        setScheduledScanEnabled(true);

        mScheduledScan = ThreadHelper.scheduleAtFixedRate(
                this::performScheduledScan,
                intervalMinutes,
                intervalMinutes,
                TimeUnit.MINUTES
        );

        LoggingHelper.i(TAG, "Started scheduled scanning every " + intervalMinutes + " minutes");
    }

    /**
     * Stop scheduled scanning.
     */
    public void stopScheduledScanning() {
        if (mScheduledScan != null) {
            mScheduledScan.cancel(false);
            mScheduledScan = null;
        }
        setScheduledScanEnabled(false);
        LoggingHelper.i(TAG, "Stopped scheduled scanning");
    }

    /**
     * Pause scheduled scanning temporarily.
     */
    public void pauseScheduledScanning() {
        if (mScheduledScan != null) {
            mScheduledScan.cancel(false);
            mScheduledScan = null;
        }
        LoggingHelper.d(TAG, "Paused scheduled scanning");
    }

    /**
     * Resume scheduled scanning.
     */
    public void resumeScheduledScanning() {
        if (isScheduledScanEnabled()) {
            startScheduledScanning();
            LoggingHelper.d(TAG, "Resumed scheduled scanning");
        }
    }

    /**
     * Perform a single scheduled scan.
     */
    private void performScheduledScan() {
        if (mIsScanning.get()) {
            notifySkipped("Scan already in progress");
            return;
        }

        // Check battery-aware settings
        if (isBatteryAwareEnabled()) {
            Context ctx = mContext.get();
            if (ctx != null) {
                BatteryStatusHelper batteryHelper = BatteryStatusHelper.getInstance(ctx);
                if (batteryHelper.getBatteryLevel() < 20 && !batteryHelper.isCharging()) {
                    notifySkipped("Battery too low");
                    return;
                }
            }
        }

        mIsScanning.set(true);

        if (mCallback != null) {
            ThreadHelper.runOnMainThread(() -> mCallback.onScanStarted());
        }

        try {
            // The actual scan will be handled by the network radar service
            org.csploit.android.services.Services.getNetworkRadar().start();

            // Update statistics
            updateScanStats();

            int targetCount = System.getTargets().size();
            if (mCallback != null) {
                final int count = targetCount;
                ThreadHelper.runOnMainThread(() -> mCallback.onScanCompleted(count));
            }

        } catch (Exception e) {
            LoggingHelper.e(TAG, "Scheduled scan failed", e);
            if (mCallback != null) {
                ThreadHelper.runOnMainThread(() -> mCallback.onScanFailed(e.getMessage()));
            }
        } finally {
            mIsScanning.set(false);
        }
    }

    private void notifySkipped(String reason) {
        LoggingHelper.d(TAG, "Scan skipped: " + reason);
        if (mCallback != null) {
            ThreadHelper.runOnMainThread(() -> mCallback.onScanSkipped(reason));
        }
    }

    private void updateScanStats() {
        SharedPreferences prefs = getPrefs();
        if (prefs != null) {
            SharedPreferences.Editor editor = prefs.edit();
            editor.putLong(KEY_LAST_SCAN_TIME, java.lang.System.currentTimeMillis());
            editor.putInt(KEY_TOTAL_SCANS, getTotalScans() + 1);
            editor.apply();
        }
    }

    // ==================== Configuration ====================

    /**
     * Set the scan interval in minutes.
     *
     * @param minutes Interval in minutes (1-1440)
     */
    public void setScanInterval(int minutes) {
        int interval = Math.max(MIN_SCAN_INTERVAL, Math.min(MAX_SCAN_INTERVAL, minutes));
        SharedPreferences prefs = getPrefs();
        if (prefs != null) {
            prefs.edit().putInt(KEY_SCAN_INTERVAL, interval).apply();
        }

        // Restart scanning with new interval if currently running
        if (isScheduledScanEnabled() && mScheduledScan != null) {
            stopScheduledScanning();
            startScheduledScanning();
        }
    }

    /**
     * Get the configured scan interval.
     *
     * @return Interval in minutes
     */
    public int getScanInterval() {
        SharedPreferences prefs = getPrefs();
        return prefs != null ? prefs.getInt(KEY_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL) : DEFAULT_SCAN_INTERVAL;
    }

    /**
     * Check if scheduled scanning is enabled.
     *
     * @return True if enabled
     */
    public boolean isScheduledScanEnabled() {
        SharedPreferences prefs = getPrefs();
        return prefs != null && prefs.getBoolean(KEY_SCAN_ENABLED, false);
    }

    private void setScheduledScanEnabled(boolean enabled) {
        SharedPreferences prefs = getPrefs();
        if (prefs != null) {
            prefs.edit().putBoolean(KEY_SCAN_ENABLED, enabled).apply();
        }
    }

    /**
     * Enable or disable battery-aware scanning.
     *
     * @param enabled True to enable
     */
    public void setBatteryAwareEnabled(boolean enabled) {
        SharedPreferences prefs = getPrefs();
        if (prefs != null) {
            prefs.edit().putBoolean(KEY_BATTERY_AWARE, enabled).apply();
        }
    }

    /**
     * Check if battery-aware scanning is enabled.
     *
     * @return True if enabled
     */
    public boolean isBatteryAwareEnabled() {
        SharedPreferences prefs = getPrefs();
        return prefs != null && prefs.getBoolean(KEY_BATTERY_AWARE, true);
    }

    // ==================== Statistics ====================

    /**
     * Get the last scan timestamp.
     *
     * @return Timestamp in milliseconds, or 0 if never scanned
     */
    public long getLastScanTime() {
        SharedPreferences prefs = getPrefs();
        return prefs != null ? prefs.getLong(KEY_LAST_SCAN_TIME, 0) : 0;
    }

    /**
     * Get the total number of scheduled scans performed.
     *
     * @return Total scan count
     */
    public int getTotalScans() {
        SharedPreferences prefs = getPrefs();
        return prefs != null ? prefs.getInt(KEY_TOTAL_SCANS, 0) : 0;
    }

    /**
     * Get time until next scheduled scan.
     *
     * @return Milliseconds until next scan, or -1 if not scheduled
     */
    public long getTimeUntilNextScan() {
        if (mScheduledScan == null || mScheduledScan.isCancelled()) {
            return -1;
        }
        return mScheduledScan.getDelay(TimeUnit.MILLISECONDS);
    }

    /**
     * Check if a scan is currently in progress.
     *
     * @return True if scanning
     */
    public boolean isScanning() {
        return mIsScanning.get();
    }

    /**
     * Reset all scan statistics.
     */
    public void resetStatistics() {
        SharedPreferences prefs = getPrefs();
        if (prefs != null) {
            SharedPreferences.Editor editor = prefs.edit();
            editor.putLong(KEY_LAST_SCAN_TIME, 0);
            editor.putInt(KEY_TOTAL_SCANS, 0);
            editor.apply();
        }
    }

    private SharedPreferences getPrefs() {
        Context ctx = mContext.get();
        return ctx != null ? ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE) : null;
    }
}
