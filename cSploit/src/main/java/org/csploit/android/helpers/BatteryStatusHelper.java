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

import android.content.BroadcastReceiver;
import org.csploit.android.helpers.LoggingHelper;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.BatteryManager;
import android.os.Build;

import java.lang.ref.WeakReference;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Helper for monitoring device battery status.
 *
 * Provides:
 * - Battery level and charging status
 * - Battery health information
 * - Low battery detection for scan management
 * - Charging state change notifications
 */
public final class BatteryStatusHelper {

    private static final String TAG = "BatteryStatusHelper";

    public static final int BATTERY_LOW_THRESHOLD = 15;
    public static final int BATTERY_CRITICAL_THRESHOLD = 5;

    private static BatteryStatusHelper sInstance;
    private WeakReference<Context> mContext;
    private BroadcastReceiver mBatteryReceiver;

    private int mBatteryLevel = -1;
    private boolean mIsCharging = false;
    private int mChargingSource = 0;
    private int mBatteryHealth = BatteryManager.BATTERY_HEALTH_UNKNOWN;
    private int mBatteryTemperature = 0;
    private int mBatteryVoltage = 0;

    private final CopyOnWriteArrayList<BatteryListener> mListeners = new CopyOnWriteArrayList<>();

    /**
     * Listener for battery status changes.
     */
    public interface BatteryListener {
        void onBatteryLevelChanged(int level, boolean isCharging);
        void onBatteryLow(int level);
        void onBatteryCritical(int level);
        void onChargingStateChanged(boolean isCharging, int source);
    }

    /**
     * Battery charging source constants.
     */
    public static class ChargingSource {
        public static final int NONE = 0;
        public static final int AC = BatteryManager.BATTERY_PLUGGED_AC;
        public static final int USB = BatteryManager.BATTERY_PLUGGED_USB;
        public static final int WIRELESS = BatteryManager.BATTERY_PLUGGED_WIRELESS;
    }

    private BatteryStatusHelper(Context context) {
        mContext = new WeakReference<>(context.getApplicationContext());
    }

    /**
     * Get the singleton instance.
     *
     * @param context Application context
     * @return BatteryStatusHelper instance
     */
    public static synchronized BatteryStatusHelper getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new BatteryStatusHelper(context);
        }
        return sInstance;
    }

    /**
     * Start monitoring battery status.
     */
    public void startMonitoring() {
        Context ctx = mContext.get();
        if (ctx == null) {
            return;
        }

        if (mBatteryReceiver != null) {
            return; // Already monitoring
        }

        mBatteryReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                handleBatteryChange(intent);
            }
        };

        IntentFilter filter = new IntentFilter();
        filter.addAction(Intent.ACTION_BATTERY_CHANGED);
        filter.addAction(Intent.ACTION_BATTERY_LOW);
        filter.addAction(Intent.ACTION_POWER_CONNECTED);
        filter.addAction(Intent.ACTION_POWER_DISCONNECTED);

        ctx.registerReceiver(mBatteryReceiver, filter);

        // Get initial battery status
        Intent batteryStatus = ctx.registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        if (batteryStatus != null) {
            handleBatteryChange(batteryStatus);
        }

        LoggingHelper.d(TAG, "Started battery monitoring");
    }

    /**
     * Stop monitoring battery status.
     */
    public void stopMonitoring() {
        Context ctx = mContext.get();
        if (ctx != null && mBatteryReceiver != null) {
            try {
                ctx.unregisterReceiver(mBatteryReceiver);
            } catch (IllegalArgumentException e) {
                // Receiver not registered
            }
            mBatteryReceiver = null;
            LoggingHelper.d(TAG, "Stopped battery monitoring");
        }
    }

    private void handleBatteryChange(Intent intent) {
        String action = intent.getAction();

        if (Intent.ACTION_BATTERY_CHANGED.equals(action)) {
            int level = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
            int scale = intent.getIntExtra(BatteryManager.EXTRA_SCALE, 100);
            int newLevel = (level * 100) / scale;

            int status = intent.getIntExtra(BatteryManager.EXTRA_STATUS, -1);
            boolean newIsCharging = status == BatteryManager.BATTERY_STATUS_CHARGING ||
                    status == BatteryManager.BATTERY_STATUS_FULL;

            int plugged = intent.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0);

            mBatteryHealth = intent.getIntExtra(BatteryManager.EXTRA_HEALTH, BatteryManager.BATTERY_HEALTH_UNKNOWN);
            mBatteryTemperature = intent.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, 0);
            mBatteryVoltage = intent.getIntExtra(BatteryManager.EXTRA_VOLTAGE, 0);

            boolean levelChanged = newLevel != mBatteryLevel;
            boolean chargingChanged = newIsCharging != mIsCharging || plugged != mChargingSource;

            mBatteryLevel = newLevel;
            mIsCharging = newIsCharging;
            mChargingSource = plugged;

            if (levelChanged) {
                notifyLevelChanged();
            }

            if (chargingChanged) {
                notifyChargingStateChanged();
            }
        }
    }

    private void notifyLevelChanged() {
        for (BatteryListener listener : mListeners) {
            listener.onBatteryLevelChanged(mBatteryLevel, mIsCharging);

            if (mBatteryLevel <= BATTERY_CRITICAL_THRESHOLD && !mIsCharging) {
                listener.onBatteryCritical(mBatteryLevel);
            } else if (mBatteryLevel <= BATTERY_LOW_THRESHOLD && !mIsCharging) {
                listener.onBatteryLow(mBatteryLevel);
            }
        }
    }

    private void notifyChargingStateChanged() {
        for (BatteryListener listener : mListeners) {
            listener.onChargingStateChanged(mIsCharging, mChargingSource);
        }
    }

    /**
     * Add a battery status listener.
     *
     * @param listener Listener to add
     */
    public void addListener(BatteryListener listener) {
        if (listener != null && !mListeners.contains(listener)) {
            mListeners.add(listener);
        }
    }

    /**
     * Remove a battery status listener.
     *
     * @param listener Listener to remove
     */
    public void removeListener(BatteryListener listener) {
        mListeners.remove(listener);
    }

    // ==================== Battery Information ====================

    /**
     * Get current battery level (0-100).
     *
     * @return Battery percentage, or -1 if unknown
     */
    public int getBatteryLevel() {
        // Get fresh value if not monitoring
        if (mBatteryLevel == -1) {
            Context ctx = mContext.get();
            if (ctx != null) {
                Intent batteryStatus = ctx.registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
                if (batteryStatus != null) {
                    int level = batteryStatus.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
                    int scale = batteryStatus.getIntExtra(BatteryManager.EXTRA_SCALE, 100);
                    mBatteryLevel = (level * 100) / scale;
                }
            }
        }
        return mBatteryLevel;
    }

    /**
     * Check if device is currently charging.
     *
     * @return True if charging
     */
    public boolean isCharging() {
        return mIsCharging;
    }

    /**
     * Get the charging source.
     *
     * @return One of ChargingSource constants
     */
    public int getChargingSource() {
        return mChargingSource;
    }

    /**
     * Get a human-readable charging source name.
     *
     * @return Charging source name
     */
    public String getChargingSourceName() {
        if (!mIsCharging) {
            return "Not charging";
        }
        switch (mChargingSource) {
            case ChargingSource.AC:
                return "AC Power";
            case ChargingSource.USB:
                return "USB";
            case ChargingSource.WIRELESS:
                return "Wireless";
            default:
                return "Unknown";
        }
    }

    /**
     * Check if battery is low.
     *
     * @return True if battery level is at or below low threshold
     */
    public boolean isBatteryLow() {
        return getBatteryLevel() <= BATTERY_LOW_THRESHOLD && !mIsCharging;
    }

    /**
     * Check if battery is critically low.
     *
     * @return True if battery level is at or below critical threshold
     */
    public boolean isBatteryCritical() {
        return getBatteryLevel() <= BATTERY_CRITICAL_THRESHOLD && !mIsCharging;
    }

    /**
     * Get battery health status.
     *
     * @return Battery health constant from BatteryManager
     */
    public int getBatteryHealth() {
        return mBatteryHealth;
    }

    /**
     * Get a human-readable battery health description.
     *
     * @return Health status string
     */
    public String getBatteryHealthString() {
        switch (mBatteryHealth) {
            case BatteryManager.BATTERY_HEALTH_GOOD:
                return "Good";
            case BatteryManager.BATTERY_HEALTH_OVERHEAT:
                return "Overheating";
            case BatteryManager.BATTERY_HEALTH_DEAD:
                return "Dead";
            case BatteryManager.BATTERY_HEALTH_OVER_VOLTAGE:
                return "Over voltage";
            case BatteryManager.BATTERY_HEALTH_COLD:
                return "Too cold";
            case BatteryManager.BATTERY_HEALTH_UNSPECIFIED_FAILURE:
                return "Failure";
            default:
                return "Unknown";
        }
    }

    /**
     * Get battery temperature in Celsius.
     *
     * @return Temperature in degrees Celsius
     */
    public float getBatteryTemperature() {
        return mBatteryTemperature / 10.0f;
    }

    /**
     * Get battery voltage in volts.
     *
     * @return Voltage in volts
     */
    public float getBatteryVoltage() {
        return mBatteryVoltage / 1000.0f;
    }

    /**
     * Check if the device can sustain intensive operations (scanning).
     * Returns true if battery is sufficient or device is charging.
     *
     * @return True if intensive operations are safe
     */
    public boolean canPerformIntensiveOperations() {
        return isCharging() || getBatteryLevel() > BATTERY_LOW_THRESHOLD;
    }

    /**
     * Get estimated remaining time based on current usage.
     * Note: This is a rough estimate and may not be accurate.
     *
     * @return Estimated minutes remaining, or -1 if unknown/charging
     */
    public long getEstimatedTimeRemaining() {
        if (mIsCharging || mBatteryLevel < 0) {
            return -1;
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            Context ctx = mContext.get();
            if (ctx != null) {
                BatteryManager batteryManager = (BatteryManager) ctx.getSystemService(Context.BATTERY_SERVICE);
                if (batteryManager != null) {
                    long remaining = batteryManager.computeChargeTimeRemaining();
                    if (remaining > 0) {
                        return remaining / 60000; // Convert to minutes
                    }
                }
            }
        }

        // Rough estimate: assume 1% = ~6 minutes at average usage
        return mBatteryLevel * 6;
    }

    /**
     * Get a summary of the current battery status.
     *
     * @return Human-readable battery status summary
     */
    public String getStatusSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("Battery: ").append(getBatteryLevel()).append("%");
        if (mIsCharging) {
            sb.append(" (").append(getChargingSourceName()).append(")");
        }
        sb.append("\nHealth: ").append(getBatteryHealthString());
        sb.append("\nTemperature: ").append(String.format("%.1f°C", getBatteryTemperature()));
        sb.append("\nVoltage: ").append(String.format("%.2fV", getBatteryVoltage()));
        return sb.toString();
    }
}
