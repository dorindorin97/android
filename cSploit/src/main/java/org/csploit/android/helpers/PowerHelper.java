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
import android.os.Build;
import android.os.PowerManager;
import android.os.BatteryManager;
import android.content.Intent;
import android.content.IntentFilter;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

/**
 * Helper class for managing power and battery-related operations.
 * Provides utilities for battery monitoring and power management.
 */
public class PowerHelper {
    
    private static final String TAG = "PowerHelper";
    
    // Battery thresholds
    public static final int BATTERY_LOW_THRESHOLD = 15;
    public static final int BATTERY_CRITICAL_THRESHOLD = 5;
    public static final int BATTERY_GOOD_THRESHOLD = 50;
    
    /**
     * Battery status enum
     */
    public enum BatteryStatus {
        UNKNOWN,
        CHARGING,
        DISCHARGING,
        FULL,
        NOT_CHARGING
    }
    
    /**
     * Get current battery percentage.
     * 
     * @param context Application context
     * @return Battery percentage (0-100), or -1 if unavailable
     */
    public static int getBatteryPercentage(@NonNull Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            BatteryManager bm = (BatteryManager) context.getSystemService(Context.BATTERY_SERVICE);
            if (bm != null) {
                return bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY);
            }
        }
        
        // Fallback for older versions
        Intent batteryIntent = context.registerReceiver(null, 
                new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        
        if (batteryIntent == null) {
            return -1;
        }
        
        int level = batteryIntent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
        int scale = batteryIntent.getIntExtra(BatteryManager.EXTRA_SCALE, -1);
        
        if (level < 0 || scale <= 0) {
            return -1;
        }
        
        return (int) ((level / (float) scale) * 100);
    }
    
    /**
     * Get current battery status.
     * 
     * @param context Application context
     * @return BatteryStatus enum value
     */
    @NonNull
    public static BatteryStatus getBatteryStatus(@NonNull Context context) {
        Intent batteryIntent = context.registerReceiver(null, 
                new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        
        if (batteryIntent == null) {
            return BatteryStatus.UNKNOWN;
        }
        
        int status = batteryIntent.getIntExtra(BatteryManager.EXTRA_STATUS, 
                BatteryManager.BATTERY_STATUS_UNKNOWN);
        
        switch (status) {
            case BatteryManager.BATTERY_STATUS_CHARGING:
                return BatteryStatus.CHARGING;
            case BatteryManager.BATTERY_STATUS_DISCHARGING:
                return BatteryStatus.DISCHARGING;
            case BatteryManager.BATTERY_STATUS_FULL:
                return BatteryStatus.FULL;
            case BatteryManager.BATTERY_STATUS_NOT_CHARGING:
                return BatteryStatus.NOT_CHARGING;
            default:
                return BatteryStatus.UNKNOWN;
        }
    }
    
    /**
     * Check if device is currently charging.
     * 
     * @param context Application context
     * @return true if charging
     */
    public static boolean isCharging(@NonNull Context context) {
        BatteryStatus status = getBatteryStatus(context);
        return status == BatteryStatus.CHARGING || status == BatteryStatus.FULL;
    }
    
    /**
     * Check if battery is low.
     * 
     * @param context Application context
     * @return true if battery is below low threshold
     */
    public static boolean isBatteryLow(@NonNull Context context) {
        int percentage = getBatteryPercentage(context);
        return percentage >= 0 && percentage <= BATTERY_LOW_THRESHOLD;
    }
    
    /**
     * Check if battery is critically low.
     * 
     * @param context Application context
     * @return true if battery is critically low
     */
    public static boolean isBatteryCritical(@NonNull Context context) {
        int percentage = getBatteryPercentage(context);
        return percentage >= 0 && percentage <= BATTERY_CRITICAL_THRESHOLD;
    }
    
    /**
     * Get battery temperature in Celsius.
     * 
     * @param context Application context
     * @return Temperature in Celsius, or Float.NaN if unavailable
     */
    public static float getBatteryTemperature(@NonNull Context context) {
        Intent batteryIntent = context.registerReceiver(null, 
                new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        
        if (batteryIntent == null) {
            return Float.NaN;
        }
        
        int temp = batteryIntent.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, Integer.MIN_VALUE);
        
        if (temp == Integer.MIN_VALUE) {
            return Float.NaN;
        }
        
        return temp / 10.0f;
    }
    
    /**
     * Get battery voltage in volts.
     * 
     * @param context Application context
     * @return Voltage in volts, or Float.NaN if unavailable
     */
    public static float getBatteryVoltage(@NonNull Context context) {
        Intent batteryIntent = context.registerReceiver(null, 
                new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        
        if (batteryIntent == null) {
            return Float.NaN;
        }
        
        int voltage = batteryIntent.getIntExtra(BatteryManager.EXTRA_VOLTAGE, Integer.MIN_VALUE);
        
        if (voltage == Integer.MIN_VALUE) {
            return Float.NaN;
        }
        
        return voltage / 1000.0f;
    }
    
    /**
     * Check if device is in power save mode.
     * 
     * @param context Application context
     * @return true if in power save mode
     */
    public static boolean isPowerSaveMode(@NonNull Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            PowerManager pm = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
            if (pm != null) {
                return pm.isPowerSaveMode();
            }
        }
        return false;
    }
    
    /**
     * Check if screen is on.
     * 
     * @param context Application context
     * @return true if screen is on
     */
    public static boolean isScreenOn(@NonNull Context context) {
        PowerManager pm = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
        if (pm == null) {
            return true; // Assume on if can't determine
        }
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT_WATCH) {
            return pm.isInteractive();
        } else {
            return pm.isScreenOn();
        }
    }
    
    /**
     * Check if app is ignoring battery optimizations.
     * 
     * @param context Application context
     * @return true if ignoring battery optimizations
     */
    public static boolean isIgnoringBatteryOptimizations(@NonNull Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            PowerManager pm = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
            if (pm != null) {
                return pm.isIgnoringBatteryOptimizations(context.getPackageName());
            }
        }
        return true; // Assume yes for older versions
    }
    
    /**
     * Get battery health status.
     * 
     * @param context Application context
     * @return Health status string
     */
    @NonNull
    public static String getBatteryHealth(@NonNull Context context) {
        Intent batteryIntent = context.registerReceiver(null, 
                new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        
        if (batteryIntent == null) {
            return "Unknown";
        }
        
        int health = batteryIntent.getIntExtra(BatteryManager.EXTRA_HEALTH, 
                BatteryManager.BATTERY_HEALTH_UNKNOWN);
        
        switch (health) {
            case BatteryManager.BATTERY_HEALTH_GOOD:
                return "Good";
            case BatteryManager.BATTERY_HEALTH_OVERHEAT:
                return "Overheat";
            case BatteryManager.BATTERY_HEALTH_DEAD:
                return "Dead";
            case BatteryManager.BATTERY_HEALTH_OVER_VOLTAGE:
                return "Over Voltage";
            case BatteryManager.BATTERY_HEALTH_COLD:
                return "Cold";
            case BatteryManager.BATTERY_HEALTH_UNSPECIFIED_FAILURE:
                return "Failure";
            default:
                return "Unknown";
        }
    }
    
    /**
     * Get charging type.
     * 
     * @param context Application context
     * @return Charging type string (AC, USB, Wireless, None)
     */
    @NonNull
    public static String getChargingType(@NonNull Context context) {
        Intent batteryIntent = context.registerReceiver(null, 
                new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        
        if (batteryIntent == null) {
            return "Unknown";
        }
        
        int plugged = batteryIntent.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1);
        
        switch (plugged) {
            case BatteryManager.BATTERY_PLUGGED_AC:
                return "AC";
            case BatteryManager.BATTERY_PLUGGED_USB:
                return "USB";
            case BatteryManager.BATTERY_PLUGGED_WIRELESS:
                return "Wireless";
            case 0:
                return "None";
            default:
                return "Unknown";
        }
    }
    
    /**
     * Get comprehensive battery info string.
     * 
     * @param context Application context
     * @return Formatted battery info
     */
    @NonNull
    public static String getBatteryInfoString(@NonNull Context context) {
        StringBuilder sb = new StringBuilder();
        sb.append("Battery: ").append(getBatteryPercentage(context)).append("%\n");
        sb.append("Status: ").append(getBatteryStatus(context)).append("\n");
        sb.append("Health: ").append(getBatteryHealth(context)).append("\n");
        sb.append("Temperature: ").append(String.format("%.1f°C", getBatteryTemperature(context))).append("\n");
        sb.append("Voltage: ").append(String.format("%.2fV", getBatteryVoltage(context))).append("\n");
        sb.append("Charging: ").append(getChargingType(context)).append("\n");
        sb.append("Power Save: ").append(isPowerSaveMode(context)).append("\n");
        return sb.toString();
    }
    
    /**
     * Check if safe to perform intensive operations.
     * Returns true if battery is good and not in power save mode.
     * 
     * @param context Application context
     * @return true if safe to proceed
     */
    public static boolean isSafeForIntensiveOperation(@NonNull Context context) {
        if (isCharging(context)) {
            return true;
        }
        
        int battery = getBatteryPercentage(context);
        if (battery >= 0 && battery < BATTERY_LOW_THRESHOLD) {
            return false;
        }
        
        if (isPowerSaveMode(context)) {
            return false;
        }
        
        return true;
    }
    
    private PowerHelper() {
        // Prevent instantiation
    }
}
