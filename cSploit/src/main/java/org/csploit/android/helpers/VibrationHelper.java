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
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.os.VibratorManager;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresPermission;

/**
 * Helper class for device vibration.
 * Provides utilities for haptic feedback.
 */
public class VibrationHelper {
    
    // Common vibration durations
    public static final long DURATION_SHORT = 50L;
    public static final long DURATION_MEDIUM = 100L;
    public static final long DURATION_LONG = 200L;
    public static final long DURATION_CLICK = 25L;
    
    // Common vibration patterns
    public static final long[] PATTERN_SINGLE = {0, DURATION_MEDIUM};
    public static final long[] PATTERN_DOUBLE = {0, DURATION_SHORT, DURATION_SHORT, DURATION_SHORT};
    public static final long[] PATTERN_TRIPLE = {0, DURATION_SHORT, DURATION_SHORT, DURATION_SHORT, DURATION_SHORT, DURATION_SHORT};
    public static final long[] PATTERN_SUCCESS = {0, DURATION_SHORT, DURATION_MEDIUM, DURATION_LONG};
    public static final long[] PATTERN_ERROR = {0, DURATION_LONG, DURATION_SHORT, DURATION_LONG};
    public static final long[] PATTERN_WARNING = {0, DURATION_MEDIUM, DURATION_SHORT, DURATION_MEDIUM};
    
    /**
     * Get vibrator service.
     * 
     * @param context Context
     * @return Vibrator, or null if not available
     */
    @SuppressWarnings("deprecation")
    private static Vibrator getVibrator(@NonNull Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            VibratorManager vibratorManager = (VibratorManager) context.getSystemService(Context.VIBRATOR_MANAGER_SERVICE);
            return vibratorManager != null ? vibratorManager.getDefaultVibrator() : null;
        } else {
            return (Vibrator) context.getSystemService(Context.VIBRATOR_SERVICE);
        }
    }
    
    /**
     * Check if device has vibrator.
     * 
     * @param context Context
     * @return true if device has vibrator
     */
    public static boolean hasVibrator(@NonNull Context context) {
        Vibrator vibrator = getVibrator(context);
        return vibrator != null && vibrator.hasVibrator();
    }
    
    /**
     * Check if device has amplitude control (for custom intensity).
     * 
     * @param context Context
     * @return true if amplitude control is supported
     */
    public static boolean hasAmplitudeControl(@NonNull Context context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return false;
        }
        Vibrator vibrator = getVibrator(context);
        return vibrator != null && vibrator.hasAmplitudeControl();
    }
    
    /**
     * Vibrate for specified duration.
     * 
     * @param context Context
     * @param durationMs Duration in milliseconds
     */
    @RequiresPermission(android.Manifest.permission.VIBRATE)
    @SuppressWarnings("deprecation")
    public static void vibrate(@NonNull Context context, long durationMs) {
        Vibrator vibrator = getVibrator(context);
        if (vibrator == null || !vibrator.hasVibrator()) {
            return;
        }
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            vibrator.vibrate(VibrationEffect.createOneShot(durationMs, VibrationEffect.DEFAULT_AMPLITUDE));
        } else {
            vibrator.vibrate(durationMs);
        }
    }
    
    /**
     * Vibrate for specified duration with amplitude.
     * 
     * @param context Context
     * @param durationMs Duration in milliseconds
     * @param amplitude Amplitude (1-255), or VibrationEffect.DEFAULT_AMPLITUDE
     */
    @RequiresPermission(android.Manifest.permission.VIBRATE)
    @SuppressWarnings("deprecation")
    public static void vibrate(@NonNull Context context, long durationMs, int amplitude) {
        Vibrator vibrator = getVibrator(context);
        if (vibrator == null || !vibrator.hasVibrator()) {
            return;
        }
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            vibrator.vibrate(VibrationEffect.createOneShot(durationMs, amplitude));
        } else {
            vibrator.vibrate(durationMs);
        }
    }
    
    /**
     * Vibrate with pattern.
     * 
     * @param context Context
     * @param pattern Pattern (timings array)
     * @param repeat Repeat index (-1 for no repeat)
     */
    @RequiresPermission(android.Manifest.permission.VIBRATE)
    @SuppressWarnings("deprecation")
    public static void vibrate(@NonNull Context context, long[] pattern, int repeat) {
        Vibrator vibrator = getVibrator(context);
        if (vibrator == null || !vibrator.hasVibrator()) {
            return;
        }
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            vibrator.vibrate(VibrationEffect.createWaveform(pattern, repeat));
        } else {
            vibrator.vibrate(pattern, repeat);
        }
    }
    
    /**
     * Vibrate with pattern (no repeat).
     * 
     * @param context Context
     * @param pattern Pattern (timings array)
     */
    @RequiresPermission(android.Manifest.permission.VIBRATE)
    public static void vibrate(@NonNull Context context, long[] pattern) {
        vibrate(context, pattern, -1);
    }
    
    /**
     * Short vibration (click feedback).
     * 
     * @param context Context
     */
    @RequiresPermission(android.Manifest.permission.VIBRATE)
    public static void click(@NonNull Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            Vibrator vibrator = getVibrator(context);
            if (vibrator != null && vibrator.hasVibrator()) {
                vibrator.vibrate(VibrationEffect.createPredefined(VibrationEffect.EFFECT_CLICK));
                return;
            }
        }
        vibrate(context, DURATION_CLICK);
    }
    
    /**
     * Short vibration.
     * 
     * @param context Context
     */
    @RequiresPermission(android.Manifest.permission.VIBRATE)
    public static void vibrateShort(@NonNull Context context) {
        vibrate(context, DURATION_SHORT);
    }
    
    /**
     * Medium vibration.
     * 
     * @param context Context
     */
    @RequiresPermission(android.Manifest.permission.VIBRATE)
    public static void vibrateMedium(@NonNull Context context) {
        vibrate(context, DURATION_MEDIUM);
    }
    
    /**
     * Long vibration.
     * 
     * @param context Context
     */
    @RequiresPermission(android.Manifest.permission.VIBRATE)
    public static void vibrateLong(@NonNull Context context) {
        vibrate(context, DURATION_LONG);
    }
    
    /**
     * Double tap vibration.
     * 
     * @param context Context
     */
    @RequiresPermission(android.Manifest.permission.VIBRATE)
    public static void vibrateDouble(@NonNull Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            Vibrator vibrator = getVibrator(context);
            if (vibrator != null && vibrator.hasVibrator()) {
                vibrator.vibrate(VibrationEffect.createPredefined(VibrationEffect.EFFECT_DOUBLE_CLICK));
                return;
            }
        }
        vibrate(context, PATTERN_DOUBLE);
    }
    
    /**
     * Success vibration pattern.
     * 
     * @param context Context
     */
    @RequiresPermission(android.Manifest.permission.VIBRATE)
    public static void vibrateSuccess(@NonNull Context context) {
        vibrate(context, PATTERN_SUCCESS);
    }
    
    /**
     * Error vibration pattern.
     * 
     * @param context Context
     */
    @RequiresPermission(android.Manifest.permission.VIBRATE)
    public static void vibrateError(@NonNull Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            Vibrator vibrator = getVibrator(context);
            if (vibrator != null && vibrator.hasVibrator()) {
                vibrator.vibrate(VibrationEffect.createPredefined(VibrationEffect.EFFECT_HEAVY_CLICK));
                return;
            }
        }
        vibrate(context, PATTERN_ERROR);
    }
    
    /**
     * Warning vibration pattern.
     * 
     * @param context Context
     */
    @RequiresPermission(android.Manifest.permission.VIBRATE)
    public static void vibrateWarning(@NonNull Context context) {
        vibrate(context, PATTERN_WARNING);
    }
    
    /**
     * Cancel ongoing vibration.
     * 
     * @param context Context
     */
    public static void cancel(@NonNull Context context) {
        Vibrator vibrator = getVibrator(context);
        if (vibrator != null) {
            vibrator.cancel();
        }
    }
    
    private VibrationHelper() {
        // Prevent instantiation
    }
}
