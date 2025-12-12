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

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.graphics.Color;
import android.os.Build;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;

import androidx.annotation.ColorInt;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatDelegate;

import org.csploit.android.R;

/**
 * Theme management helper for cSploit.
 *
 * Provides:
 * - Dark/Light mode switching
 * - System theme following
 * - Theme preference persistence
 * - Status bar styling
 * - Dynamic color utilities
 */
public final class ThemeHelper {

    private static final String TAG = "ThemeHelper";
    private static final String PREFS_NAME = "THEME";
    private static final String KEY_IS_DARK = "isDark";
    private static final String KEY_FOLLOW_SYSTEM = "followSystem";
    private static final String KEY_ACCENT_COLOR = "accentColor";

    public enum ThemeMode {
        LIGHT,
        DARK,
        FOLLOW_SYSTEM
    }

    private ThemeHelper() {}

    // ==================== Theme Mode Management ====================

    /**
     * Get current theme mode setting
     */
    public static ThemeMode getThemeMode(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        boolean followSystem = prefs.getBoolean(KEY_FOLLOW_SYSTEM, false);
        if (followSystem) {
            return ThemeMode.FOLLOW_SYSTEM;
        }
        boolean isDark = prefs.getBoolean(KEY_IS_DARK, false);
        return isDark ? ThemeMode.DARK : ThemeMode.LIGHT;
    }

    /**
     * Set theme mode
     */
    public static void setThemeMode(Context context, ThemeMode mode) {
        SharedPreferences.Editor editor = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit();

        switch (mode) {
            case DARK:
                editor.putBoolean(KEY_IS_DARK, true);
                editor.putBoolean(KEY_FOLLOW_SYSTEM, false);
                AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_YES);
                break;
            case LIGHT:
                editor.putBoolean(KEY_IS_DARK, false);
                editor.putBoolean(KEY_FOLLOW_SYSTEM, false);
                AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_NO);
                break;
            case FOLLOW_SYSTEM:
                editor.putBoolean(KEY_FOLLOW_SYSTEM, true);
                AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM);
                break;
        }
        editor.apply();
    }

    /**
     * Check if dark mode is currently active
     */
    public static boolean isDarkMode(Context context) {
        ThemeMode mode = getThemeMode(context);
        if (mode == ThemeMode.FOLLOW_SYSTEM) {
            return isSystemDarkMode(context);
        }
        return mode == ThemeMode.DARK;
    }

    /**
     * Check if system dark mode is enabled
     */
    public static boolean isSystemDarkMode(Context context) {
        int nightMode = context.getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK;
        return nightMode == Configuration.UI_MODE_NIGHT_YES;
    }

    /**
     * Toggle between dark and light mode
     */
    public static void toggleDarkMode(Context context) {
        if (isDarkMode(context)) {
            setThemeMode(context, ThemeMode.LIGHT);
        } else {
            setThemeMode(context, ThemeMode.DARK);
        }
    }

    // ==================== Activity Theme Application ====================

    /**
     * Apply theme to activity (call before setContentView)
     */
    public static void applyTheme(Activity activity) {
        if (isDarkMode(activity)) {
            activity.setTheme(R.style.DarkTheme);
        } else {
            activity.setTheme(R.style.AppTheme);
        }
    }

    /**
     * Get the appropriate theme resource ID
     */
    public static int getThemeResId(Context context) {
        return isDarkMode(context) ? R.style.DarkTheme : R.style.AppTheme;
    }

    // ==================== Status Bar Styling ====================

    /**
     * Style the status bar based on current theme
     */
    public static void styleStatusBar(Activity activity) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Window window = activity.getWindow();
            View decorView = window.getDecorView();

            if (isDarkMode(activity)) {
                // Dark mode: light icons on dark background
                decorView.setSystemUiVisibility(
                    decorView.getSystemUiVisibility() & ~View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR
                );
                window.setStatusBarColor(getDarkPrimaryColor());
            } else {
                // Light mode: dark icons on light background
                decorView.setSystemUiVisibility(
                    decorView.getSystemUiVisibility() | View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR
                );
                window.setStatusBarColor(getLightPrimaryColor());
            }
        }
    }

    /**
     * Set transparent status bar
     */
    public static void setTransparentStatusBar(Activity activity) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            Window window = activity.getWindow();
            window.addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
            window.setStatusBarColor(Color.TRANSPARENT);
            window.getDecorView().setSystemUiVisibility(
                View.SYSTEM_UI_FLAG_LAYOUT_STABLE | View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
            );
        }
    }

    // ==================== Color Utilities ====================

    /**
     * Get primary color for dark theme
     */
    @ColorInt
    public static int getDarkPrimaryColor() {
        return Color.parseColor("#1F1F1F");
    }

    /**
     * Get primary color for light theme
     */
    @ColorInt
    public static int getLightPrimaryColor() {
        return Color.parseColor("#4CAF50"); // Green
    }

    /**
     * Get background color based on current theme
     */
    @ColorInt
    public static int getBackgroundColor(Context context) {
        return isDarkMode(context) ? Color.parseColor("#121212") : Color.parseColor("#FAFAFA");
    }

    /**
     * Get surface color based on current theme
     */
    @ColorInt
    public static int getSurfaceColor(Context context) {
        return isDarkMode(context) ? Color.parseColor("#1E1E1E") : Color.WHITE;
    }

    /**
     * Get text color based on current theme
     */
    @ColorInt
    public static int getTextColor(Context context) {
        return isDarkMode(context) ? Color.parseColor("#E0E0E0") : Color.parseColor("#212121");
    }

    /**
     * Get secondary text color based on current theme
     */
    @ColorInt
    public static int getSecondaryTextColor(Context context) {
        return isDarkMode(context) ? Color.parseColor("#9E9E9E") : Color.parseColor("#757575");
    }

    /**
     * Get accent color
     */
    @ColorInt
    public static int getAccentColor(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        return prefs.getInt(KEY_ACCENT_COLOR, Color.parseColor("#4CAF50")); // Default green
    }

    /**
     * Set accent color
     */
    public static void setAccentColor(Context context, @ColorInt int color) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putInt(KEY_ACCENT_COLOR, color)
            .apply();
    }

    /**
     * Get divider color based on current theme
     */
    @ColorInt
    public static int getDividerColor(Context context) {
        return isDarkMode(context) ? Color.parseColor("#2C2C2C") : Color.parseColor("#E0E0E0");
    }

    /**
     * Get error color (typically red, but adjusted for theme)
     */
    @ColorInt
    public static int getErrorColor(Context context) {
        return isDarkMode(context) ? Color.parseColor("#CF6679") : Color.parseColor("#B00020");
    }

    /**
     * Get success color (typically green, but adjusted for theme)
     */
    @ColorInt
    public static int getSuccessColor(Context context) {
        return isDarkMode(context) ? Color.parseColor("#81C784") : Color.parseColor("#4CAF50");
    }

    /**
     * Get warning color (typically orange/yellow)
     */
    @ColorInt
    public static int getWarningColor(Context context) {
        return isDarkMode(context) ? Color.parseColor("#FFB74D") : Color.parseColor("#FF9800");
    }

    // ==================== Color Manipulation ====================

    /**
     * Darken a color by a percentage
     */
    @ColorInt
    public static int darkenColor(@ColorInt int color, float percent) {
        float[] hsv = new float[3];
        Color.colorToHSV(color, hsv);
        hsv[2] *= (1 - percent);
        return Color.HSVToColor(hsv);
    }

    /**
     * Lighten a color by a percentage
     */
    @ColorInt
    public static int lightenColor(@ColorInt int color, float percent) {
        float[] hsv = new float[3];
        Color.colorToHSV(color, hsv);
        hsv[2] = Math.min(1.0f, hsv[2] + (1 - hsv[2]) * percent);
        return Color.HSVToColor(hsv);
    }

    /**
     * Get color with alpha
     */
    @ColorInt
    public static int withAlpha(@ColorInt int color, int alpha) {
        return Color.argb(alpha, Color.red(color), Color.green(color), Color.blue(color));
    }

    /**
     * Calculate contrast ratio between two colors
     */
    public static double getContrastRatio(@ColorInt int foreground, @ColorInt int background) {
        double luminance1 = getLuminance(foreground);
        double luminance2 = getLuminance(background);

        double lighter = Math.max(luminance1, luminance2);
        double darker = Math.min(luminance1, luminance2);

        return (lighter + 0.05) / (darker + 0.05);
    }

    /**
     * Calculate relative luminance of a color
     */
    private static double getLuminance(@ColorInt int color) {
        double r = Color.red(color) / 255.0;
        double g = Color.green(color) / 255.0;
        double b = Color.blue(color) / 255.0;

        r = r <= 0.03928 ? r / 12.92 : Math.pow((r + 0.055) / 1.055, 2.4);
        g = g <= 0.03928 ? g / 12.92 : Math.pow((g + 0.055) / 1.055, 2.4);
        b = b <= 0.03928 ? b / 12.92 : Math.pow((b + 0.055) / 1.055, 2.4);

        return 0.2126 * r + 0.7152 * g + 0.0722 * b;
    }

    /**
     * Determine if text should be light or dark based on background
     */
    public static boolean shouldUseLightText(@ColorInt int backgroundColor) {
        double luminance = getLuminance(backgroundColor);
        return luminance < 0.5;
    }

    /**
     * Get appropriate text color for a background
     */
    @ColorInt
    public static int getTextColorForBackground(@ColorInt int backgroundColor) {
        return shouldUseLightText(backgroundColor) ? Color.WHITE : Color.BLACK;
    }

    // ==================== Initialization ====================

    /**
     * Initialize theme system (call in Application.onCreate)
     */
    public static void initialize(Context context) {
        ThemeMode mode = getThemeMode(context);
        switch (mode) {
            case DARK:
                AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_YES);
                break;
            case LIGHT:
                AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_NO);
                break;
            case FOLLOW_SYSTEM:
                AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM);
                break;
        }
    }
}
