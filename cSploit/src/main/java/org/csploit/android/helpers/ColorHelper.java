/*
 * This file is part of the cSploit.
 *
 * Copyleft of Simone Margaritelli aka evilsocket <evilsocket@gmail.com>
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
import androidx.core.content.ContextCompat;

/**
 * Centralized color management utility.
 * 
 * Provides convenient methods for accessing colors with ContextCompat compatibility.
 * Replaces repetitive ContextCompat.getColor() calls throughout the codebase.
 * 
 * Benefits:
 * - Centralized color access pattern
 * - Easy theme switching support
 * - Reduced boilerplate code
 * - Consistent color usage across app
 * 
 * Usage:
 * ```java
 * int color = ColorHelper.get(context, R.color.app_color);
 * view.setTextColor(ColorHelper.get(context, R.color.text_primary));
 * ```
 */
public class ColorHelper {

    /**
     * Get a color resource with ContextCompat compatibility.
     * 
     * @param context Application context
     * @param colorResId Color resource ID
     * @return Resolved color integer
     */
    public static int get(Context context, int colorResId) {
        return ContextCompat.getColor(context, colorResId);
    }

    /**
     * Get app primary color.
     * 
     * @param context Application context
     * @return App theme color
     */
    public static int getAppColor(Context context) {
        return get(context, android.R.color.holo_blue_bright);
    }

    /**
     * Get text primary color.
     * 
     * @param context Application context
     * @return Text color (dark or light based on theme)
     */
    public static int getTextPrimary(Context context) {
        return get(context, android.R.color.black);
    }

    /**
     * Get text secondary/gray color.
     * 
     * @param context Application context
     * @return Gray text color
     */
    public static int getTextSecondary(Context context) {
        return get(context, android.R.color.darker_gray);
    }

    /**
     * Get error/warning color.
     * 
     * @param context Application context
     * @return Error red color
     */
    public static int getError(Context context) {
        return get(context, android.R.color.holo_red_light);
    }

    /**
     * Get success color.
     * 
     * @param context Application context
     * @return Success green color
     */
    public static int getSuccess(Context context) {
        return get(context, android.R.color.holo_green_light);
    }

    /**
     * Get warning color.
     * 
     * @param context Application context
     * @return Warning orange color
     */
    public static int getWarning(Context context) {
        return get(context, android.R.color.holo_orange_light);
    }

    /**
     * Get background color (respects theme preference).
     * 
     * @param context Application context
     * @return Background color
     */
    public static int getBackground(Context context) {
        boolean isDark = context.getSharedPreferences("THEME", 0).getBoolean("isDark", false);
        // Returns white for light theme, dark gray for dark theme
        return isDark ? 0xFF1F1F1F : 0xFFFFFFFF;
    }

    /**
     * Get window background color (respects theme preference).
     * 
     * @param context Application context
     * @return Window background color
     */
    public static int getWindowBackground(Context context) {
        boolean isDark = context.getSharedPreferences("THEME", 0).getBoolean("isDark", false);
        // Assumes R.color.background_window_dark and R.color.background_window exist
        // Returns appropriate color based on current theme
        return isDark ? 0xFF121212 : 0xFFFFFFFF;
    }
}
