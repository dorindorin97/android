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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with cSploit. If not, see <http://www.gnu.org/licenses/>.
 */

package org.csploit.android.helpers;

import android.content.Context;
import android.widget.Toast;

import androidx.annotation.NonNull;

/**
 * ToastHelper - Standardized toast message utilities
 *
 * Provides consistent, reusable toast patterns across the application:
 * - Status messages (started, stopped, running)
 * - Error messages with visual indicators
 * - Success messages with checkmarks
 * - Info messages with consistent styling
 * - Long-running operation messages
 *
 * Features:
 * - Visual emoji indicators for quick scanning
 * - Consistent duration (SHORT for quick feedback, LONG for important)
 * - Activity context handling
 * - Message deduplication through LoggingHelper
 *
 * Usage:
 * {@code
 * // Status messages
 * ToastHelper.status(context, "Scan started");
 * ToastHelper.status(context, getString(R.string.child_not_started), Toast.LENGTH_LONG);
 *
 * // Error messages
 * ToastHelper.error(context, "Connection failed");
 *
 * // Success messages
 * ToastHelper.success(context, "Completed successfully");
 *
 * // Info messages
 * ToastHelper.info(context, "Tap again to confirm");
 * }
 *
 * @author cSploit Team
 * @version 1.0
 */
public final class ToastHelper {

    private static final String TAG = "ToastHelper";

    private ToastHelper() {}

    /**
     * Show status message toast (neutral color with icon)
     *
     * @param context Android context
     * @param message status message to display
     */
    public static void status(@NonNull Context context, @NonNull String message) {
        status(context, message, Toast.LENGTH_SHORT);
    }

    /**
     * Show status message toast with custom duration
     *
     * @param context Android context
     * @param message status message to display
     * @param duration Toast.LENGTH_SHORT or Toast.LENGTH_LONG
     */
    public static void status(@NonNull Context context, @NonNull String message, int duration) {
        Toast.makeText(context, "ℹ️ " + message, duration).show();
        LoggingHelper.d(TAG, "Status: " + message);
    }

    /**
     * Show error toast
     *
     * @param context Android context
     * @param message error message
     */
    public static void error(@NonNull Context context, @NonNull String message) {
        error(context, message, Toast.LENGTH_LONG);
    }

    /**
     * Show error toast with custom duration
     *
     * @param context Android context
     * @param message error message
     * @param duration Toast.LENGTH_SHORT or Toast.LENGTH_LONG
     */
    public static void error(@NonNull Context context, @NonNull String message, int duration) {
        Toast.makeText(context, "❌ " + message, duration).show();
        LoggingHelper.e(TAG, "Error toast: " + message);
    }

    /**
     * Show success toast
     *
     * @param context Android context
     * @param message success message
     */
    public static void success(@NonNull Context context, @NonNull String message) {
        success(context, message, Toast.LENGTH_SHORT);
    }

    /**
     * Show success toast with custom duration
     *
     * @param context Android context
     * @param message success message
     * @param duration Toast.LENGTH_SHORT or Toast.LENGTH_LONG
     */
    public static void success(@NonNull Context context, @NonNull String message, int duration) {
        Toast.makeText(context, "✓ " + message, duration).show();
        LoggingHelper.d(TAG, "Success: " + message);
    }

    /**
     * Show info/action required toast (for taps, confirmations, etc.)
     *
     * @param context Android context
     * @param message info message
     */
    public static void info(@NonNull Context context, @NonNull String message) {
        info(context, message, Toast.LENGTH_LONG);
    }

    /**
     * Show info/action required toast with custom duration
     *
     * @param context Android context
     * @param message info message
     * @param duration Toast.LENGTH_SHORT or Toast.LENGTH_LONG
     */
    public static void info(@NonNull Context context, @NonNull String message, int duration) {
        Toast.makeText(context, "ℹ️ " + message, duration).show();
        LoggingHelper.d(TAG, "Info: " + message);
    }

    /**
     * Show "child process not started" error (common pattern)
     *
     * @param context Android context
     * @param processName name of the child process that failed
     */
    public static void childNotStarted(@NonNull Context context, @NonNull String processName) {
        error(context, processName + " failed to start", Toast.LENGTH_LONG);
    }

    /**
     * Show "tap again" prompt (common pattern)
     *
     * @param context Android context
     */
    public static void tapAgain(@NonNull Context context) {
        info(context, "Tap again to confirm", Toast.LENGTH_LONG);
    }

    /**
     * Show logging message toast
     *
     * @param context Android context
     * @param message logging/debug message
     */
    public static void debug(@NonNull Context context, @NonNull String message) {
        Toast.makeText(context, "🔧 " + message, Toast.LENGTH_SHORT).show();
        LoggingHelper.d(TAG, "Debug: " + message);
    }
}
