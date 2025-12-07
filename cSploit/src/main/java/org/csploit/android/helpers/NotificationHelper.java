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

import android.app.NotificationChannel;
import org.csploit.android.helpers.LoggingHelper;
import android.app.NotificationManager;
import org.csploit.android.helpers.LoggingHelper;
import android.app.PendingIntent;
import org.csploit.android.helpers.LoggingHelper;
import android.content.Context;
import org.csploit.android.helpers.LoggingHelper;
import android.graphics.Bitmap;
import org.csploit.android.helpers.LoggingHelper;
import android.os.Build;
import org.csploit.android.helpers.LoggingHelper;

import androidx.annotation.NonNull;
import org.csploit.android.helpers.LoggingHelper;
import androidx.annotation.Nullable;
import org.csploit.android.helpers.LoggingHelper;
import androidx.core.app.NotificationCompat;
import org.csploit.android.helpers.LoggingHelper;

import java.util.Collections;
import org.csploit.android.helpers.LoggingHelper;
import java.util.HashMap;
import org.csploit.android.helpers.LoggingHelper;
import java.util.Map;
import org.csploit.android.helpers.LoggingHelper;

/**
 * NotificationHelper - Centralized notification management utility
 *
 * Provides streamlined notification creation, display, and management for the application.
 *
 * Features:
 * - Simple notification builder with common configurations
 * - Notification channel management (Android 8.0+)
 * - Progress notifications for long-running operations
 * - Group notifications support
 * - Big text and big picture styles
 * - Priority and importance management
 * - Cancellation and clearing
 *
 * Usage:
 * {@code
 * // Simple notification
 * NotificationHelper.show(context, "Title", "Message", R.drawable.icon);
 *
 * // With channel
 * NotificationHelper.showWithChannel(context, "channelId", "Title", "Message", 
 *     R.drawable.icon, NotificationManager.IMPORTANCE_DEFAULT);
 *
 * // Progress notification
 * NotificationHelper.showProgress(context, "Loading", 50, 100);
 *
 * // Big text notification
 * NotificationHelper.showBigText(context, "Title", "Message", "Big text content");
 * }
 *
 * @author cSploit Team
 * @version 1.0
 */
public final class NotificationHelper {

    private static final String TAG = "NotificationHelper";

    // Default channel ID
    private static final String DEFAULT_CHANNEL_ID = "csploit_default";
    private static final String PROGRESS_CHANNEL_ID = "csploit_progress";

    // Notification ID tracking
    private static final Map<String, Integer> notificationIds = 
            Collections.synchronizedMap(new HashMap<String, Integer>());
    private static int nextNotificationId = 1000;

    // Private constructor to prevent instantiation
    private NotificationHelper() {}

    /**
     * Show simple notification
     *
     * @param context Android context
     * @param title notification title
     * @param message notification message
     * @param smallIcon small icon resource ID
     */
    public static void show(@NonNull Context context, @NonNull String title, 
                           @NonNull String message, int smallIcon) {
        showWithChannel(context, DEFAULT_CHANNEL_ID, title, message, smallIcon, 
                NotificationManager.IMPORTANCE_DEFAULT);
    }

    /**
     * Show notification with custom channel
     *
     * @param context Android context
     * @param channelId notification channel ID
     * @param title notification title
     * @param message notification message
     * @param smallIcon small icon resource ID
     * @param importance notification importance
     */
    public static void showWithChannel(@NonNull Context context, @NonNull String channelId,
                                      @NonNull String title, @NonNull String message,
                                      int smallIcon, int importance) {
        ensureChannelExists(context, channelId, title, importance);

        NotificationCompat.Builder builder = new NotificationCompat.Builder(context, channelId)
                .setSmallIcon(smallIcon)
                .setContentTitle(title)
                .setContentText(message)
                .setPriority(mapImportanceToPriority(importance))
                .setAutoCancel(true);

        show(context, builder.build(), getNotificationId(channelId));
    }

    /**
     * Show notification with action
     *
     * @param context Android context
     * @param title notification title
     * @param message notification message
     * @param smallIcon small icon resource ID
     * @param intent pending intent for tap action
     */
    public static void showWithAction(@NonNull Context context, @NonNull String title,
                                     @NonNull String message, int smallIcon,
                                     @NonNull PendingIntent intent) {
        NotificationCompat.Builder builder = new NotificationCompat.Builder(context, DEFAULT_CHANNEL_ID)
                .setSmallIcon(smallIcon)
                .setContentTitle(title)
                .setContentText(message)
                .setContentIntent(intent)
                .setAutoCancel(true)
                .setPriority(NotificationCompat.PRIORITY_DEFAULT);

        show(context, builder.build(), getNotificationId(DEFAULT_CHANNEL_ID));
    }

    /**
     * Show progress notification
     *
     * @param context Android context
     * @param title notification title
     * @param progress current progress (0-100)
     * @param max maximum progress value
     * @return notification ID
     */
    public static int showProgress(@NonNull Context context, @NonNull String title,
                                   int progress, int max) {
        return showProgress(context, PROGRESS_CHANNEL_ID, title, "", progress, max);
    }

    /**
     * Show progress notification with message
     *
     * @param context Android context
     * @param channelId notification channel ID
     * @param title notification title
     * @param message notification message
     * @param progress current progress
     * @param max maximum progress value
     * @return notification ID
     */
    public static int showProgress(@NonNull Context context, @NonNull String channelId,
                                   @NonNull String title, @NonNull String message,
                                   int progress, int max) {
        ensureChannelExists(context, channelId, "Progress", NotificationManager.IMPORTANCE_LOW);

        NotificationCompat.Builder builder = new NotificationCompat.Builder(context, channelId)
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentTitle(title)
                .setContentText(message)
                .setProgress(max, progress, false)
                .setOngoing(true)
                .setPriority(NotificationCompat.PRIORITY_LOW);

        int notificationId = getNotificationId(channelId + "_progress");
        show(context, builder.build(), notificationId);
        return notificationId;
    }

    /**
     * Show big text notification
     *
     * @param context Android context
     * @param title notification title
     * @param message notification message
     * @param bigText large text content
     * @param smallIcon small icon resource ID
     */
    public static void showBigText(@NonNull Context context, @NonNull String title,
                                  @NonNull String message, @NonNull String bigText,
                                  int smallIcon) {
        ensureChannelExists(context, DEFAULT_CHANNEL_ID, "General", NotificationManager.IMPORTANCE_DEFAULT);

        NotificationCompat.BigTextStyle bigStyle = new NotificationCompat.BigTextStyle()
                .bigText(bigText)
                .setBigContentTitle(title)
                .setSummaryText(message);

        NotificationCompat.Builder builder = new NotificationCompat.Builder(context, DEFAULT_CHANNEL_ID)
                .setSmallIcon(smallIcon)
                .setContentTitle(title)
                .setContentText(message)
                .setStyle(bigStyle)
                .setAutoCancel(true)
                .setPriority(NotificationCompat.PRIORITY_DEFAULT);

        show(context, builder.build(), getNotificationId(DEFAULT_CHANNEL_ID));
    }

    /**
     * Show big picture notification
     *
     * @param context Android context
     * @param title notification title
     * @param message notification message
     * @param picture bitmap picture
     * @param smallIcon small icon resource ID
     */
    public static void showBigPicture(@NonNull Context context, @NonNull String title,
                                     @NonNull String message, @NonNull Bitmap picture,
                                     int smallIcon) {
        ensureChannelExists(context, DEFAULT_CHANNEL_ID, "General", NotificationManager.IMPORTANCE_DEFAULT);

        NotificationCompat.BigPictureStyle bigStyle = new NotificationCompat.BigPictureStyle()
                .bigPicture(picture)
                .setBigContentTitle(title)
                .setSummaryText(message);

        NotificationCompat.Builder builder = new NotificationCompat.Builder(context, DEFAULT_CHANNEL_ID)
                .setSmallIcon(smallIcon)
                .setContentTitle(title)
                .setContentText(message)
                .setLargeIcon(picture)
                .setStyle(bigStyle)
                .setAutoCancel(true)
                .setPriority(NotificationCompat.PRIORITY_DEFAULT);

        show(context, builder.build(), getNotificationId(DEFAULT_CHANNEL_ID));
    }

    /**
     * Update existing progress notification
     *
     * @param context Android context
     * @param notificationId notification ID to update
     * @param progress current progress
     * @param max maximum progress value
     * @param message optional message
     */
    public static void updateProgress(@NonNull Context context, int notificationId,
                                     int progress, int max, @NonNull String message) {
        NotificationCompat.Builder builder = new NotificationCompat.Builder(context, PROGRESS_CHANNEL_ID)
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentText(message)
                .setProgress(max, progress, false)
                .setOngoing(true);

        show(context, builder.build(), notificationId);
    }

    /**
     * Cancel notification by ID
     *
     * @param context Android context
     * @param notificationId notification ID to cancel
     */
    public static void cancel(@NonNull Context context, int notificationId) {
        NotificationManager nm = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm != null) {
            nm.cancel(notificationId);
            LoggingHelper.d(TAG, "Notification cancelled: " + notificationId);
        }
    }

    /**
     * Cancel all notifications for a channel
     *
     * @param context Android context
     * @param channelId channel ID to cancel
     */
    public static void cancelChannel(@NonNull Context context, @NonNull String channelId) {
        if (notificationIds.containsKey(channelId)) {
            cancel(context, notificationIds.get(channelId));
        }
    }

    /**
     * Cancel all notifications
     *
     * @param context Android context
     */
    public static void cancelAll(@NonNull Context context) {
        NotificationManager nm = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm != null) {
            nm.cancelAll();
            notificationIds.clear();
            LoggingHelper.d(TAG, "All notifications cancelled");
        }
    }

    /**
     * Create notification channel (Android 8.0+)
     *
     * @param context Android context
     * @param channelId channel ID
     * @param channelName channel name
     * @param importance notification importance level
     */
    public static void createChannel(@NonNull Context context, @NonNull String channelId,
                                    @NonNull String channelName, int importance) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(channelId, channelName, importance);
            channel.setDescription("cSploit notification channel");

            NotificationManager nm = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
            if (nm != null) {
                nm.createNotificationChannel(channel);
                LoggingHelper.d(TAG, "Notification channel created: " + channelId);
            }
        }
    }

    /**
     * Delete notification channel (Android 8.0+)
     *
     * @param context Android context
     * @param channelId channel ID to delete
     */
    public static void deleteChannel(@NonNull Context context, @NonNull String channelId) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationManager nm = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
            if (nm != null) {
                nm.deleteNotificationChannel(channelId);
                LoggingHelper.d(TAG, "Notification channel deleted: " + channelId);
            }
        }
    }

    /**
     * Show notification (internal)
     */
    private static void show(@NonNull Context context, @NonNull android.app.Notification notification,
                            int notificationId) {
        NotificationManager nm = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm != null) {
            nm.notify(notificationId, notification);
            LoggingHelper.d(TAG, "Notification shown: " + notificationId);
        }
    }

    /**
     * Ensure notification channel exists (Android 8.0+)
     */
    private static void ensureChannelExists(@NonNull Context context, @NonNull String channelId,
                                           @NonNull String channelName, int importance) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationManager nm = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
            if (nm != null && nm.getNotificationChannel(channelId) == null) {
                createChannel(context, channelId, channelName, importance);
            }
        }
    }

    /**
     * Get unique notification ID for a channel
     */
    private static int getNotificationId(@NonNull String key) {
        if (!notificationIds.containsKey(key)) {
            notificationIds.put(key, nextNotificationId++);
        }
        return notificationIds.get(key);
    }

    /**
     * Map notification importance to priority (for compatibility)
     */
    private static int mapImportanceToPriority(int importance) {
        switch (importance) {
            case NotificationManager.IMPORTANCE_HIGH:
                return NotificationCompat.PRIORITY_HIGH;
            case NotificationManager.IMPORTANCE_DEFAULT:
                return NotificationCompat.PRIORITY_DEFAULT;
            case NotificationManager.IMPORTANCE_LOW:
                return NotificationCompat.PRIORITY_LOW;
            case NotificationManager.IMPORTANCE_MIN:
                return NotificationCompat.PRIORITY_MIN;
            default:
                return NotificationCompat.PRIORITY_DEFAULT;
        }
    }

    /**
     * Show simple notification with big text (shorthand)
     *
     * @param context Android context
     * @param title notification title
     * @param message notification message
     * @param bigText large text content
     */
    public static void showBigText(@NonNull Context context, @NonNull String title,
                                  @NonNull String message, @NonNull String bigText) {
        showBigText(context, title, message, bigText, android.R.drawable.ic_dialog_info);
    }

    /**
     * Get total number of active notifications
     *
     * @return number of notification IDs tracked
     */
    public static int getNotificationCount() {
        return notificationIds.size();
    }
}
