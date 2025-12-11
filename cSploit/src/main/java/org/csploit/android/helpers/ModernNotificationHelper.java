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

import android.app.PendingIntent;
import org.csploit.android.helpers.LoggingHelper;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import androidx.annotation.NonNull;
import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;

import org.csploit.android.R;

/**
 * Modern notification helper using NotificationCompat for better compatibility.
 * Provides enhanced notification features for Android 8.0+ (Oreo) with proper channel support.
 */
public class ModernNotificationHelper {
    
    private static final String TAG = "ModernNotificationHelper";
    
    // Notification IDs
    public static final int NOTIFICATION_ID_SCAN = 1001;
    public static final int NOTIFICATION_ID_UPDATE = 1002;
    public static final int NOTIFICATION_ID_ALERT = 1003;
    public static final int NOTIFICATION_ID_PROGRESS = 1004;
    
    /**
     * Show a progress notification.
     * 
     * @param context Application context
     * @param title Notification title
     * @param message Notification message
     * @param progress Current progress (0-100)
     * @param max Maximum progress value (default 100)
     */
    public static void showProgressNotification(@NonNull Context context, 
                                                @NonNull String title, 
                                                @NonNull String message,
                                                int progress, 
                                                int max) {
        NotificationCompat.Builder builder = createNotificationBuilder(context)
                .setContentTitle(title)
                .setContentText(message)
                .setProgress(max, progress, false)
                .setSmallIcon(R.drawable.ic_launcher)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .setOngoing(true);
        
        show(context, NOTIFICATION_ID_PROGRESS, builder);
    }
    
    /**
     * Show an indeterminate progress notification.
     * 
     * @param context Application context
     * @param title Notification title
     * @param message Notification message
     */
    public static void showIndeterminateProgressNotification(@NonNull Context context,
                                                            @NonNull String title,
                                                            @NonNull String message) {
        NotificationCompat.Builder builder = createNotificationBuilder(context)
                .setContentTitle(title)
                .setContentText(message)
                .setProgress(0, 0, true)
                .setSmallIcon(R.drawable.ic_launcher)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .setOngoing(true);
        
        show(context, NOTIFICATION_ID_PROGRESS, builder);
    }
    
    /**
     * Show a scan complete notification.
     * 
     * @param context Application context
     * @param title Notification title
     * @param message Notification message
     * @param targetsFound Number of targets found
     */
    public static void showScanCompleteNotification(@NonNull Context context,
                                                    @NonNull String title,
                                                    @NonNull String message,
                                                    int targetsFound) {
        NotificationCompat.Builder builder = createNotificationBuilder(context)
                .setContentTitle(title)
                .setContentText(message)
                .setSmallIcon(R.drawable.ic_launcher)
                .setPriority(NotificationCompat.PRIORITY_DEFAULT)
                .setAutoCancel(true)
                .setNumber(targetsFound);
        
        show(context, NOTIFICATION_ID_SCAN, builder);
    }
    
    /**
     * Show a security alert notification.
     * 
     * @param context Application context
     * @param title Notification title
     * @param message Notification message
     */
    public static void showAlertNotification(@NonNull Context context,
                                            @NonNull String title,
                                            @NonNull String message) {
        NotificationCompat.Builder builder = createNotificationBuilder(context)
                .setContentTitle(title)
                .setContentText(message)
                .setSmallIcon(R.drawable.ic_launcher)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setAutoCancel(true)
                .setDefaults(NotificationCompat.DEFAULT_ALL);
        
        show(context, NOTIFICATION_ID_ALERT, builder);
    }
    
    /**
     * Cancel a notification by ID.
     * 
     * @param context Application context
     * @param notificationId Notification ID to cancel
     */
    public static void cancel(@NonNull Context context, int notificationId) {
        NotificationManagerCompat notificationManager = NotificationManagerCompat.from(context);
        notificationManager.cancel(notificationId);
    }
    
    /**
     * Cancel all notifications.
     * 
     * @param context Application context
     */
    public static void cancelAll(@NonNull Context context) {
        NotificationManagerCompat notificationManager = NotificationManagerCompat.from(context);
        notificationManager.cancelAll();
    }
    
    /**
     * Create a notification builder with proper channel configuration.
     * 
     * @param context Application context
     * @return NotificationCompat.Builder instance
     */
    private static NotificationCompat.Builder createNotificationBuilder(@NonNull Context context) {
        String channelId = context.getString(R.string.csploitChannelId);
        return new NotificationCompat.Builder(context, channelId)
                .setDefaults(NotificationCompat.DEFAULT_VIBRATE);
    }
    
    /**
     * Show a notification.
     * 
     * @param context Application context
     * @param notificationId Unique notification ID
     * @param builder NotificationCompat.Builder instance
     */
    private static void show(@NonNull Context context, int notificationId, 
                            @NonNull NotificationCompat.Builder builder) {
        try {
            NotificationManagerCompat notificationManager = NotificationManagerCompat.from(context);
            notificationManager.notify(notificationId, builder.build());
        } catch (SecurityException e) {
            LoggingHelper.e(TAG, "Failed to show notification - permission denied", e);
        }
    }
    
    /**
     * Create a pending intent with appropriate flags for current Android version.
     * 
     * @param context Application context
     * @param requestCode Request code
     * @param intent Intent to wrap
     * @param flags Additional flags
     * @return PendingIntent
     */
    public static PendingIntent createPendingIntent(@NonNull Context context,
                                                   int requestCode,
                                                   @NonNull Intent intent,
                                                   int flags) {
        int pendingIntentFlags = flags;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            pendingIntentFlags |= PendingIntent.FLAG_IMMUTABLE;
        }
        return PendingIntent.getActivity(context, requestCode, intent, pendingIntentFlags);
    }
    
    private ModernNotificationHelper() {
        // Prevent instantiation
    }
}
