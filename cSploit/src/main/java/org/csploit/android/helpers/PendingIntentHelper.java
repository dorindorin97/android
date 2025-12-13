package org.csploit.android.helpers;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

import androidx.annotation.NonNull;

/**
 * Helper class for creating PendingIntents with proper flags for all Android versions.
 * Android 12+ (API 31) requires explicit mutability flags.
 */
public final class PendingIntentHelper {

    private PendingIntentHelper() {
        // Utility class
    }

    /**
     * Get immutable flag for PendingIntent.
     * Returns FLAG_IMMUTABLE on Android 12+ (API 31), 0 otherwise.
     */
    public static int getImmutableFlag() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            return PendingIntent.FLAG_IMMUTABLE;
        }
        return 0;
    }

    /**
     * Get mutable flag for PendingIntent.
     * Returns FLAG_MUTABLE on Android 12+ (API 31), 0 otherwise.
     * Use this only when the PendingIntent needs to be modified.
     */
    public static int getMutableFlag() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            return PendingIntent.FLAG_MUTABLE;
        }
        return 0;
    }

    /**
     * Create an immutable Activity PendingIntent.
     *
     * @param context     The context
     * @param requestCode The request code
     * @param intent      The intent
     * @return The PendingIntent
     */
    @NonNull
    public static PendingIntent getActivityImmutable(
            @NonNull Context context,
            int requestCode,
            @NonNull Intent intent) {
        return PendingIntent.getActivity(
                context,
                requestCode,
                intent,
                getImmutableFlag()
        );
    }

    /**
     * Create an immutable Activity PendingIntent with additional flags.
     *
     * @param context     The context
     * @param requestCode The request code
     * @param intent      The intent
     * @param extraFlags  Additional flags (e.g., FLAG_UPDATE_CURRENT)
     * @return The PendingIntent
     */
    @NonNull
    public static PendingIntent getActivityImmutable(
            @NonNull Context context,
            int requestCode,
            @NonNull Intent intent,
            int extraFlags) {
        return PendingIntent.getActivity(
                context,
                requestCode,
                intent,
                extraFlags | getImmutableFlag()
        );
    }

    /**
     * Create a mutable Activity PendingIntent.
     * Use only when the PendingIntent needs to be modified.
     *
     * @param context     The context
     * @param requestCode The request code
     * @param intent      The intent
     * @return The PendingIntent
     */
    @NonNull
    public static PendingIntent getActivityMutable(
            @NonNull Context context,
            int requestCode,
            @NonNull Intent intent) {
        return PendingIntent.getActivity(
                context,
                requestCode,
                intent,
                getMutableFlag()
        );
    }

    /**
     * Create an immutable Broadcast PendingIntent.
     *
     * @param context     The context
     * @param requestCode The request code
     * @param intent      The intent
     * @return The PendingIntent
     */
    @NonNull
    public static PendingIntent getBroadcastImmutable(
            @NonNull Context context,
            int requestCode,
            @NonNull Intent intent) {
        return PendingIntent.getBroadcast(
                context,
                requestCode,
                intent,
                getImmutableFlag()
        );
    }

    /**
     * Create an immutable Broadcast PendingIntent with additional flags.
     *
     * @param context     The context
     * @param requestCode The request code
     * @param intent      The intent
     * @param extraFlags  Additional flags
     * @return The PendingIntent
     */
    @NonNull
    public static PendingIntent getBroadcastImmutable(
            @NonNull Context context,
            int requestCode,
            @NonNull Intent intent,
            int extraFlags) {
        return PendingIntent.getBroadcast(
                context,
                requestCode,
                intent,
                extraFlags | getImmutableFlag()
        );
    }

    /**
     * Create a mutable Broadcast PendingIntent.
     * Use only when the PendingIntent needs to be modified.
     *
     * @param context     The context
     * @param requestCode The request code
     * @param intent      The intent
     * @return The PendingIntent
     */
    @NonNull
    public static PendingIntent getBroadcastMutable(
            @NonNull Context context,
            int requestCode,
            @NonNull Intent intent) {
        return PendingIntent.getBroadcast(
                context,
                requestCode,
                intent,
                getMutableFlag()
        );
    }

    /**
     * Create an immutable Service PendingIntent.
     *
     * @param context     The context
     * @param requestCode The request code
     * @param intent      The intent
     * @return The PendingIntent
     */
    @NonNull
    public static PendingIntent getServiceImmutable(
            @NonNull Context context,
            int requestCode,
            @NonNull Intent intent) {
        return PendingIntent.getService(
                context,
                requestCode,
                intent,
                getImmutableFlag()
        );
    }

    /**
     * Create an immutable Service PendingIntent with additional flags.
     *
     * @param context     The context
     * @param requestCode The request code
     * @param intent      The intent
     * @param extraFlags  Additional flags
     * @return The PendingIntent
     */
    @NonNull
    public static PendingIntent getServiceImmutable(
            @NonNull Context context,
            int requestCode,
            @NonNull Intent intent,
            int extraFlags) {
        return PendingIntent.getService(
                context,
                requestCode,
                intent,
                extraFlags | getImmutableFlag()
        );
    }

    /**
     * Create a mutable Service PendingIntent.
     * Use only when the PendingIntent needs to be modified.
     *
     * @param context     The context
     * @param requestCode The request code
     * @param intent      The intent
     * @return The PendingIntent
     */
    @NonNull
    public static PendingIntent getServiceMutable(
            @NonNull Context context,
            int requestCode,
            @NonNull Intent intent) {
        return PendingIntent.getService(
                context,
                requestCode,
                intent,
                getMutableFlag()
        );
    }

    /**
     * Create an immutable foreground Service PendingIntent (Android O+).
     *
     * @param context     The context
     * @param requestCode The request code
     * @param intent      The intent
     * @return The PendingIntent
     */
    @NonNull
    public static PendingIntent getForegroundServiceImmutable(
            @NonNull Context context,
            int requestCode,
            @NonNull Intent intent) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            return PendingIntent.getForegroundService(
                    context,
                    requestCode,
                    intent,
                    getImmutableFlag()
            );
        }
        return getServiceImmutable(context, requestCode, intent);
    }
}
