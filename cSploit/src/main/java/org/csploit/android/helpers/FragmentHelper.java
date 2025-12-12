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

import android.app.Activity;
import android.app.Fragment;
import android.os.Handler;
import android.os.Looper;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

/**
 * FragmentHelper - Safe fragment operations utility class.
 *
 * Provides thread-safe utilities for working with fragments,
 * preventing NPE risks from detached fragments and null activities.
 *
 * Usage:
 * {@code
 * // Safe runOnUiThread
 * FragmentHelper.runOnUiThreadSafe(fragment, () -> {
 *     // UI operations
 * });
 *
 * // Safe getActivity with fallback
 * FragmentHelper.withActivity(fragment, activity -> {
 *     // Use activity safely
 * });
 * }
 */
public final class FragmentHelper {

    private static final String TAG = "FragmentHelper";
    private static final Handler mainHandler = new Handler(Looper.getMainLooper());

    private FragmentHelper() {}

    /**
     * Check if a fragment is safely attached to an activity.
     *
     * @param fragment The fragment to check
     * @return true if fragment is attached and activity is available
     */
    public static boolean isAttached(@Nullable Fragment fragment) {
        return fragment != null && fragment.isAdded() && fragment.getActivity() != null;
    }

    /**
     * Check if an AndroidX fragment is safely attached to an activity.
     *
     * @param fragment The AndroidX fragment to check
     * @return true if fragment is attached and activity is available
     */
    public static boolean isAttached(@Nullable androidx.fragment.app.Fragment fragment) {
        return fragment != null && fragment.isAdded() && fragment.getActivity() != null;
    }

    /**
     * Safely run code on UI thread if fragment is attached.
     *
     * @param fragment The fragment
     * @param action The action to run
     */
    public static void runOnUiThreadSafe(@Nullable Fragment fragment, @NonNull Runnable action) {
        if (fragment == null) {
            return;
        }
        
        Activity activity = fragment.getActivity();
        if (activity == null || !fragment.isAdded()) {
            return;
        }

        if (Looper.myLooper() == Looper.getMainLooper()) {
            // Already on main thread, check again before running
            if (fragment.isAdded() && fragment.getActivity() != null) {
                action.run();
            }
        } else {
            activity.runOnUiThread(() -> {
                if (fragment.isAdded() && fragment.getActivity() != null) {
                    action.run();
                }
            });
        }
    }

    /**
     * Safely run code on UI thread if AndroidX fragment is attached.
     *
     * @param fragment The AndroidX fragment
     * @param action The action to run
     */
    public static void runOnUiThreadSafe(@Nullable androidx.fragment.app.Fragment fragment, @NonNull Runnable action) {
        if (fragment == null) {
            return;
        }
        
        androidx.fragment.app.FragmentActivity activity = fragment.getActivity();
        if (activity == null || !fragment.isAdded()) {
            return;
        }

        if (Looper.myLooper() == Looper.getMainLooper()) {
            if (fragment.isAdded() && fragment.getActivity() != null) {
                action.run();
            }
        } else {
            activity.runOnUiThread(() -> {
                if (fragment.isAdded() && fragment.getActivity() != null) {
                    action.run();
                }
            });
        }
    }

    /**
     * Execute code with activity if fragment is attached.
     *
     * @param fragment The fragment
     * @param consumer The consumer to receive the activity
     */
    public static void withActivity(@Nullable Fragment fragment, @NonNull ActivityConsumer consumer) {
        if (fragment == null || !fragment.isAdded()) {
            return;
        }
        
        Activity activity = fragment.getActivity();
        if (activity != null) {
            consumer.accept(activity);
        }
    }

    /**
     * Execute code with AndroidX activity if fragment is attached.
     *
     * @param fragment The AndroidX fragment
     * @param consumer The consumer to receive the activity
     */
    public static void withActivity(@Nullable androidx.fragment.app.Fragment fragment, 
                                    @NonNull FragmentActivityConsumer consumer) {
        if (fragment == null || !fragment.isAdded()) {
            return;
        }
        
        androidx.fragment.app.FragmentActivity activity = fragment.getActivity();
        if (activity != null) {
            consumer.accept(activity);
        }
    }

    /**
     * Post a delayed action if fragment is still attached.
     *
     * @param fragment The fragment
     * @param action The action to run
     * @param delayMs Delay in milliseconds
     */
    public static void postDelayed(@Nullable Fragment fragment, @NonNull Runnable action, long delayMs) {
        if (fragment == null) {
            return;
        }
        
        mainHandler.postDelayed(() -> {
            if (fragment.isAdded() && fragment.getActivity() != null) {
                action.run();
            }
        }, delayMs);
    }

    /**
     * Post a delayed action if AndroidX fragment is still attached.
     *
     * @param fragment The AndroidX fragment
     * @param action The action to run
     * @param delayMs Delay in milliseconds
     */
    public static void postDelayed(@Nullable androidx.fragment.app.Fragment fragment, 
                                   @NonNull Runnable action, long delayMs) {
        if (fragment == null) {
            return;
        }
        
        mainHandler.postDelayed(() -> {
            if (fragment.isAdded() && fragment.getActivity() != null) {
                action.run();
            }
        }, delayMs);
    }

    /**
     * Get string resource safely.
     *
     * @param fragment The fragment
     * @param resId String resource ID
     * @return The string, or empty string if fragment detached
     */
    @NonNull
    public static String getStringSafe(@Nullable Fragment fragment, int resId) {
        if (fragment != null && fragment.isAdded()) {
            try {
                return fragment.getString(resId);
            } catch (Exception e) {
                LoggingHelper.e(TAG, "Failed to get string resource", e);
            }
        }
        return "";
    }

    /**
     * Get string resource safely with format arguments.
     *
     * @param fragment The fragment
     * @param resId String resource ID
     * @param formatArgs Format arguments
     * @return The formatted string, or empty string if fragment detached
     */
    @NonNull
    public static String getStringSafe(@Nullable Fragment fragment, int resId, Object... formatArgs) {
        if (fragment != null && fragment.isAdded()) {
            try {
                return fragment.getString(resId, formatArgs);
            } catch (Exception e) {
                LoggingHelper.e(TAG, "Failed to get string resource", e);
            }
        }
        return "";
    }

    /**
     * Activity consumer functional interface.
     */
    public interface ActivityConsumer {
        void accept(@NonNull Activity activity);
    }

    /**
     * FragmentActivity consumer functional interface.
     */
    public interface FragmentActivityConsumer {
        void accept(@NonNull androidx.fragment.app.FragmentActivity activity);
    }

    /**
     * Safe callback wrapper that checks fragment attachment before invoking.
     */
    public static class SafeCallback implements Runnable {
        private final Fragment fragment;
        private final Runnable action;

        public SafeCallback(@NonNull Fragment fragment, @NonNull Runnable action) {
            this.fragment = fragment;
            this.action = action;
        }

        @Override
        public void run() {
            if (isAttached(fragment)) {
                action.run();
            }
        }
    }

    /**
     * Safe callback wrapper for AndroidX fragments.
     */
    public static class SafeCallbackX implements Runnable {
        private final androidx.fragment.app.Fragment fragment;
        private final Runnable action;

        public SafeCallbackX(@NonNull androidx.fragment.app.Fragment fragment, @NonNull Runnable action) {
            this.fragment = fragment;
            this.action = action;
        }

        @Override
        public void run() {
            if (isAttached(fragment)) {
                action.run();
            }
        }
    }
}
