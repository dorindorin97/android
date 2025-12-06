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

import android.app.Activity;
import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.IdRes;
import androidx.annotation.LayoutRes;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

/**
 * Helper class for View operations.
 * Provides utilities for view inflation and manipulation.
 */
public class ViewHelper {
    
    /**
     * Find view by ID with type safety.
     * 
     * @param parent Parent view
     * @param id View ID
     * @param <T> View type
     * @return View or null if not found
     */
    @SuppressWarnings("unchecked")
    @Nullable
    public static <T extends View> T findViewById(@NonNull View parent, @IdRes int id) {
        return (T) parent.findViewById(id);
    }
    
    /**
     * Find view by ID with type safety.
     * 
     * @param activity Activity
     * @param id View ID
     * @param <T> View type
     * @return View or null if not found
     */
    @SuppressWarnings("unchecked")
    @Nullable
    public static <T extends View> T findViewById(@NonNull Activity activity, @IdRes int id) {
        return (T) activity.findViewById(id);
    }
    
    /**
     * Find view by ID with type safety (non-null).
     * 
     * @param parent Parent view
     * @param id View ID
     * @param <T> View type
     * @return View (throws if not found)
     */
    @NonNull
    public static <T extends View> T requireViewById(@NonNull View parent, @IdRes int id) {
        T view = findViewById(parent, id);
        if (view == null) {
            throw new IllegalStateException("Required view not found: " + id);
        }
        return view;
    }
    
    /**
     * Find view by ID with type safety (non-null).
     * 
     * @param activity Activity
     * @param id View ID
     * @param <T> View type
     * @return View (throws if not found)
     */
    @NonNull
    public static <T extends View> T requireViewById(@NonNull Activity activity, @IdRes int id) {
        T view = findViewById(activity, id);
        if (view == null) {
            throw new IllegalStateException("Required view not found: " + id);
        }
        return view;
    }
    
    /**
     * Inflate a layout.
     * 
     * @param context Context
     * @param layoutRes Layout resource ID
     * @param parent Parent view (for layout params)
     * @param attachToRoot Whether to attach to parent
     * @return Inflated view
     */
    @NonNull
    public static View inflate(@NonNull Context context, @LayoutRes int layoutRes,
                                @Nullable ViewGroup parent, boolean attachToRoot) {
        return LayoutInflater.from(context).inflate(layoutRes, parent, attachToRoot);
    }
    
    /**
     * Inflate a layout without attaching to parent.
     * 
     * @param context Context
     * @param layoutRes Layout resource ID
     * @param parent Parent view (for layout params)
     * @return Inflated view
     */
    @NonNull
    public static View inflate(@NonNull Context context, @LayoutRes int layoutRes,
                                @Nullable ViewGroup parent) {
        return inflate(context, layoutRes, parent, false);
    }
    
    /**
     * Inflate a layout without parent.
     * 
     * @param context Context
     * @param layoutRes Layout resource ID
     * @return Inflated view
     */
    @NonNull
    public static View inflate(@NonNull Context context, @LayoutRes int layoutRes) {
        return inflate(context, layoutRes, null, false);
    }
    
    /**
     * Set view visibility to VISIBLE.
     * 
     * @param view View
     */
    public static void show(@Nullable View view) {
        if (view != null) {
            view.setVisibility(View.VISIBLE);
        }
    }
    
    /**
     * Set view visibility to GONE.
     * 
     * @param view View
     */
    public static void hide(@Nullable View view) {
        if (view != null) {
            view.setVisibility(View.GONE);
        }
    }
    
    /**
     * Set view visibility to INVISIBLE.
     * 
     * @param view View
     */
    public static void invisible(@Nullable View view) {
        if (view != null) {
            view.setVisibility(View.INVISIBLE);
        }
    }
    
    /**
     * Set view visibility.
     * 
     * @param view View
     * @param visible Whether visible
     */
    public static void setVisible(@Nullable View view, boolean visible) {
        if (view != null) {
            view.setVisibility(visible ? View.VISIBLE : View.GONE);
        }
    }
    
    /**
     * Check if view is visible.
     * 
     * @param view View
     * @return true if visible
     */
    public static boolean isVisible(@Nullable View view) {
        return view != null && view.getVisibility() == View.VISIBLE;
    }
    
    /**
     * Check if view is gone.
     * 
     * @param view View
     * @return true if gone
     */
    public static boolean isGone(@Nullable View view) {
        return view == null || view.getVisibility() == View.GONE;
    }
    
    /**
     * Check if view is invisible.
     * 
     * @param view View
     * @return true if invisible
     */
    public static boolean isInvisible(@Nullable View view) {
        return view != null && view.getVisibility() == View.INVISIBLE;
    }
    
    /**
     * Toggle visibility (between VISIBLE and GONE).
     * 
     * @param view View
     */
    public static void toggleVisibility(@Nullable View view) {
        if (view != null) {
            view.setVisibility(view.getVisibility() == View.VISIBLE ? View.GONE : View.VISIBLE);
        }
    }
    
    /**
     * Enable view.
     * 
     * @param view View
     */
    public static void enable(@Nullable View view) {
        if (view != null) {
            view.setEnabled(true);
        }
    }
    
    /**
     * Disable view.
     * 
     * @param view View
     */
    public static void disable(@Nullable View view) {
        if (view != null) {
            view.setEnabled(false);
        }
    }
    
    /**
     * Set view enabled state.
     * 
     * @param view View
     * @param enabled Whether enabled
     */
    public static void setEnabled(@Nullable View view, boolean enabled) {
        if (view != null) {
            view.setEnabled(enabled);
        }
    }
    
    /**
     * Set click listener on view.
     * 
     * @param view View
     * @param listener Click listener
     */
    public static void setOnClick(@Nullable View view, @Nullable View.OnClickListener listener) {
        if (view != null) {
            view.setOnClickListener(listener);
        }
    }
    
    /**
     * Set long click listener on view.
     * 
     * @param view View
     * @param listener Long click listener
     */
    public static void setOnLongClick(@Nullable View view, @Nullable View.OnLongClickListener listener) {
        if (view != null) {
            view.setOnLongClickListener(listener);
        }
    }
    
    /**
     * Set text on TextView.
     * 
     * @param view View (should be TextView or subclass)
     * @param text Text to set
     */
    public static void setText(@Nullable View view, @Nullable CharSequence text) {
        if (view instanceof TextView) {
            ((TextView) view).setText(text);
        }
    }
    
    /**
     * Get text from TextView.
     * 
     * @param view View (should be TextView or subclass)
     * @return Text, or empty string if not TextView
     */
    @NonNull
    public static String getText(@Nullable View view) {
        if (view instanceof TextView) {
            CharSequence text = ((TextView) view).getText();
            return text != null ? text.toString() : "";
        }
        return "";
    }
    
    /**
     * Set padding on view in dp.
     * 
     * @param view View
     * @param paddingDp Padding in dp
     */
    public static void setPaddingDp(@NonNull View view, int paddingDp) {
        int paddingPx = DisplayHelper.dpToPx(view.getContext(), paddingDp);
        view.setPadding(paddingPx, paddingPx, paddingPx, paddingPx);
    }
    
    /**
     * Set padding on view in dp.
     * 
     * @param view View
     * @param leftDp Left padding in dp
     * @param topDp Top padding in dp
     * @param rightDp Right padding in dp
     * @param bottomDp Bottom padding in dp
     */
    public static void setPaddingDp(@NonNull View view, int leftDp, int topDp, int rightDp, int bottomDp) {
        Context context = view.getContext();
        view.setPadding(
                DisplayHelper.dpToPx(context, leftDp),
                DisplayHelper.dpToPx(context, topDp),
                DisplayHelper.dpToPx(context, rightDp),
                DisplayHelper.dpToPx(context, bottomDp)
        );
    }
    
    /**
     * Set margin on view in dp.
     * 
     * @param view View
     * @param marginDp Margin in dp
     */
    public static void setMarginDp(@NonNull View view, int marginDp) {
        setMarginDp(view, marginDp, marginDp, marginDp, marginDp);
    }
    
    /**
     * Set margin on view in dp.
     * 
     * @param view View
     * @param leftDp Left margin in dp
     * @param topDp Top margin in dp
     * @param rightDp Right margin in dp
     * @param bottomDp Bottom margin in dp
     */
    public static void setMarginDp(@NonNull View view, int leftDp, int topDp, int rightDp, int bottomDp) {
        ViewGroup.LayoutParams params = view.getLayoutParams();
        if (params instanceof ViewGroup.MarginLayoutParams) {
            ViewGroup.MarginLayoutParams marginParams = (ViewGroup.MarginLayoutParams) params;
            Context context = view.getContext();
            marginParams.setMargins(
                    DisplayHelper.dpToPx(context, leftDp),
                    DisplayHelper.dpToPx(context, topDp),
                    DisplayHelper.dpToPx(context, rightDp),
                    DisplayHelper.dpToPx(context, bottomDp)
            );
            view.setLayoutParams(marginParams);
        }
    }
    
    /**
     * Set view size in dp.
     * 
     * @param view View
     * @param widthDp Width in dp (or MATCH_PARENT/WRAP_CONTENT)
     * @param heightDp Height in dp (or MATCH_PARENT/WRAP_CONTENT)
     */
    public static void setSizeDp(@NonNull View view, int widthDp, int heightDp) {
        ViewGroup.LayoutParams params = view.getLayoutParams();
        if (params != null) {
            Context context = view.getContext();
            params.width = widthDp >= 0 ? DisplayHelper.dpToPx(context, widthDp) : widthDp;
            params.height = heightDp >= 0 ? DisplayHelper.dpToPx(context, heightDp) : heightDp;
            view.setLayoutParams(params);
        }
    }
    
    /**
     * Post a runnable to view's message queue.
     * 
     * @param view View
     * @param action Runnable to execute
     */
    public static void post(@Nullable View view, @NonNull Runnable action) {
        if (view != null) {
            view.post(action);
        }
    }
    
    /**
     * Post a delayed runnable to view's message queue.
     * 
     * @param view View
     * @param action Runnable to execute
     * @param delayMs Delay in milliseconds
     */
    public static void postDelayed(@Nullable View view, @NonNull Runnable action, long delayMs) {
        if (view != null) {
            view.postDelayed(action, delayMs);
        }
    }
    
    /**
     * Remove callbacks from view.
     * 
     * @param view View
     * @param action Runnable to remove
     */
    public static void removeCallbacks(@Nullable View view, @NonNull Runnable action) {
        if (view != null) {
            view.removeCallbacks(action);
        }
    }
    
    private ViewHelper() {
        // Prevent instantiation
    }
}
