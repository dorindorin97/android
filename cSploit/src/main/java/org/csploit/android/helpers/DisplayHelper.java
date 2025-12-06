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
import android.graphics.Point;
import android.os.Build;
import android.util.DisplayMetrics;
import android.view.Display;
import android.view.WindowManager;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

/**
 * Helper class for display and screen operations.
 * Provides utilities for screen dimensions and density.
 */
public class DisplayHelper {
    
    // Density buckets
    public static final int DENSITY_LOW = 120;      // ldpi
    public static final int DENSITY_MEDIUM = 160;   // mdpi
    public static final int DENSITY_HIGH = 240;     // hdpi
    public static final int DENSITY_XHIGH = 320;    // xhdpi
    public static final int DENSITY_XXHIGH = 480;   // xxhdpi
    public static final int DENSITY_XXXHIGH = 640;  // xxxhdpi
    
    /**
     * Get WindowManager.
     * 
     * @param context Context
     * @return WindowManager
     */
    @Nullable
    public static WindowManager getWindowManager(@NonNull Context context) {
        return (WindowManager) context.getSystemService(Context.WINDOW_SERVICE);
    }
    
    /**
     * Get default display.
     * 
     * @param context Context
     * @return Display
     */
    @Nullable
    @SuppressWarnings("deprecation")
    public static Display getDefaultDisplay(@NonNull Context context) {
        WindowManager wm = getWindowManager(context);
        return wm != null ? wm.getDefaultDisplay() : null;
    }
    
    /**
     * Get display metrics.
     * 
     * @param context Context
     * @return DisplayMetrics
     */
    @NonNull
    public static DisplayMetrics getDisplayMetrics(@NonNull Context context) {
        return context.getResources().getDisplayMetrics();
    }
    
    /**
     * Get screen width in pixels.
     * 
     * @param context Context
     * @return Screen width in pixels
     */
    public static int getScreenWidthPx(@NonNull Context context) {
        return getDisplayMetrics(context).widthPixels;
    }
    
    /**
     * Get screen height in pixels.
     * 
     * @param context Context
     * @return Screen height in pixels
     */
    public static int getScreenHeightPx(@NonNull Context context) {
        return getDisplayMetrics(context).heightPixels;
    }
    
    /**
     * Get real screen width in pixels (including system UI).
     * 
     * @param context Context
     * @return Real screen width
     */
    @SuppressWarnings("deprecation")
    public static int getRealScreenWidthPx(@NonNull Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            WindowManager wm = getWindowManager(context);
            if (wm != null) {
                return wm.getCurrentWindowMetrics().getBounds().width();
            }
        }
        
        Display display = getDefaultDisplay(context);
        if (display != null) {
            Point size = new Point();
            display.getRealSize(size);
            return size.x;
        }
        return getScreenWidthPx(context);
    }
    
    /**
     * Get real screen height in pixels (including system UI).
     * 
     * @param context Context
     * @return Real screen height
     */
    @SuppressWarnings("deprecation")
    public static int getRealScreenHeightPx(@NonNull Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            WindowManager wm = getWindowManager(context);
            if (wm != null) {
                return wm.getCurrentWindowMetrics().getBounds().height();
            }
        }
        
        Display display = getDefaultDisplay(context);
        if (display != null) {
            Point size = new Point();
            display.getRealSize(size);
            return size.y;
        }
        return getScreenHeightPx(context);
    }
    
    /**
     * Get screen density.
     * 
     * @param context Context
     * @return Screen density
     */
    public static float getDensity(@NonNull Context context) {
        return getDisplayMetrics(context).density;
    }
    
    /**
     * Get screen density DPI.
     * 
     * @param context Context
     * @return Screen density DPI
     */
    public static int getDensityDpi(@NonNull Context context) {
        return getDisplayMetrics(context).densityDpi;
    }
    
    /**
     * Get scaled density (for text).
     * 
     * @param context Context
     * @return Scaled density
     */
    public static float getScaledDensity(@NonNull Context context) {
        return getDisplayMetrics(context).scaledDensity;
    }
    
    /**
     * Convert dp to pixels.
     * 
     * @param context Context
     * @param dp DP value
     * @return Pixel value
     */
    public static int dpToPx(@NonNull Context context, float dp) {
        return Math.round(dp * getDensity(context));
    }
    
    /**
     * Convert pixels to dp.
     * 
     * @param context Context
     * @param px Pixel value
     * @return DP value
     */
    public static float pxToDp(@NonNull Context context, int px) {
        return px / getDensity(context);
    }
    
    /**
     * Convert sp to pixels.
     * 
     * @param context Context
     * @param sp SP value
     * @return Pixel value
     */
    public static int spToPx(@NonNull Context context, float sp) {
        return Math.round(sp * getScaledDensity(context));
    }
    
    /**
     * Convert pixels to sp.
     * 
     * @param context Context
     * @param px Pixel value
     * @return SP value
     */
    public static float pxToSp(@NonNull Context context, int px) {
        return px / getScaledDensity(context);
    }
    
    /**
     * Get screen width in dp.
     * 
     * @param context Context
     * @return Screen width in dp
     */
    public static float getScreenWidthDp(@NonNull Context context) {
        return pxToDp(context, getScreenWidthPx(context));
    }
    
    /**
     * Get screen height in dp.
     * 
     * @param context Context
     * @return Screen height in dp
     */
    public static float getScreenHeightDp(@NonNull Context context) {
        return pxToDp(context, getScreenHeightPx(context));
    }
    
    /**
     * Get smallest width in dp (for sw qualifiers).
     * 
     * @param context Context
     * @return Smallest width in dp
     */
    public static int getSmallestWidthDp(@NonNull Context context) {
        return context.getResources().getConfiguration().smallestScreenWidthDp;
    }
    
    /**
     * Check if device is tablet (sw >= 600dp).
     * 
     * @param context Context
     * @return true if tablet
     */
    public static boolean isTablet(@NonNull Context context) {
        return getSmallestWidthDp(context) >= 600;
    }
    
    /**
     * Check if device is large tablet (sw >= 720dp).
     * 
     * @param context Context
     * @return true if large tablet
     */
    public static boolean isLargeTablet(@NonNull Context context) {
        return getSmallestWidthDp(context) >= 720;
    }
    
    /**
     * Check if device is in portrait orientation.
     * 
     * @param context Context
     * @return true if portrait
     */
    public static boolean isPortrait(@NonNull Context context) {
        return getScreenWidthPx(context) < getScreenHeightPx(context);
    }
    
    /**
     * Check if device is in landscape orientation.
     * 
     * @param context Context
     * @return true if landscape
     */
    public static boolean isLandscape(@NonNull Context context) {
        return getScreenWidthPx(context) >= getScreenHeightPx(context);
    }
    
    /**
     * Get density bucket name.
     * 
     * @param context Context
     * @return Density bucket name
     */
    @NonNull
    public static String getDensityBucket(@NonNull Context context) {
        int dpi = getDensityDpi(context);
        if (dpi <= DENSITY_LOW) {
            return "ldpi";
        } else if (dpi <= DENSITY_MEDIUM) {
            return "mdpi";
        } else if (dpi <= DENSITY_HIGH) {
            return "hdpi";
        } else if (dpi <= DENSITY_XHIGH) {
            return "xhdpi";
        } else if (dpi <= DENSITY_XXHIGH) {
            return "xxhdpi";
        } else {
            return "xxxhdpi";
        }
    }
    
    /**
     * Get refresh rate.
     * 
     * @param context Context
     * @return Refresh rate in Hz
     */
    @SuppressWarnings("deprecation")
    public static float getRefreshRate(@NonNull Context context) {
        Display display = getDefaultDisplay(context);
        return display != null ? display.getRefreshRate() : 60f;
    }
    
    /**
     * Get status bar height.
     * 
     * @param context Context
     * @return Status bar height in pixels
     */
    public static int getStatusBarHeight(@NonNull Context context) {
        int resourceId = context.getResources().getIdentifier("status_bar_height", "dimen", "android");
        if (resourceId > 0) {
            return context.getResources().getDimensionPixelSize(resourceId);
        }
        return dpToPx(context, 24); // Default
    }
    
    /**
     * Get navigation bar height.
     * 
     * @param context Context
     * @return Navigation bar height in pixels
     */
    public static int getNavigationBarHeight(@NonNull Context context) {
        int resourceId = context.getResources().getIdentifier("navigation_bar_height", "dimen", "android");
        if (resourceId > 0) {
            return context.getResources().getDimensionPixelSize(resourceId);
        }
        return dpToPx(context, 48); // Default
    }
    
    /**
     * Get action bar height.
     * 
     * @param context Context
     * @return Action bar height in pixels
     */
    public static int getActionBarHeight(@NonNull Context context) {
        int[] attrs = new int[] { android.R.attr.actionBarSize };
        android.content.res.TypedArray ta = context.obtainStyledAttributes(attrs);
        int height = ta.getDimensionPixelSize(0, dpToPx(context, 56));
        ta.recycle();
        return height;
    }
    
    /**
     * Check if has navigation bar.
     * 
     * @param context Context
     * @return true if device has navigation bar
     */
    public static boolean hasNavigationBar(@NonNull Context context) {
        int resourceId = context.getResources().getIdentifier("config_showNavigationBar", "bool", "android");
        if (resourceId > 0) {
            return context.getResources().getBoolean(resourceId);
        }
        return false;
    }
    
    /**
     * Keep screen on.
     * 
     * @param activity Activity
     * @param keepOn Whether to keep screen on
     */
    public static void setKeepScreenOn(@NonNull Activity activity, boolean keepOn) {
        if (keepOn) {
            activity.getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        } else {
            activity.getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        }
    }
    
    /**
     * Set brightness level.
     * 
     * @param activity Activity
     * @param brightness Brightness (0-1, or WindowManager.LayoutParams.BRIGHTNESS_OVERRIDE_NONE)
     */
    public static void setBrightness(@NonNull Activity activity, float brightness) {
        WindowManager.LayoutParams params = activity.getWindow().getAttributes();
        params.screenBrightness = brightness;
        activity.getWindow().setAttributes(params);
    }
    
    private DisplayHelper() {
        // Prevent instantiation
    }
}
