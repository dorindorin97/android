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
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import org.csploit.android.BuildConfig;

/**
 * Helper class for application information and version management.
 */
public class AppInfoHelper {
    
    private static final String TAG = "AppInfoHelper";
    
    /**
     * Get the application version name.
     * 
     * @param context Application context
     * @return Version name string (e.g., "1.8.0-stable")
     */
    @NonNull
    public static String getVersionName(@NonNull Context context) {
        try {
            PackageInfo packageInfo = context.getPackageManager()
                    .getPackageInfo(context.getPackageName(), 0);
            return packageInfo.versionName != null ? packageInfo.versionName : "unknown";
        } catch (PackageManager.NameNotFoundException e) {
            LoggingHelper.e(TAG, "Failed to get version name", e);
            return "unknown";
        }
    }
    
    /**
     * Get the application version code.
     * 
     * @param context Application context
     * @return Version code (e.g., 6)
     */
    public static long getVersionCode(@NonNull Context context) {
        try {
            PackageInfo packageInfo = context.getPackageManager()
                    .getPackageInfo(context.getPackageName(), 0);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                return packageInfo.getLongVersionCode();
            } else {
                return packageInfo.versionCode;
            }
        } catch (PackageManager.NameNotFoundException e) {
            LoggingHelper.e(TAG, "Failed to get version code", e);
            return -1;
        }
    }
    
    /**
     * Get the application package name.
     * 
     * @param context Application context
     * @return Package name (e.g., "org.csploit.android")
     */
    @NonNull
    public static String getPackageName(@NonNull Context context) {
        return context.getPackageName();
    }
    
    /**
     * Get the application name.
     * 
     * @param context Application context
     * @return Application name
     */
    @NonNull
    public static String getAppName(@NonNull Context context) {
        ApplicationInfo applicationInfo = context.getApplicationInfo();
        int stringId = applicationInfo.labelRes;
        return stringId == 0 ? applicationInfo.nonLocalizedLabel.toString() 
                            : context.getString(stringId);
    }
    
    /**
     * Check if the app is running in debug mode.
     * 
     * @return true if debug build
     */
    public static boolean isDebugBuild() {
        return BuildConfig.DEBUG;
    }
    
    /**
     * Get the build type (debug/release).
     * 
     * @return Build type string
     */
    @NonNull
    public static String getBuildType() {
        return BuildConfig.BUILD_TYPE;
    }
    
    /**
     * Get the first install time.
     * 
     * @param context Application context
     * @return First install timestamp in milliseconds, or -1 if unavailable
     */
    public static long getFirstInstallTime(@NonNull Context context) {
        try {
            PackageInfo packageInfo = context.getPackageManager()
                    .getPackageInfo(context.getPackageName(), 0);
            return packageInfo.firstInstallTime;
        } catch (PackageManager.NameNotFoundException e) {
            LoggingHelper.e(TAG, "Failed to get first install time", e);
            return -1;
        }
    }
    
    /**
     * Get the last update time.
     * 
     * @param context Application context
     * @return Last update timestamp in milliseconds, or -1 if unavailable
     */
    public static long getLastUpdateTime(@NonNull Context context) {
        try {
            PackageInfo packageInfo = context.getPackageManager()
                    .getPackageInfo(context.getPackageName(), 0);
            return packageInfo.lastUpdateTime;
        } catch (PackageManager.NameNotFoundException e) {
            LoggingHelper.e(TAG, "Failed to get last update time", e);
            return -1;
        }
    }
    
    /**
     * Get comprehensive app info as formatted string.
     * 
     * @param context Application context
     * @return Formatted app info string
     */
    @NonNull
    public static String getAppInfoString(@NonNull Context context) {
        StringBuilder sb = new StringBuilder();
        sb.append("App: ").append(getAppName(context)).append("\n");
        sb.append("Package: ").append(getPackageName(context)).append("\n");
        sb.append("Version: ").append(getVersionName(context)).append("\n");
        sb.append("Version Code: ").append(getVersionCode(context)).append("\n");
        sb.append("Build Type: ").append(getBuildType()).append("\n");
        sb.append("Debug: ").append(isDebugBuild()).append("\n");
        return sb.toString();
    }
    
    /**
     * Get device and system info for debugging.
     * 
     * @return Formatted device info string
     */
    @NonNull
    public static String getDeviceInfoString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Device: ").append(Build.MANUFACTURER).append(" ").append(Build.MODEL).append("\n");
        sb.append("Android: ").append(Build.VERSION.RELEASE).append("\n");
        sb.append("SDK: ").append(Build.VERSION.SDK_INT).append("\n");
        sb.append("Build: ").append(Build.DISPLAY).append("\n");
        sb.append("Hardware: ").append(Build.HARDWARE).append("\n");
        sb.append("Board: ").append(Build.BOARD).append("\n");
        return sb.toString();
    }
    
    /**
     * Check if app was installed from Play Store.
     * 
     * @param context Application context
     * @return true if installed from Play Store
     */
    public static boolean isInstalledFromPlayStore(@NonNull Context context) {
        String installer = getInstallerPackageName(context);
        return "com.android.vending".equals(installer) || 
               "com.google.android.feedback".equals(installer);
    }
    
    /**
     * Get the installer package name.
     * 
     * @param context Application context
     * @return Installer package name or null if unknown
     */
    @Nullable
    public static String getInstallerPackageName(@NonNull Context context) {
        try {
            PackageManager pm = context.getPackageManager();
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                return pm.getInstallSourceInfo(context.getPackageName())
                        .getInstallingPackageName();
            } else {
                return pm.getInstallerPackageName(context.getPackageName());
            }
        } catch (Exception e) {
            LoggingHelper.w(TAG, "Failed to get installer package name", e);
            return null;
        }
    }
    
    /**
     * Get target SDK version.
     * 
     * @param context Application context
     * @return Target SDK version
     */
    public static int getTargetSdkVersion(@NonNull Context context) {
        return context.getApplicationInfo().targetSdkVersion;
    }
    
    /**
     * Get minimum SDK version.
     * 
     * @param context Application context
     * @return Minimum SDK version
     */
    public static int getMinSdkVersion(@NonNull Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            return context.getApplicationInfo().minSdkVersion;
        }
        return -1;
    }
    
    private AppInfoHelper() {
        // Prevent instantiation
    }
}
