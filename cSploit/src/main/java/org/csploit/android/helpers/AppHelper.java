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
import org.csploit.android.helpers.LoggingHelper;
import android.content.pm.ApplicationInfo;
import org.csploit.android.helpers.LoggingHelper;
import android.content.pm.PackageInfo;
import org.csploit.android.helpers.LoggingHelper;
import android.content.pm.PackageManager;
import org.csploit.android.helpers.LoggingHelper;
import android.os.Build;
import org.csploit.android.helpers.LoggingHelper;

import androidx.annotation.NonNull;
import org.csploit.android.helpers.LoggingHelper;

import com.github.zafarkhaja.semver.Version;
import org.csploit.android.helpers.LoggingHelper;

/**
 * AppHelper - Application information and state management utility
 *
 * Provides centralized access to application version, build information,
 * and state management. Replaces scattered PackageManager calls and
 * BuildConfig access throughout the codebase.
 *
 * Features:
 * - Application version code and name retrieval
 * - Build information and metadata
 * - Semantic versioning support
 * - Application signature verification
 * - Debug and release build detection
 * - Application state and lifecycle management
 *
 * Usage:
 * {@code
 * String version = AppHelper.getVersionName(context);
 * int versionCode = AppHelper.getVersionCode(context);
 * if (AppHelper.isDebugBuild(context)) {
 *     // Debug-specific code
 * }
 * String signature = AppHelper.getAppSignature(context);
 * boolean isNewer = AppHelper.compareVersions("1.2.3", "1.2.0") > 0;
 * }
 *
 * @author cSploit Team
 * @version 1.0
 */
public final class AppHelper {

    private static final String TAG = "AppHelper";

    // Cache for app info to avoid repeated PackageManager calls
    private static volatile PackageInfo cachedPackageInfo;
    private static volatile ApplicationInfo cachedAppInfo;
    private static volatile Long lastCacheTime = 0L;
    private static final long CACHE_VALIDITY_MS = 5 * 60 * 1000;  // 5 minutes

    // Private constructor to prevent instantiation
    private AppHelper() {}

    /**
     * Get application version name
     *
     * @param context Android context
     * @return version name (e.g., "1.2.3") or "unknown"
     */
    @NonNull
    public static String getVersionName(@NonNull Context context) {
        try {
            PackageInfo info = getPackageInfo(context);
            if (info != null && info.versionName != null) {
                return info.versionName;
            }
        } catch (Exception e) {
            LoggingHelper.e(TAG, "Failed to get version name", e);
        }
        return "unknown";
    }

    /**
     * Get application version code
     *
     * @param context Android context
     * @return version code (e.g., 123) or 0
     */
    public static int getVersionCode(@NonNull Context context) {
        try {
            PackageInfo info = getPackageInfo(context);
            if (info != null) {
                return (int) getVersionCodeLong(info);
            }
        } catch (Exception e) {
            LoggingHelper.e(TAG, "Failed to get version code", e);
        }
        return 0;
    }

    /**
     * Get application version code as long (for API 28+)
     *
     * @param context Android context
     * @return version code long
     */
    public static long getVersionCodeLong(@NonNull Context context) {
        try {
            PackageInfo info = getPackageInfo(context);
            return getVersionCodeLong(info);
        } catch (Exception e) {
            LoggingHelper.e(TAG, "Failed to get version code long", e);
        }
        return 0L;
    }

    /**
     * Extract version code from PackageInfo (handles API version differences)
     */
    private static long getVersionCodeLong(@NonNull PackageInfo info) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            return info.longVersionCode;
        } else {
            return info.versionCode;
        }
    }

    /**
     * Get application package name
     *
     * @param context Android context
     * @return package name (e.g., "org.csploit.android")
     */
    @NonNull
    public static String getPackageName(@NonNull Context context) {
        return context.getPackageName();
    }

    /**
     * Get build time (if available in BuildConfig)
     *
     * @return build time string or "unknown"
     */
    @NonNull
    public static String getBuildTime() {
        try {
            Class<?> buildConfig = Class.forName("org.csploit.android.BuildConfig");
            Object buildTime = buildConfig.getField("BUILD_TIME").get(null);
            return buildTime != null ? buildTime.toString() : "unknown";
        } catch (Exception e) {
            LoggingHelper.e(TAG, "Failed to get build time", e);
        }
        return "unknown";
    }

    /**
     * Get build name (builder/CI system)
     *
     * @return build name or "unknown"
     */
    @NonNull
    public static String getBuildName() {
        try {
            Class<?> buildConfig = Class.forName("org.csploit.android.BuildConfig");
            Object buildName = buildConfig.getField("BUILD_NAME").get(null);
            return buildName != null ? buildName.toString() : "unknown";
        } catch (Exception e) {
            LoggingHelper.e(TAG, "Failed to get build name", e);
        }
        return "unknown";
    }

    /**
     * Check if application is debug build
     *
     * @param context Android context
     * @return true if debug build
     */
    public static boolean isDebugBuild(@NonNull Context context) {
        try {
            ApplicationInfo info = getApplicationInfo(context);
            if (info != null) {
                return (info.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
            }
        } catch (Exception e) {
            LoggingHelper.e(TAG, "Failed to check if debug build", e);
        }
        return false;
    }

    /**
     * Get application flags
     *
     * @param context Android context
     * @return application flags
     */
    public static int getApplicationFlags(@NonNull Context context) {
        try {
            ApplicationInfo info = getApplicationInfo(context);
            if (info != null) {
                return info.flags;
            }
        } catch (Exception e) {
            LoggingHelper.e(TAG, "Failed to get application flags", e);
        }
        return 0;
    }

    /**
     * Get application target SDK level
     *
     * @param context Android context
     * @return target SDK level
     */
    public static int getTargetSdkLevel(@NonNull Context context) {
        try {
            ApplicationInfo info = getApplicationInfo(context);
            if (info != null) {
                return info.targetSdkVersion;
            }
        } catch (Exception e) {
            LoggingHelper.e(TAG, "Failed to get target SDK level", e);
        }
        return 0;
    }

    /**
     * Get application minimum SDK level
     *
     * @param context Android context
     * @return minimum SDK level
     */
    public static int getMinSdkLevel(@NonNull Context context) {
        try {
            ApplicationInfo info = getApplicationInfo(context);
            if (info != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                return info.minSdkVersion;
            }
        } catch (Exception e) {
            LoggingHelper.e(TAG, "Failed to get min SDK level", e);
        }
        return 0;
    }

    /**
     * Get application process name
     *
     * @param context Android context
     * @return process name
     */
    @NonNull
    public static String getProcessName(@NonNull Context context) {
        try {
            ApplicationInfo info = getApplicationInfo(context);
            if (info != null && info.processName != null) {
                return info.processName;
            }
        } catch (Exception e) {
            LoggingHelper.e(TAG, "Failed to get process name", e);
        }
        return context.getPackageName();
    }

    /**
     * Compare two semantic versions
     *
     * @param version1 first version (e.g., "1.2.3")
     * @param version2 second version (e.g., "1.2.0")
     * @return negative if version1 < version2, zero if equal, positive if version1 > version2
     */
    public static int compareVersions(@NonNull String version1, @NonNull String version2) {
        try {
            Version v1 = Version.valueOf(version1);
            Version v2 = Version.valueOf(version2);
            return v1.compareTo(v2);
        } catch (Exception e) {
            LoggingHelper.w(TAG, "Failed to compare versions: " + version1 + " vs " + version2, e);
            // Fallback to string comparison
            return version1.compareTo(version2);
        }
    }

    /**
     * Check if version1 is newer than version2
     *
     * @param version1 first version
     * @param version2 second version
     * @return true if version1 > version2
     */
    public static boolean isNewerVersion(@NonNull String version1, @NonNull String version2) {
        return compareVersions(version1, version2) > 0;
    }

    /**
     * Check if version1 is older than version2
     *
     * @param version1 first version
     * @param version2 second version
     * @return true if version1 < version2
     */
    public static boolean isOlderVersion(@NonNull String version1, @NonNull String version2) {
        return compareVersions(version1, version2) < 0;
    }

    /**
     * Get application signature (for security verification)
     *
     * @param context Android context
     * @return application signature or null
     */
    public static String getAppSignature(@NonNull Context context) {
        try {
            PackageInfo info = getPackageInfo(context);
            if (info != null && info.signatures != null && info.signatures.length > 0) {
                return info.signatures[0].toCharsString();
            }
        } catch (Exception e) {
            LoggingHelper.e(TAG, "Failed to get app signature", e);
        }
        return null;
    }

    /**
     * Get first installed app time
     *
     * @param context Android context
     * @return installation time in milliseconds
     */
    public static long getInstallationTime(@NonNull Context context) {
        try {
            PackageInfo info = getPackageInfo(context);
            if (info != null) {
                return info.firstInstallTime;
            }
        } catch (Exception e) {
            LoggingHelper.e(TAG, "Failed to get installation time", e);
        }
        return 0L;
    }

    /**
     * Get last updated app time
     *
     * @param context Android context
     * @return last update time in milliseconds
     */
    public static long getLastUpdateTime(@NonNull Context context) {
        try {
            PackageInfo info = getPackageInfo(context);
            if (info != null) {
                return info.lastUpdateTime;
            }
        } catch (Exception e) {
            LoggingHelper.e(TAG, "Failed to get last update time", e);
        }
        return 0L;
    }

    /**
     * Get comprehensive app info summary
     *
     * @param context Android context
     * @return formatted app info
     */
    @NonNull
    public static String getAppInfo(@NonNull Context context) {
        StringBuilder sb = new StringBuilder();
        sb.append("Package: ").append(getPackageName(context)).append("\n");
        sb.append("Version: ").append(getVersionName(context)).append(" (").append(getVersionCode(context)).append(")\n");
        sb.append("Target SDK: ").append(getTargetSdkLevel(context)).append("\n");
        sb.append("Min SDK: ").append(getMinSdkLevel(context)).append("\n");
        sb.append("Debug: ").append(isDebugBuild(context)).append("\n");
        sb.append("Build: ").append(getBuildName(context)).append("\n");
        sb.append("Built: ").append(getBuildTime(context)).append("\n");
        sb.append("Installed: ").append(getInstallationTime(context)).append("\n");
        sb.append("Updated: ").append(getLastUpdateTime(context)).append("\n");
        return sb.toString();
    }

    /**
     * Clear cached app information
     *
     * Useful when app info may have changed (after update, etc.)
     */
    public static void clearCache() {
        cachedPackageInfo = null;
        cachedAppInfo = null;
        lastCacheTime = 0L;
        LoggingHelper.d(TAG, "App cache cleared");
    }

    /**
     * Get cached or fresh PackageInfo
     *
     * @param context Android context
     * @return PackageInfo or null
     */
    private static PackageInfo getPackageInfo(@NonNull Context context) {
        // Check cache validity
        long currentTime = System.currentTimeMillis();
        if (cachedPackageInfo != null && (currentTime - lastCacheTime) < CACHE_VALIDITY_MS) {
            return cachedPackageInfo;
        }

        try {
            PackageManager pm = context.getPackageManager();
            if (pm != null) {
                cachedPackageInfo = pm.getPackageInfo(context.getPackageName(), 0);
                lastCacheTime = currentTime;
                return cachedPackageInfo;
            }
        } catch (PackageManager.NameNotFoundException e) {
            LoggingHelper.e(TAG, "Package not found", e);
        }
        return null;
    }

    /**
     * Get cached or fresh ApplicationInfo
     *
     * @param context Android context
     * @return ApplicationInfo or null
     */
    private static ApplicationInfo getApplicationInfo(@NonNull Context context) {
        // Check cache validity
        long currentTime = System.currentTimeMillis();
        if (cachedAppInfo != null && (currentTime - lastCacheTime) < CACHE_VALIDITY_MS) {
            return cachedAppInfo;
        }

        try {
            PackageManager pm = context.getPackageManager();
            if (pm != null) {
                cachedAppInfo = pm.getApplicationInfo(context.getPackageName(), 0);
                lastCacheTime = currentTime;
                return cachedAppInfo;
            }
        } catch (PackageManager.NameNotFoundException e) {
            LoggingHelper.e(TAG, "Application not found", e);
        }
        return null;
    }

    /**
     * Get app state information
     *
     * @param context Android context
     * @return state information map
     */
    @NonNull
    public static String getAppStateInfo(@NonNull Context context) {
        StringBuilder sb = new StringBuilder();
        sb.append("isDebugBuild: ").append(isDebugBuild(context)).append("\n");
        sb.append("targetSdk: ").append(getTargetSdkLevel(context)).append("\n");
        sb.append("minSdk: ").append(getMinSdkLevel(context)).append("\n");
        sb.append("process: ").append(getProcessName(context)).append("\n");
        sb.append("installTime: ").append(getInstallationTime(context)).append("\n");
        sb.append("updateTime: ").append(getLastUpdateTime(context)).append("\n");
        return sb.toString();
    }
}
