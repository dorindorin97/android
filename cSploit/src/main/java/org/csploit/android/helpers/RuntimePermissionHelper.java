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

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import androidx.annotation.NonNull;
import androidx.core.content.ContextCompat;

import java.util.ArrayList;
import java.util.List;

/**
 * Helper class for runtime permission management.
 * Provides centralized permission checking and request handling.
 */
public class RuntimePermissionHelper {
    
    private static final String TAG = "RuntimePermissionHelper";
    
    // Permission groups
    public static final String[] STORAGE_PERMISSIONS = Build.VERSION.SDK_INT >= 33 
            ? new String[] {}  // No storage permissions needed for Android 13+
            : new String[] { Manifest.permission.WRITE_EXTERNAL_STORAGE };
    
    public static final String[] LOCATION_PERMISSIONS = {
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION
    };
    
    public static final String[] NETWORK_PERMISSIONS = {
            Manifest.permission.ACCESS_NETWORK_STATE,
            Manifest.permission.ACCESS_WIFI_STATE,
            Manifest.permission.CHANGE_WIFI_STATE,
            Manifest.permission.INTERNET
    };
    
    /**
     * Check if a single permission is granted.
     * 
     * @param context Application context
     * @param permission Permission to check
     * @return true if permission is granted
     */
    public static boolean hasPermission(@NonNull Context context, @NonNull String permission) {
        return ContextCompat.checkSelfPermission(context, permission) 
                == PackageManager.PERMISSION_GRANTED;
    }
    
    /**
     * Check if all permissions in an array are granted.
     * 
     * @param context Application context
     * @param permissions Array of permissions to check
     * @return true if all permissions are granted
     */
    public static boolean hasPermissions(@NonNull Context context, @NonNull String[] permissions) {
        for (String permission : permissions) {
            if (!hasPermission(context, permission)) {
                return false;
            }
        }
        return true;
    }
    
    /**
     * Get list of permissions that are not granted.
     * 
     * @param context Application context
     * @param permissions Array of permissions to check
     * @return List of denied permissions
     */
    @NonNull
    public static List<String> getDeniedPermissions(@NonNull Context context, 
                                                     @NonNull String[] permissions) {
        List<String> denied = new ArrayList<>();
        for (String permission : permissions) {
            if (!hasPermission(context, permission)) {
                denied.add(permission);
            }
        }
        return denied;
    }
    
    /**
     * Check if storage permissions are granted.
     * 
     * @param context Application context
     * @return true if storage permissions are granted
     */
    public static boolean hasStoragePermission(@NonNull Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            // Android 13+ doesn't need explicit storage permissions for app-specific storage
            return true;
        }
        return hasPermissions(context, STORAGE_PERMISSIONS);
    }
    
    /**
     * Check if location permissions are granted.
     * 
     * @param context Application context
     * @return true if any location permission is granted
     */
    public static boolean hasLocationPermission(@NonNull Context context) {
        return hasPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) ||
               hasPermission(context, Manifest.permission.ACCESS_COARSE_LOCATION);
    }
    
    /**
     * Check if fine location permission is granted.
     * 
     * @param context Application context
     * @return true if fine location permission is granted
     */
    public static boolean hasFineLocationPermission(@NonNull Context context) {
        return hasPermission(context, Manifest.permission.ACCESS_FINE_LOCATION);
    }
    
    /**
     * Check if network state permissions are granted.
     * 
     * @param context Application context
     * @return true if network state permissions are granted
     */
    public static boolean hasNetworkStatePermission(@NonNull Context context) {
        return hasPermission(context, Manifest.permission.ACCESS_NETWORK_STATE);
    }
    
    /**
     * Check if WiFi state permissions are granted.
     * 
     * @param context Application context
     * @return true if WiFi state permissions are granted
     */
    public static boolean hasWifiStatePermission(@NonNull Context context) {
        return hasPermission(context, Manifest.permission.ACCESS_WIFI_STATE);
    }
    
    /**
     * Check if internet permission is granted.
     * 
     * @param context Application context
     * @return true if internet permission is granted
     */
    public static boolean hasInternetPermission(@NonNull Context context) {
        return hasPermission(context, Manifest.permission.INTERNET);
    }
    
    /**
     * Check if wake lock permission is granted.
     * 
     * @param context Application context
     * @return true if wake lock permission is granted
     */
    public static boolean hasWakeLockPermission(@NonNull Context context) {
        return hasPermission(context, Manifest.permission.WAKE_LOCK);
    }
    
    /**
     * Get all required permissions based on SDK version.
     * 
     * @return Array of required permissions
     */
    @NonNull
    public static String[] getRequiredPermissions() {
        List<String> permissions = new ArrayList<>();
        
        // Always needed
        permissions.add(Manifest.permission.WAKE_LOCK);
        permissions.add(Manifest.permission.ACCESS_NETWORK_STATE);
        permissions.add(Manifest.permission.ACCESS_WIFI_STATE);
        permissions.add(Manifest.permission.CHANGE_WIFI_STATE);
        permissions.add(Manifest.permission.INTERNET);
        
        // Location for WiFi scanning on Android 8.0+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            permissions.add(Manifest.permission.ACCESS_FINE_LOCATION);
        }
        
        // Storage for older Android versions
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            permissions.add(Manifest.permission.WRITE_EXTERNAL_STORAGE);
        }
        
        return permissions.toArray(new String[0]);
    }
    
    /**
     * Get missing required permissions.
     * 
     * @param context Application context
     * @return Array of missing required permissions
     */
    @NonNull
    public static String[] getMissingRequiredPermissions(@NonNull Context context) {
        return getDeniedPermissions(context, getRequiredPermissions()).toArray(new String[0]);
    }
    
    /**
     * Check if all required permissions are granted.
     * 
     * @param context Application context
     * @return true if all required permissions are granted
     */
    public static boolean hasAllRequiredPermissions(@NonNull Context context) {
        return getMissingRequiredPermissions(context).length == 0;
    }
    
    /**
     * Get human-readable name for a permission.
     * 
     * @param permission Permission string
     * @return Human-readable name
     */
    @NonNull
    public static String getPermissionName(@NonNull String permission) {
        switch (permission) {
            case Manifest.permission.WRITE_EXTERNAL_STORAGE:
                return "Storage";
            case Manifest.permission.ACCESS_FINE_LOCATION:
                return "Fine Location";
            case Manifest.permission.ACCESS_COARSE_LOCATION:
                return "Coarse Location";
            case Manifest.permission.ACCESS_NETWORK_STATE:
                return "Network State";
            case Manifest.permission.ACCESS_WIFI_STATE:
                return "WiFi State";
            case Manifest.permission.CHANGE_WIFI_STATE:
                return "Change WiFi";
            case Manifest.permission.INTERNET:
                return "Internet";
            case Manifest.permission.WAKE_LOCK:
                return "Wake Lock";
            default:
                // Extract last part of permission string
                String[] parts = permission.split("\\.");
                return parts[parts.length - 1].replace("_", " ");
        }
    }
    
    private RuntimePermissionHelper() {
        // Prevent instantiation
    }
}
