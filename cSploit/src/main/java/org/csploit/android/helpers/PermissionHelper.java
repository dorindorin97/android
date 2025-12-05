package org.csploit.android.helpers;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;

import androidx.annotation.NonNull;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import java.util.ArrayList;
import java.util.List;

/**
 * Permission utility helper for simplified runtime permission checks and requests on Android 6+.
 * 
 * Features:
 * - Simple permission checking
 * - Automatic permission request handling
 * - Batch permission requests
 * - Callback-based permission results
 * - Built-in common permission groups
 * 
 * Example:
 * <pre>
 * PermissionHelper.PermissionCallback callback = new PermissionHelper.PermissionCallback() {
 *     @Override
 *     public void onPermissionsGranted(List<String> grantedPermissions) {
 *         // Use granted permissions
 *     }
 *     
 *     @Override
 *     public void onPermissionsDenied(List<String> deniedPermissions) {
 *         // Handle denied permissions
 *     }
 * };
 * 
 * PermissionHelper.requestPermissions(
 *     activity,
 *     new String[]{Manifest.permission.INTERNET, Manifest.permission.ACCESS_WIFI_STATE},
 *     callback,
 *     101
 * );
 * </pre>
 */
public final class PermissionHelper {
    private static final String TAG = "PermissionHelper";
    
    // Common permission groups
    public static final String[] LOCATION_PERMISSIONS = {
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION
    };
    
    public static final String[] STORAGE_PERMISSIONS = {
            Manifest.permission.READ_EXTERNAL_STORAGE,
            Manifest.permission.WRITE_EXTERNAL_STORAGE
    };
    
    public static final String[] NETWORK_PERMISSIONS = {
            Manifest.permission.INTERNET,
            Manifest.permission.ACCESS_NETWORK_STATE,
            Manifest.permission.ACCESS_WIFI_STATE,
            Manifest.permission.CHANGE_NETWORK_STATE
    };
    
    public static final String[] CAMERA_PERMISSIONS = {
            Manifest.permission.CAMERA
    };
    
    public static final String[] PHONE_PERMISSIONS = {
            Manifest.permission.READ_PHONE_STATE
    };
    
    public static final String[] NOTIFICATION_PERMISSIONS = {
            Manifest.permission.POST_NOTIFICATIONS
    };
    
    // Callback interface for permission results
    public interface PermissionCallback {
        /**
         * Called when permissions are granted
         * @param grantedPermissions list of granted permissions
         */
        void onPermissionsGranted(@NonNull List<String> grantedPermissions);
        
        /**
         * Called when permissions are denied
         * @param deniedPermissions list of denied permissions
         */
        void onPermissionsDenied(@NonNull List<String> deniedPermissions);
    }
    
    /**
     * Check if a single permission is granted
     * 
     * @param context Android context
     * @param permission permission to check
     * @return true if permission is granted
     */
    public static boolean isPermissionGranted(@NonNull Context context, @NonNull String permission) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return true;  // Runtime permissions not required before Android 6
        }
        
        return ContextCompat.checkSelfPermission(context, permission) == 
               PackageManager.PERMISSION_GRANTED;
    }
    
    /**
     * Check if multiple permissions are granted
     * 
     * @param context Android context
     * @param permissions permissions to check
     * @return true if all permissions are granted
     */
    public static boolean arePermissionsGranted(@NonNull Context context, @NonNull String[] permissions) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return true;
        }
        
        for (String permission : permissions) {
            if (ContextCompat.checkSelfPermission(context, permission) != 
                PackageManager.PERMISSION_GRANTED) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Check if a permission should show a rationale (user previously denied)
     * 
     * @param activity Activity context
     * @param permission permission to check
     * @return true if rationale should be shown
     */
    public static boolean shouldShowRationale(@NonNull Activity activity, @NonNull String permission) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return false;
        }
        
        return ActivityCompat.shouldShowRequestPermissionRationale(activity, permission);
    }
    
    /**
     * Request a single permission
     * 
     * @param activity Activity context
     * @param permission permission to request
     * @param callback callback for results
     * @param requestCode unique request code
     */
    public static void requestPermission(
            @NonNull Activity activity,
            @NonNull String permission,
            @NonNull PermissionCallback callback,
            int requestCode) {
        
        requestPermissions(activity, new String[]{permission}, callback, requestCode);
    }
    
    /**
     * Request multiple permissions
     * 
     * @param activity Activity context
     * @param permissions permissions to request
     * @param callback callback for results
     * @param requestCode unique request code
     */
    public static void requestPermissions(
            @NonNull Activity activity,
            @NonNull String[] permissions,
            @NonNull PermissionCallback callback,
            int requestCode) {
        
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            // Pre-Android 6: all permissions granted
            List<String> grantedPermissions = new ArrayList<>();
            for (String permission : permissions) {
                grantedPermissions.add(permission);
            }
            callback.onPermissionsGranted(grantedPermissions);
            return;
        }
        
        // Check which permissions need to be requested
        List<String> permissionsToRequest = new ArrayList<>();
        List<String> grantedPermissions = new ArrayList<>();
        
        for (String permission : permissions) {
            if (ContextCompat.checkSelfPermission(activity, permission) == 
                PackageManager.PERMISSION_GRANTED) {
                grantedPermissions.add(permission);
            } else {
                permissionsToRequest.add(permission);
            }
        }
        
        // If no permissions need to be requested, call success
        if (permissionsToRequest.isEmpty()) {
            callback.onPermissionsGranted(grantedPermissions);
            return;
        }
        
        // Store callback for later use in onRequestPermissionsResult
        PermissionResultHandler.setCallback(requestCode, callback);
        
        // Request the remaining permissions
        ActivityCompat.requestPermissions(
                activity,
                permissionsToRequest.toArray(new String[0]),
                requestCode
        );
    }
    
    /**
     * Process permission request results
     * Call this from Activity.onRequestPermissionsResult()
     * 
     * @param requestCode request code
     * @param permissions permissions that were requested
     * @param grantResults grant results
     */
    public static void onRequestPermissionsResult(
            int requestCode,
            @NonNull String[] permissions,
            @NonNull int[] grantResults) {
        
        List<String> grantedPermissions = new ArrayList<>();
        List<String> deniedPermissions = new ArrayList<>();
        
        for (int i = 0; i < permissions.length; i++) {
            if (grantResults[i] == PackageManager.PERMISSION_GRANTED) {
                grantedPermissions.add(permissions[i]);
            } else {
                deniedPermissions.add(permissions[i]);
            }
        }
        
        PermissionCallback callback = PermissionResultHandler.getCallback(requestCode);
        
        if (callback != null) {
            if (deniedPermissions.isEmpty()) {
                callback.onPermissionsGranted(grantedPermissions);
            } else {
                callback.onPermissionsDenied(deniedPermissions);
            }
            
            PermissionResultHandler.removeCallback(requestCode);
        }
    }
    
    /**
     * Handler for storing callbacks across permission requests
     */
    private static class PermissionResultHandler {
        private static final java.util.Map<Integer, PermissionCallback> callbacks = 
                new java.util.HashMap<>();
        
        static void setCallback(int requestCode, PermissionCallback callback) {
            synchronized (callbacks) {
                callbacks.put(requestCode, callback);
            }
        }
        
        static PermissionCallback getCallback(int requestCode) {
            synchronized (callbacks) {
                return callbacks.get(requestCode);
            }
        }
        
        static void removeCallback(int requestCode) {
            synchronized (callbacks) {
                callbacks.remove(requestCode);
            }
        }
    }
    
    /**
     * Check if Android 6.0 (API 23) or higher is running
     * 
     * @return true if runtime permissions are supported
     */
    public static boolean runtimePermissionsSupported() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M;
    }
    
    /**
     * Get human-readable permission description
     * 
     * @param permission permission constant
     * @return human-readable description
     */
    public static String getPermissionDescription(@NonNull String permission) {
        switch (permission) {
            case Manifest.permission.INTERNET:
                return "Internet";
            case Manifest.permission.ACCESS_NETWORK_STATE:
                return "Network State";
            case Manifest.permission.ACCESS_WIFI_STATE:
                return "WiFi State";
            case Manifest.permission.CHANGE_NETWORK_STATE:
                return "Change Network";
            case Manifest.permission.ACCESS_FINE_LOCATION:
                return "Precise Location";
            case Manifest.permission.ACCESS_COARSE_LOCATION:
                return "Approximate Location";
            case Manifest.permission.CAMERA:
                return "Camera";
            case Manifest.permission.READ_PHONE_STATE:
                return "Phone State";
            case Manifest.permission.READ_EXTERNAL_STORAGE:
                return "Read Storage";
            case Manifest.permission.WRITE_EXTERNAL_STORAGE:
                return "Write Storage";
            case Manifest.permission.POST_NOTIFICATIONS:
                return "Send Notifications";
            default:
                return permission;
        }
    }
}
