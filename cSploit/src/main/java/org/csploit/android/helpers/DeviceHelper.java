package org.csploit.android.helpers;

import android.annotation.SuppressLint;
import org.csploit.android.helpers.LoggingHelper;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.telephony.TelephonyManager;

import androidx.annotation.NonNull;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Device information utility helper for accessing device properties, features, and system info.
 * 
 * Features:
 * - Device model, manufacturer, and OS version
 * - Feature detection (NFC, Bluetooth, camera, etc.)
 * - Device capabilities caching
 * - API level checking with built-in constants
 * - Device type detection (phone, tablet, watch)
 * - Network type detection
 * 
 * Example:
 * <pre>
 * String model = DeviceHelper.getDeviceModel();
 * boolean hasNfc = DeviceHelper.hasFeature(context, PackageManager.FEATURE_NFC);
 * if (DeviceHelper.isAtLeastAndroid(Build.VERSION_CODES.S)) {
 *     // Use Android 12+ features
 * }
 * </pre>
 */
public final class DeviceHelper {
    private static final String TAG = "DeviceHelper";
    
    // Cached device properties (synchronized map handles threading)
    private static final Map<String, Object> DEVICE_CACHE = 
            Collections.synchronizedMap(new HashMap<>());
    
    /**
     * Get device manufacturer
     * 
     * @return manufacturer name (e.g., "Samsung", "Google")
     */
    public static String getManufacturer() {
        return Build.MANUFACTURER;
    }
    
    /**
     * Get device model
     * 
     * @return model name (e.g., "SM-G950F")
     */
    public static String getDeviceModel() {
        return Build.MODEL;
    }
    
    /**
     * Get device brand
     * 
     * @return brand name (e.g., "samsung")
     */
    public static String getBrand() {
        return Build.BRAND;
    }
    
    /**
     * Get device product name
     * 
     * @return product name
     */
    public static String getProductName() {
        return Build.PRODUCT;
    }
    
    /**
     * Get full device name
     * 
     * @return formatted device name
     */
    public static String getDeviceName() {
        return getManufacturer() + " " + getDeviceModel();
    }
    
    /**
     * Get Android OS version name
     * 
     * @return version name (e.g., "13.0", "12.1")
     */
    public static String getAndroidVersion() {
        return Build.VERSION.RELEASE;
    }
    
    /**
     * Get Android API level
     * 
     * @return API level (e.g., 33)
     */
    public static int getApiLevel() {
        return Build.VERSION.SDK_INT;
    }
    
    /**
     * Check if device is running at least specified API level
     * 
     * @param apiLevel API level to check
     * @return true if current API level >= specified level
     */
    public static boolean isAtLeastAndroid(int apiLevel) {
        return Build.VERSION.SDK_INT >= apiLevel;
    }
    
    /**
     * Get Build ID (unique identifier for ROM version)
     * 
     * @return build ID
     */
    public static String getBuildId() {
        return Build.ID;
    }
    
    /**
     * Get build type (user, userdebug, eng)
     * 
     * @return build type
     */
    public static String getBuildType() {
        return Build.TYPE;
    }
    
    /**
     * Get fingerprint (unique identifier for build)
     * 
     * @return build fingerprint
     */
    public static String getFingerprint() {
        return Build.FINGERPRINT;
    }
    
    /**
     * Check if device is rooted/in development mode
     * 
     * @return true if build type is userdebug or eng
     */
    public static boolean isDevelopmentBuild() {
        String type = getBuildType();
        return "userdebug".equals(type) || "eng".equals(type);
    }
    
    /**
     * Check if feature is available on device
     * 
     * @param context Android context
     * @param feature feature constant from PackageManager
     * @return true if feature is available
     */
    public static boolean hasFeature(@NonNull Context context, @NonNull String feature) {
        // Check cache first (synchronized map is thread-safe)
        String cacheKey = "feature_" + feature;
        if (DEVICE_CACHE.containsKey(cacheKey)) {
            return (boolean) DEVICE_CACHE.get(cacheKey);
        }
        
        // Query and cache
        PackageManager pm = context.getPackageManager();
        boolean hasFeature = pm.hasSystemFeature(feature);
        DEVICE_CACHE.put(cacheKey, hasFeature);
        
        return hasFeature;
    }
    
    /**
     * Check if device has NFC
     * 
     * @param context Android context
     * @return true if NFC is available
     */
    public static boolean hasNfc(@NonNull Context context) {
        return hasFeature(context, PackageManager.FEATURE_NFC);
    }
    
    /**
     * Check if device has Bluetooth
     * 
     * @param context Android context
     * @return true if Bluetooth is available
     */
    public static boolean hasBluetooth(@NonNull Context context) {
        return hasFeature(context, PackageManager.FEATURE_BLUETOOTH);
    }
    
    /**
     * Check if device has camera
     * 
     * @param context Android context
     * @return true if camera is available
     */
    public static boolean hasCamera(@NonNull Context context) {
        return hasFeature(context, PackageManager.FEATURE_CAMERA);
    }
    
    /**
     * Check if device has front-facing camera
     * 
     * @param context Android context
     * @return true if front camera is available
     */
    public static boolean hasFrontCamera(@NonNull Context context) {
        return hasFeature(context, PackageManager.FEATURE_CAMERA_FRONT);
    }
    
    /**
     * Check if device has GPS
     * 
     * @param context Android context
     * @return true if GPS is available
     */
    public static boolean hasGps(@NonNull Context context) {
        return hasFeature(context, PackageManager.FEATURE_LOCATION_GPS);
    }
    
    /**
     * Check if device has microphone
     * 
     * @param context Android context
     * @return true if microphone is available
     */
    public static boolean hasMicrophone(@NonNull Context context) {
        return hasFeature(context, PackageManager.FEATURE_MICROPHONE);
    }
    
    /**
     * Check if device has vibrator
     * 
     * @param context Android context
     * @return true if vibrator is available
     */
    public static boolean hasVibrator(@NonNull Context context) {
        android.os.Vibrator vibrator = (android.os.Vibrator) context.getSystemService(Context.VIBRATOR_SERVICE);
        return vibrator != null && vibrator.hasVibrator();
    }
    
    /**
     * Check if device has touchscreen
     * 
     * @param context Android context
     * @return true if touchscreen is available
     */
    public static boolean hasTouchscreen(@NonNull Context context) {
        return hasFeature(context, PackageManager.FEATURE_TOUCHSCREEN);
    }
    
    /**
     * Check if device has WiFi
     * 
     * @param context Android context
     * @return true if WiFi is available
     */
    public static boolean hasWiFi(@NonNull Context context) {
        return hasFeature(context, PackageManager.FEATURE_WIFI);
    }
    
    /**
     * Check if device is tablet or phone
     * 
     * @param context Android context
     * @return true if device is tablet (large screen)
     */
    public static boolean isTablet(@NonNull Context context) {
        return hasFeature(context, "android.hardware.type.tablet");
    }
    
    /**
     * Check if device is watch
     * 
     * @param context Android context
     * @return true if device is watch
     */
    public static boolean isWatch(@NonNull Context context) {
        return hasFeature(context, "android.hardware.type.watch");
    }
    
    /**
     * Get device type
     * 
     * @param context Android context
     * @return "phone", "tablet", "watch", or "unknown"
     */
    public static String getDeviceType(@NonNull Context context) {
        if (isTablet(context)) return "tablet";
        if (isWatch(context)) return "watch";
        return "phone";
    }
    
    /**
     * Get network type (SIM type for phones)
     * 
     * @param context Android context
     * @return network type string
     */
    @SuppressLint("MissingPermission")
    public static String getNetworkType(@NonNull Context context) {
        try {
            TelephonyManager tm = (TelephonyManager) 
                    context.getSystemService(Context.TELEPHONY_SERVICE);
            
            if (tm == null) {
                return "Unknown";
            }
            
            int type = tm.getNetworkType();
            
            switch (type) {
                case TelephonyManager.NETWORK_TYPE_GPRS:
                    return "GPRS";
                case TelephonyManager.NETWORK_TYPE_EDGE:
                    return "EDGE";
                case TelephonyManager.NETWORK_TYPE_UMTS:
                    return "UMTS";
                case TelephonyManager.NETWORK_TYPE_CDMA:
                    return "CDMA";
                case TelephonyManager.NETWORK_TYPE_EVDO_0:
                    return "EVDO_0";
                case TelephonyManager.NETWORK_TYPE_EVDO_A:
                    return "EVDO_A";
                case TelephonyManager.NETWORK_TYPE_1xRTT:
                    return "1xRTT";
                case TelephonyManager.NETWORK_TYPE_HSDPA:
                    return "HSDPA";
                case TelephonyManager.NETWORK_TYPE_HSUPA:
                    return "HSUPA";
                case TelephonyManager.NETWORK_TYPE_HSPA:
                    return "HSPA";
                case TelephonyManager.NETWORK_TYPE_IDEN:
                    return "IDEN";
                case TelephonyManager.NETWORK_TYPE_EVDO_B:
                    return "EVDO_B";
                case TelephonyManager.NETWORK_TYPE_LTE:
                    return "LTE";
                case TelephonyManager.NETWORK_TYPE_EHRPD:
                    return "EHRPD";
                case TelephonyManager.NETWORK_TYPE_HSPAP:
                    return "HSPAP";
                default:
                    if (type >= 13) return "LTE_AND_HIGHER";
                    return "Unknown";
            }
        } catch (SecurityException e) {
            LoggingHelper.w(TAG, "Permission denied for network type", e);
            return "Unknown";
        }
    }
    
    /**
     * Clear feature cache (call after installing/uninstalling features)
     */
    public static void clearFeatureCache() {
        DEVICE_CACHE.clear();
        LoggingHelper.d(TAG, "Feature cache cleared");
    }
    
    /**
     * Get debug info string with device details
     * 
     * @return formatted debug string
     */
    public static String getDebugInfo() {
        return String.format(
            "Device: %s (%s)\nOS: Android %s (API %d)\nBuild: %s\nType: %s",
            getDeviceName(),
            getBrand(),
            getAndroidVersion(),
            getApiLevel(),
            getBuildId(),
            getBuildType()
        );
    }
}
