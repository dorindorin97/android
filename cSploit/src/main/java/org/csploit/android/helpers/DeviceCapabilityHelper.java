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
import android.content.pm.PackageManager;
import android.os.Build;

import androidx.annotation.NonNull;

/**
 * Helper class for checking device capabilities and features.
 * Provides utilities for hardware and software feature detection.
 */
public class DeviceCapabilityHelper {
    
    /**
     * Check if device has camera.
     * 
     * @param context Context
     * @return true if device has any camera
     */
    public static boolean hasCamera(@NonNull Context context) {
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY);
    }
    
    /**
     * Check if device has front camera.
     * 
     * @param context Context
     * @return true if device has front camera
     */
    public static boolean hasFrontCamera(@NonNull Context context) {
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_CAMERA_FRONT);
    }
    
    /**
     * Check if device has flash.
     * 
     * @param context Context
     * @return true if device has camera flash
     */
    public static boolean hasFlash(@NonNull Context context) {
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_CAMERA_FLASH);
    }
    
    /**
     * Check if device has autofocus.
     * 
     * @param context Context
     * @return true if device has camera autofocus
     */
    public static boolean hasAutofocus(@NonNull Context context) {
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_CAMERA_AUTOFOCUS);
    }
    
    /**
     * Check if device has GPS.
     * 
     * @param context Context
     * @return true if device has GPS
     */
    public static boolean hasGps(@NonNull Context context) {
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_LOCATION_GPS);
    }
    
    /**
     * Check if device has network location.
     * 
     * @param context Context
     * @return true if device has network location
     */
    public static boolean hasNetworkLocation(@NonNull Context context) {
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_LOCATION_NETWORK);
    }
    
    /**
     * Check if device has WiFi.
     * 
     * @param context Context
     * @return true if device has WiFi
     */
    public static boolean hasWifi(@NonNull Context context) {
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_WIFI);
    }
    
    /**
     * Check if device has WiFi Direct.
     * 
     * @param context Context
     * @return true if device has WiFi Direct
     */
    public static boolean hasWifiDirect(@NonNull Context context) {
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_WIFI_DIRECT);
    }
    
    /**
     * Check if device has Bluetooth.
     * 
     * @param context Context
     * @return true if device has Bluetooth
     */
    public static boolean hasBluetooth(@NonNull Context context) {
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_BLUETOOTH);
    }
    
    /**
     * Check if device has Bluetooth LE.
     * 
     * @param context Context
     * @return true if device has Bluetooth LE
     */
    public static boolean hasBluetoothLe(@NonNull Context context) {
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE);
    }
    
    /**
     * Check if device has NFC.
     * 
     * @param context Context
     * @return true if device has NFC
     */
    public static boolean hasNfc(@NonNull Context context) {
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_NFC);
    }
    
    /**
     * Check if device has telephony (is a phone).
     * 
     * @param context Context
     * @return true if device has telephony
     */
    public static boolean hasTelephony(@NonNull Context context) {
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_TELEPHONY);
    }
    
    /**
     * Check if device has fingerprint sensor.
     * 
     * @param context Context
     * @return true if device has fingerprint sensor
     */
    public static boolean hasFingerprint(@NonNull Context context) {
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_FINGERPRINT);
    }
    
    /**
     * Check if device has microphone.
     * 
     * @param context Context
     * @return true if device has microphone
     */
    public static boolean hasMicrophone(@NonNull Context context) {
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_MICROPHONE);
    }
    
    /**
     * Check if device has accelerometer.
     * 
     * @param context Context
     * @return true if device has accelerometer
     */
    public static boolean hasAccelerometer(@NonNull Context context) {
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_SENSOR_ACCELEROMETER);
    }
    
    /**
     * Check if device has gyroscope.
     * 
     * @param context Context
     * @return true if device has gyroscope
     */
    public static boolean hasGyroscope(@NonNull Context context) {
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_SENSOR_GYROSCOPE);
    }
    
    /**
     * Check if device has compass.
     * 
     * @param context Context
     * @return true if device has compass
     */
    public static boolean hasCompass(@NonNull Context context) {
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_SENSOR_COMPASS);
    }
    
    /**
     * Check if device has barometer.
     * 
     * @param context Context
     * @return true if device has barometer
     */
    public static boolean hasBarometer(@NonNull Context context) {
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_SENSOR_BAROMETER);
    }
    
    /**
     * Check if device has step counter.
     * 
     * @param context Context
     * @return true if device has step counter
     */
    public static boolean hasStepCounter(@NonNull Context context) {
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_SENSOR_STEP_COUNTER);
    }
    
    /**
     * Check if device has heart rate sensor.
     * 
     * @param context Context
     * @return true if device has heart rate sensor
     */
    public static boolean hasHeartRateSensor(@NonNull Context context) {
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_SENSOR_HEART_RATE);
    }
    
    /**
     * Check if device is a watch.
     * 
     * @param context Context
     * @return true if device is a watch
     */
    public static boolean isWatch(@NonNull Context context) {
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_WATCH);
    }
    
    /**
     * Check if device is a TV.
     * 
     * @param context Context
     * @return true if device is a TV
     */
    public static boolean isTv(@NonNull Context context) {
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_LEANBACK);
    }
    
    /**
     * Check if device is automotive.
     * 
     * @param context Context
     * @return true if device is automotive
     */
    public static boolean isAutomotive(@NonNull Context context) {
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_AUTOMOTIVE);
    }
    
    /**
     * Check if device has USB host support.
     * 
     * @param context Context
     * @return true if device supports USB host
     */
    public static boolean hasUsbHost(@NonNull Context context) {
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_USB_HOST);
    }
    
    /**
     * Check if device has USB accessory support.
     * 
     * @param context Context
     * @return true if device supports USB accessory
     */
    public static boolean hasUsbAccessory(@NonNull Context context) {
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_USB_ACCESSORY);
    }
    
    /**
     * Check if device supports multitouch.
     * 
     * @param context Context
     * @return true if device supports multitouch
     */
    public static boolean hasMultitouch(@NonNull Context context) {
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_TOUCHSCREEN_MULTITOUCH);
    }
    
    /**
     * Check if device supports SIP VoIP.
     * 
     * @param context Context
     * @return true if device supports SIP VoIP
     */
    public static boolean hasSipVoip(@NonNull Context context) {
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_SIP_VOIP);
    }
    
    /**
     * Check if device has VR mode.
     * 
     * @param context Context
     * @return true if device has VR mode
     */
    public static boolean hasVrMode(@NonNull Context context) {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.N &&
                context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_VR_MODE);
    }
    
    /**
     * Get API level of the device.
     * 
     * @return API level
     */
    public static int getApiLevel() {
        return Build.VERSION.SDK_INT;
    }
    
    /**
     * Check if device is running at least specified API level.
     * 
     * @param apiLevel API level to check
     * @return true if device API level >= specified level
     */
    public static boolean isAtLeast(int apiLevel) {
        return Build.VERSION.SDK_INT >= apiLevel;
    }
    
    /**
     * Get device manufacturer.
     * 
     * @return Device manufacturer
     */
    @NonNull
    public static String getManufacturer() {
        return Build.MANUFACTURER;
    }
    
    /**
     * Get device model.
     * 
     * @return Device model
     */
    @NonNull
    public static String getModel() {
        return Build.MODEL;
    }
    
    /**
     * Get device name (manufacturer + model).
     * 
     * @return Device name
     */
    @NonNull
    public static String getDeviceName() {
        String manufacturer = Build.MANUFACTURER;
        String model = Build.MODEL;
        if (model.toLowerCase().startsWith(manufacturer.toLowerCase())) {
            return capitalize(model);
        }
        return capitalize(manufacturer) + " " + model;
    }
    
    /**
     * Get Android version name.
     * 
     * @return Android version name
     */
    @NonNull
    public static String getAndroidVersion() {
        return Build.VERSION.RELEASE;
    }
    
    private static String capitalize(String str) {
        if (str == null || str.isEmpty()) {
            return str;
        }
        return Character.toUpperCase(str.charAt(0)) + str.substring(1);
    }
    
    private DeviceCapabilityHelper() {
        // Prevent instantiation
    }
}
