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

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresPermission;

import java.util.Collections;
import java.util.List;

/**
 * Helper class for WiFi operations.
 * Provides utilities for WiFi scanning and management.
 */
public class WifiHelper {
    
    // WiFi security types
    public static final String SECURITY_OPEN = "Open";
    public static final String SECURITY_WEP = "WEP";
    public static final String SECURITY_WPA = "WPA";
    public static final String SECURITY_WPA2 = "WPA2";
    public static final String SECURITY_WPA3 = "WPA3";
    public static final String SECURITY_EAP = "EAP";
    
    // Signal strength levels
    public static final int SIGNAL_EXCELLENT = 4;
    public static final int SIGNAL_GOOD = 3;
    public static final int SIGNAL_FAIR = 2;
    public static final int SIGNAL_WEAK = 1;
    public static final int SIGNAL_NONE = 0;
    
    /**
     * Get WiFi manager.
     * 
     * @param context Context
     * @return WifiManager
     */
    @Nullable
    public static WifiManager getWifiManager(@NonNull Context context) {
        return (WifiManager) context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
    }
    
    /**
     * Check if WiFi is enabled.
     * 
     * @param context Context
     * @return true if WiFi is enabled
     */
    public static boolean isWifiEnabled(@NonNull Context context) {
        WifiManager wifiManager = getWifiManager(context);
        return wifiManager != null && wifiManager.isWifiEnabled();
    }
    
    /**
     * Check if device is connected to WiFi.
     * 
     * @param context Context
     * @return true if connected to WiFi
     */
    public static boolean isConnectedToWifi(@NonNull Context context) {
        return ConnectivityHelper.isWifiConnected(context);
    }
    
    /**
     * Enable WiFi.
     * Note: This method is deprecated on Android Q+ and may not work.
     * 
     * @param context Context
     * @return true if operation was initiated
     */
    @SuppressWarnings("deprecation")
    public static boolean enableWifi(@NonNull Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            // Cannot programmatically enable WiFi on Android Q+
            return false;
        }
        WifiManager wifiManager = getWifiManager(context);
        if (wifiManager == null) {
            return false;
        }
        return wifiManager.setWifiEnabled(true);
    }
    
    /**
     * Disable WiFi.
     * Note: This method is deprecated on Android Q+ and may not work.
     * 
     * @param context Context
     * @return true if operation was initiated
     */
    @SuppressWarnings("deprecation")
    public static boolean disableWifi(@NonNull Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            // Cannot programmatically disable WiFi on Android Q+
            return false;
        }
        WifiManager wifiManager = getWifiManager(context);
        if (wifiManager == null) {
            return false;
        }
        return wifiManager.setWifiEnabled(false);
    }
    
    /**
     * Get current WiFi connection info.
     * 
     * @param context Context
     * @return WifiInfo or null
     */
    @Nullable
    @SuppressWarnings("deprecation")
    public static WifiInfo getConnectionInfo(@NonNull Context context) {
        WifiManager wifiManager = getWifiManager(context);
        if (wifiManager == null) {
            return null;
        }
        return wifiManager.getConnectionInfo();
    }
    
    /**
     * Get current WiFi SSID.
     * 
     * @param context Context
     * @return SSID or null if not connected
     */
    @Nullable
    @SuppressWarnings("deprecation")
    public static String getCurrentSsid(@NonNull Context context) {
        WifiInfo wifiInfo = getConnectionInfo(context);
        if (wifiInfo == null) {
            return null;
        }
        String ssid = wifiInfo.getSSID();
        if (ssid != null && ssid.startsWith("\"") && ssid.endsWith("\"")) {
            ssid = ssid.substring(1, ssid.length() - 1);
        }
        return "<unknown ssid>".equals(ssid) ? null : ssid;
    }
    
    /**
     * Get current WiFi BSSID.
     * 
     * @param context Context
     * @return BSSID or null if not connected
     */
    @Nullable
    @SuppressWarnings("deprecation")
    public static String getCurrentBssid(@NonNull Context context) {
        WifiInfo wifiInfo = getConnectionInfo(context);
        if (wifiInfo == null) {
            return null;
        }
        String bssid = wifiInfo.getBSSID();
        return "02:00:00:00:00:00".equals(bssid) ? null : bssid;
    }
    
    /**
     * Get current WiFi IP address.
     * 
     * @param context Context
     * @return IP address as integer, or 0 if not connected
     */
    @SuppressWarnings("deprecation")
    public static int getIpAddressInt(@NonNull Context context) {
        WifiInfo wifiInfo = getConnectionInfo(context);
        return wifiInfo != null ? wifiInfo.getIpAddress() : 0;
    }
    
    /**
     * Get current WiFi IP address as string.
     * 
     * @param context Context
     * @return IP address string or null
     */
    @Nullable
    public static String getIpAddress(@NonNull Context context) {
        int ip = getIpAddressInt(context);
        if (ip == 0) {
            return null;
        }
        return String.format("%d.%d.%d.%d",
                (ip & 0xff),
                (ip >> 8 & 0xff),
                (ip >> 16 & 0xff),
                (ip >> 24 & 0xff));
    }
    
    /**
     * Get current WiFi link speed.
     * 
     * @param context Context
     * @return Link speed in Mbps, or -1 if not available
     */
    @SuppressWarnings("deprecation")
    public static int getLinkSpeed(@NonNull Context context) {
        WifiInfo wifiInfo = getConnectionInfo(context);
        return wifiInfo != null ? wifiInfo.getLinkSpeed() : -1;
    }
    
    /**
     * Get current WiFi signal strength (RSSI).
     * 
     * @param context Context
     * @return RSSI value in dBm, or Integer.MIN_VALUE if not available
     */
    @SuppressWarnings("deprecation")
    public static int getRssi(@NonNull Context context) {
        WifiInfo wifiInfo = getConnectionInfo(context);
        return wifiInfo != null ? wifiInfo.getRssi() : Integer.MIN_VALUE;
    }
    
    /**
     * Get signal level (0-4) from RSSI.
     * 
     * @param rssi RSSI value
     * @param numLevels Number of levels
     * @return Signal level
     */
    @SuppressWarnings("deprecation")
    public static int calculateSignalLevel(int rssi, int numLevels) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            return WifiManager.calculateSignalLevel(rssi, numLevels);
        } else {
            if (rssi <= -100) {
                return 0;
            } else if (rssi >= -55) {
                return numLevels - 1;
            } else {
                float inputRange = (-55) - (-100);
                float outputRange = numLevels - 1;
                return (int) ((float) (rssi - (-100)) * outputRange / inputRange);
            }
        }
    }
    
    /**
     * Get current signal level (0-4).
     * 
     * @param context Context
     * @return Signal level 0-4
     */
    public static int getSignalLevel(@NonNull Context context) {
        int rssi = getRssi(context);
        if (rssi == Integer.MIN_VALUE) {
            return SIGNAL_NONE;
        }
        return calculateSignalLevel(rssi, 5);
    }
    
    /**
     * Get signal level description.
     * 
     * @param level Signal level (0-4)
     * @return Description string
     */
    @NonNull
    public static String getSignalLevelDescription(int level) {
        switch (level) {
            case SIGNAL_EXCELLENT:
                return "Excellent";
            case SIGNAL_GOOD:
                return "Good";
            case SIGNAL_FAIR:
                return "Fair";
            case SIGNAL_WEAK:
                return "Weak";
            default:
                return "None";
        }
    }
    
    /**
     * Get WiFi frequency.
     * 
     * @param context Context
     * @return Frequency in MHz, or -1 if not available
     */
    @SuppressWarnings("deprecation")
    public static int getFrequency(@NonNull Context context) {
        WifiInfo wifiInfo = getConnectionInfo(context);
        return wifiInfo != null ? wifiInfo.getFrequency() : -1;
    }
    
    /**
     * Check if connected to 5GHz WiFi.
     * 
     * @param context Context
     * @return true if 5GHz
     */
    public static boolean is5GHz(@NonNull Context context) {
        int freq = getFrequency(context);
        return freq >= 4900 && freq <= 5900;
    }
    
    /**
     * Check if connected to 2.4GHz WiFi.
     * 
     * @param context Context
     * @return true if 2.4GHz
     */
    public static boolean is24GHz(@NonNull Context context) {
        int freq = getFrequency(context);
        return freq >= 2400 && freq <= 2500;
    }
    
    /**
     * Start WiFi scan.
     * 
     * @param context Context
     * @return true if scan started
     */
    @RequiresPermission(allOf = {
            android.Manifest.permission.ACCESS_FINE_LOCATION,
            android.Manifest.permission.CHANGE_WIFI_STATE
    })
    @SuppressWarnings("deprecation")
    public static boolean startScan(@NonNull Context context) {
        WifiManager wifiManager = getWifiManager(context);
        if (wifiManager == null) {
            return false;
        }
        return wifiManager.startScan();
    }
    
    /**
     * Get scan results.
     * 
     * @param context Context
     * @return List of scan results
     */
    @RequiresPermission(android.Manifest.permission.ACCESS_FINE_LOCATION)
    @NonNull
    public static List<ScanResult> getScanResults(@NonNull Context context) {
        WifiManager wifiManager = getWifiManager(context);
        if (wifiManager == null) {
            return Collections.emptyList();
        }
        List<ScanResult> results = wifiManager.getScanResults();
        return results != null ? results : Collections.emptyList();
    }
    
    /**
     * Get configured networks.
     * 
     * @param context Context
     * @return List of configured networks
     */
    @RequiresPermission(android.Manifest.permission.ACCESS_FINE_LOCATION)
    @NonNull
    @SuppressWarnings("deprecation")
    public static List<WifiConfiguration> getConfiguredNetworks(@NonNull Context context) {
        WifiManager wifiManager = getWifiManager(context);
        if (wifiManager == null) {
            return Collections.emptyList();
        }
        List<WifiConfiguration> configs = wifiManager.getConfiguredNetworks();
        return configs != null ? configs : Collections.emptyList();
    }
    
    /**
     * Get security type from scan result.
     * 
     * @param result Scan result
     * @return Security type string
     */
    @NonNull
    public static String getSecurityType(@NonNull ScanResult result) {
        String capabilities = result.capabilities;
        if (capabilities == null) {
            return SECURITY_OPEN;
        }
        
        if (capabilities.contains("WPA3")) {
            return SECURITY_WPA3;
        } else if (capabilities.contains("WPA2")) {
            return SECURITY_WPA2;
        } else if (capabilities.contains("WPA")) {
            return SECURITY_WPA;
        } else if (capabilities.contains("WEP")) {
            return SECURITY_WEP;
        } else if (capabilities.contains("EAP")) {
            return SECURITY_EAP;
        }
        return SECURITY_OPEN;
    }
    
    /**
     * Check if network is open (no security).
     * 
     * @param result Scan result
     * @return true if open network
     */
    public static boolean isOpenNetwork(@NonNull ScanResult result) {
        return SECURITY_OPEN.equals(getSecurityType(result));
    }
    
    /**
     * Check if network is secure.
     * 
     * @param result Scan result
     * @return true if network has security
     */
    public static boolean isSecureNetwork(@NonNull ScanResult result) {
        return !isOpenNetwork(result);
    }
    
    /**
     * Register WiFi scan receiver.
     * 
     * @param context Context
     * @param receiver BroadcastReceiver for scan results
     */
    @SuppressWarnings("deprecation")
    public static void registerScanReceiver(@NonNull Context context, @NonNull BroadcastReceiver receiver) {
        IntentFilter filter = new IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED);
        } else {
            context.registerReceiver(receiver, filter);
        }
    }
    
    /**
     * Unregister receiver.
     * 
     * @param context Context
     * @param receiver BroadcastReceiver to unregister
     */
    public static void unregisterReceiver(@NonNull Context context, @NonNull BroadcastReceiver receiver) {
        try {
            context.unregisterReceiver(receiver);
        } catch (IllegalArgumentException e) {
            // Receiver was not registered
        }
    }
    
    /**
     * Open WiFi settings.
     * 
     * @param context Context
     */
    public static void openWifiSettings(@NonNull Context context) {
        Intent intent = new Intent(android.provider.Settings.ACTION_WIFI_SETTINGS);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        context.startActivity(intent);
    }
    
    private WifiHelper() {
        // Prevent instantiation
    }
}
