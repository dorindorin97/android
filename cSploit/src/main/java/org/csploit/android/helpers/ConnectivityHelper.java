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
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.os.Build;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

/**
 * Helper class for network connectivity detection and monitoring.
 * Provides modern network state checking compatible with all Android versions.
 */
public class ConnectivityHelper {
    
    private static final String TAG = "ConnectivityHelper";
    
    /**
     * Network type enumeration
     */
    public enum NetworkType {
        NONE,
        WIFI,
        CELLULAR,
        ETHERNET,
        VPN,
        OTHER
    }
    
    /**
     * Check if device has any network connectivity.
     * 
     * @param context Application context
     * @return true if connected to any network
     */
    public static boolean isNetworkAvailable(@NonNull Context context) {
        ConnectivityManager cm = (ConnectivityManager) 
                context.getSystemService(Context.CONNECTIVITY_SERVICE);
        
        if (cm == null) {
            LoggingHelper.w(TAG, "ConnectivityManager not available");
            return false;
        }
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Network network = cm.getActiveNetwork();
            if (network == null) return false;
            
            NetworkCapabilities capabilities = cm.getNetworkCapabilities(network);
            if (capabilities == null) return false;
            
            return capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                   capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED);
        } else {
            NetworkInfo networkInfo = cm.getActiveNetworkInfo();
            return networkInfo != null && networkInfo.isConnected();
        }
    }
    
    /**
     * Check if device is connected to WiFi.
     * 
     * @param context Application context
     * @return true if connected to WiFi
     */
    public static boolean isWifiConnected(@NonNull Context context) {
        ConnectivityManager cm = (ConnectivityManager) 
                context.getSystemService(Context.CONNECTIVITY_SERVICE);
        
        if (cm == null) return false;
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Network network = cm.getActiveNetwork();
            if (network == null) return false;
            
            NetworkCapabilities capabilities = cm.getNetworkCapabilities(network);
            return capabilities != null && 
                   capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI);
        } else {
            NetworkInfo networkInfo = cm.getActiveNetworkInfo();
            return networkInfo != null && 
                   networkInfo.getType() == ConnectivityManager.TYPE_WIFI &&
                   networkInfo.isConnected();
        }
    }
    
    /**
     * Check if device is connected to cellular network.
     * 
     * @param context Application context
     * @return true if connected to cellular
     */
    public static boolean isCellularConnected(@NonNull Context context) {
        ConnectivityManager cm = (ConnectivityManager) 
                context.getSystemService(Context.CONNECTIVITY_SERVICE);
        
        if (cm == null) return false;
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Network network = cm.getActiveNetwork();
            if (network == null) return false;
            
            NetworkCapabilities capabilities = cm.getNetworkCapabilities(network);
            return capabilities != null && 
                   capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR);
        } else {
            NetworkInfo networkInfo = cm.getActiveNetworkInfo();
            return networkInfo != null && 
                   networkInfo.getType() == ConnectivityManager.TYPE_MOBILE &&
                   networkInfo.isConnected();
        }
    }
    
    /**
     * Check if device is connected via VPN.
     * 
     * @param context Application context
     * @return true if VPN is active
     */
    public static boolean isVpnConnected(@NonNull Context context) {
        ConnectivityManager cm = (ConnectivityManager) 
                context.getSystemService(Context.CONNECTIVITY_SERVICE);
        
        if (cm == null) return false;
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Network network = cm.getActiveNetwork();
            if (network == null) return false;
            
            NetworkCapabilities capabilities = cm.getNetworkCapabilities(network);
            return capabilities != null && 
                   capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
        } else {
            // VPN detection on older APIs requires different approach
            NetworkInfo networkInfo = cm.getActiveNetworkInfo();
            return networkInfo != null && 
                   networkInfo.getType() == ConnectivityManager.TYPE_VPN &&
                   networkInfo.isConnected();
        }
    }
    
    /**
     * Get the current network type.
     * 
     * @param context Application context
     * @return NetworkType enum value
     */
    @NonNull
    public static NetworkType getNetworkType(@NonNull Context context) {
        ConnectivityManager cm = (ConnectivityManager) 
                context.getSystemService(Context.CONNECTIVITY_SERVICE);
        
        if (cm == null) return NetworkType.NONE;
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Network network = cm.getActiveNetwork();
            if (network == null) return NetworkType.NONE;
            
            NetworkCapabilities capabilities = cm.getNetworkCapabilities(network);
            if (capabilities == null) return NetworkType.NONE;
            
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                return NetworkType.VPN;
            } else if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                return NetworkType.WIFI;
            } else if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                return NetworkType.CELLULAR;
            } else if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) {
                return NetworkType.ETHERNET;
            } else {
                return NetworkType.OTHER;
            }
        } else {
            NetworkInfo networkInfo = cm.getActiveNetworkInfo();
            if (networkInfo == null || !networkInfo.isConnected()) {
                return NetworkType.NONE;
            }
            
            switch (networkInfo.getType()) {
                case ConnectivityManager.TYPE_WIFI:
                    return NetworkType.WIFI;
                case ConnectivityManager.TYPE_MOBILE:
                    return NetworkType.CELLULAR;
                case ConnectivityManager.TYPE_ETHERNET:
                    return NetworkType.ETHERNET;
                case ConnectivityManager.TYPE_VPN:
                    return NetworkType.VPN;
                default:
                    return NetworkType.OTHER;
            }
        }
    }
    
    /**
     * Get network type as human-readable string.
     * 
     * @param context Application context
     * @return Network type string (e.g., "WiFi", "Cellular", "None")
     */
    @NonNull
    public static String getNetworkTypeString(@NonNull Context context) {
        NetworkType type = getNetworkType(context);
        switch (type) {
            case WIFI:
                return "WiFi";
            case CELLULAR:
                return "Cellular";
            case ETHERNET:
                return "Ethernet";
            case VPN:
                return "VPN";
            case OTHER:
                return "Other";
            case NONE:
            default:
                return "None";
        }
    }
    
    /**
     * Check if the network has internet capability.
     * 
     * @param context Application context
     * @return true if network has internet access
     */
    public static boolean hasInternetCapability(@NonNull Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            ConnectivityManager cm = (ConnectivityManager) 
                    context.getSystemService(Context.CONNECTIVITY_SERVICE);
            
            if (cm == null) return false;
            
            Network network = cm.getActiveNetwork();
            if (network == null) return false;
            
            NetworkCapabilities capabilities = cm.getNetworkCapabilities(network);
            return capabilities != null && 
                   capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET);
        }
        
        // Fallback for older APIs
        return isNetworkAvailable(context);
    }
    
    /**
     * Get link download speed in Kbps (API 21+).
     * 
     * @param context Application context
     * @return Download speed in Kbps, or -1 if unavailable
     */
    public static int getLinkDownstreamBandwidthKbps(@NonNull Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            ConnectivityManager cm = (ConnectivityManager) 
                    context.getSystemService(Context.CONNECTIVITY_SERVICE);
            
            if (cm == null) return -1;
            
            Network network = cm.getActiveNetwork();
            if (network == null) return -1;
            
            NetworkCapabilities capabilities = cm.getNetworkCapabilities(network);
            if (capabilities == null) return -1;
            
            return capabilities.getLinkDownstreamBandwidthKbps();
        }
        
        return -1;
    }
    
    /**
     * Get link upload speed in Kbps (API 21+).
     * 
     * @param context Application context
     * @return Upload speed in Kbps, or -1 if unavailable
     */
    public static int getLinkUpstreamBandwidthKbps(@NonNull Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            ConnectivityManager cm = (ConnectivityManager) 
                    context.getSystemService(Context.CONNECTIVITY_SERVICE);
            
            if (cm == null) return -1;
            
            Network network = cm.getActiveNetwork();
            if (network == null) return -1;
            
            NetworkCapabilities capabilities = cm.getNetworkCapabilities(network);
            if (capabilities == null) return -1;
            
            return capabilities.getLinkUpstreamBandwidthKbps();
        }
        
        return -1;
    }
    
    private ConnectivityHelper() {
        // Prevent instantiation
    }
}
