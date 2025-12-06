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

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.net.NetworkRequest;
import android.os.Build;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.lang.ref.WeakReference;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * ConnectionMonitor - Monitor network connectivity changes
 * 
 * Provides:
 * - Real-time network state monitoring
 * - Connection type detection (WiFi, Mobile, Ethernet)
 * - Network quality/capability information
 * - Listener support for connection changes
 * 
 * Usage:
 * {@code
 * ConnectionMonitor monitor = ConnectionMonitor.getInstance(context);
 * monitor.addListener(new ConnectionListener() {
 *     @Override
 *     public void onConnectionChanged(boolean isConnected, ConnectionType type) {
 *         if (isConnected) {
 *             startNetworkScan();
 *         } else {
 *             stopNetworkScan();
 *         }
 *     }
 * });
 * monitor.start();
 * }
 */
public final class ConnectionMonitor {
    private static final String TAG = "ConnectionMonitor";
    
    // Connection types
    public enum ConnectionType {
        NONE,
        WIFI,
        MOBILE,
        ETHERNET,
        VPN,
        UNKNOWN
    }
    
    /**
     * Listener interface for connection changes
     */
    public interface ConnectionListener {
        void onConnectionChanged(boolean isConnected, ConnectionType type);
        default void onNetworkCapabilitiesChanged(NetworkCapabilities capabilities) {}
    }
    
    private static volatile ConnectionMonitor sInstance;
    private final WeakReference<Context> mContextRef;
    private final CopyOnWriteArrayList<ConnectionListener> mListeners;
    private ConnectivityManager mConnectivityManager;
    private ConnectivityManager.NetworkCallback mNetworkCallback;
    private BroadcastReceiver mLegacyReceiver;
    private boolean mIsMonitoring = false;
    private boolean mIsConnected = false;
    private ConnectionType mCurrentType = ConnectionType.NONE;
    
    private ConnectionMonitor(@NonNull Context context) {
        mContextRef = new WeakReference<>(context.getApplicationContext());
        mListeners = new CopyOnWriteArrayList<>();
        mConnectivityManager = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        initializeNetworkCallback();
    }
    
    /**
     * Get singleton instance
     * @param context Android context
     * @return ConnectionMonitor instance
     */
    public static ConnectionMonitor getInstance(@NonNull Context context) {
        if (sInstance == null) {
            synchronized (ConnectionMonitor.class) {
                if (sInstance == null) {
                    sInstance = new ConnectionMonitor(context);
                }
            }
        }
        return sInstance;
    }
    
    private void initializeNetworkCallback() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            mNetworkCallback = new ConnectivityManager.NetworkCallback() {
                @Override
                public void onAvailable(@NonNull Network network) {
                    updateConnectionState(true);
                }
                
                @Override
                public void onLost(@NonNull Network network) {
                    updateConnectionState(false);
                }
                
                @Override
                public void onCapabilitiesChanged(@NonNull Network network,
                                                   @NonNull NetworkCapabilities capabilities) {
                    ConnectionType type = getTypeFromCapabilities(capabilities);
                    if (type != mCurrentType) {
                        mCurrentType = type;
                        notifyListeners(mIsConnected, type);
                    }
                    notifyCapabilitiesChanged(capabilities);
                }
            };
        }
    }
    
    /**
     * Start monitoring network changes
     */
    public synchronized void start() {
        if (mIsMonitoring) {
            return;
        }
        
        Context context = mContextRef.get();
        if (context == null) {
            LoggingHelper.w(TAG, "Context is null, cannot start monitoring");
            return;
        }
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            NetworkRequest request = new NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .build();
            mConnectivityManager.registerNetworkCallback(request, mNetworkCallback);
        } else {
            // Legacy receiver for older Android versions
            mLegacyReceiver = new BroadcastReceiver() {
                @Override
                public void onReceive(Context context, Intent intent) {
                    updateConnectionState(isNetworkAvailable());
                }
            };
            IntentFilter filter = new IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION);
            context.registerReceiver(mLegacyReceiver, filter);
        }
        
        // Update initial state
        updateConnectionState(isNetworkAvailable());
        mIsMonitoring = true;
        LoggingHelper.d(TAG, "Connection monitoring started");
    }
    
    /**
     * Stop monitoring network changes
     */
    public synchronized void stop() {
        if (!mIsMonitoring) {
            return;
        }
        
        Context context = mContextRef.get();
        
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N && mNetworkCallback != null) {
                mConnectivityManager.unregisterNetworkCallback(mNetworkCallback);
            } else if (mLegacyReceiver != null && context != null) {
                context.unregisterReceiver(mLegacyReceiver);
                mLegacyReceiver = null;
            }
        } catch (Exception e) {
            LoggingHelper.w(TAG, "Error stopping connection monitor", e);
        }
        
        mIsMonitoring = false;
        LoggingHelper.d(TAG, "Connection monitoring stopped");
    }
    
    /**
     * Add a connection listener
     * @param listener listener to add
     */
    public void addListener(@NonNull ConnectionListener listener) {
        if (!mListeners.contains(listener)) {
            mListeners.add(listener);
            // Notify current state immediately
            listener.onConnectionChanged(mIsConnected, mCurrentType);
        }
    }
    
    /**
     * Remove a connection listener
     * @param listener listener to remove
     */
    public void removeListener(@NonNull ConnectionListener listener) {
        mListeners.remove(listener);
    }
    
    /**
     * Check if currently connected to any network
     * @return true if connected
     */
    public boolean isConnected() {
        return mIsConnected;
    }
    
    /**
     * Get current connection type
     * @return current ConnectionType
     */
    public ConnectionType getCurrentType() {
        return mCurrentType;
    }
    
    /**
     * Check if connected to WiFi
     * @return true if connected to WiFi
     */
    public boolean isWifiConnected() {
        return mIsConnected && mCurrentType == ConnectionType.WIFI;
    }
    
    /**
     * Check if any network is available (synchronous check)
     * @return true if network is available
     */
    public boolean isNetworkAvailable() {
        if (mConnectivityManager == null) {
            return false;
        }
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Network network = mConnectivityManager.getActiveNetwork();
            if (network == null) {
                return false;
            }
            NetworkCapabilities capabilities = mConnectivityManager.getNetworkCapabilities(network);
            return capabilities != null && 
                   (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ||
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) ||
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN));
        } else {
            NetworkInfo activeNetwork = mConnectivityManager.getActiveNetworkInfo();
            return activeNetwork != null && activeNetwork.isConnected();
        }
    }
    
    private void updateConnectionState(boolean isConnected) {
        if (mIsConnected != isConnected) {
            mIsConnected = isConnected;
            mCurrentType = isConnected ? detectConnectionType() : ConnectionType.NONE;
            notifyListeners(isConnected, mCurrentType);
            LoggingHelper.d(TAG, "Connection state changed: " + isConnected + ", type: " + mCurrentType);
        }
    }
    
    private ConnectionType detectConnectionType() {
        if (mConnectivityManager == null) {
            return ConnectionType.UNKNOWN;
        }
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Network network = mConnectivityManager.getActiveNetwork();
            if (network == null) {
                return ConnectionType.NONE;
            }
            NetworkCapabilities capabilities = mConnectivityManager.getNetworkCapabilities(network);
            return getTypeFromCapabilities(capabilities);
        } else {
            NetworkInfo activeNetwork = mConnectivityManager.getActiveNetworkInfo();
            if (activeNetwork == null || !activeNetwork.isConnected()) {
                return ConnectionType.NONE;
            }
            switch (activeNetwork.getType()) {
                case ConnectivityManager.TYPE_WIFI:
                    return ConnectionType.WIFI;
                case ConnectivityManager.TYPE_MOBILE:
                    return ConnectionType.MOBILE;
                case ConnectivityManager.TYPE_ETHERNET:
                    return ConnectionType.ETHERNET;
                case ConnectivityManager.TYPE_VPN:
                    return ConnectionType.VPN;
                default:
                    return ConnectionType.UNKNOWN;
            }
        }
    }
    
    private ConnectionType getTypeFromCapabilities(@Nullable NetworkCapabilities capabilities) {
        if (capabilities == null) {
            return ConnectionType.NONE;
        }
        
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
            return ConnectionType.WIFI;
        } else if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
            return ConnectionType.MOBILE;
        } else if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) {
            return ConnectionType.ETHERNET;
        } else if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
            return ConnectionType.VPN;
        }
        
        return ConnectionType.UNKNOWN;
    }
    
    private void notifyListeners(boolean isConnected, ConnectionType type) {
        for (ConnectionListener listener : mListeners) {
            try {
                listener.onConnectionChanged(isConnected, type);
            } catch (Exception e) {
                LoggingHelper.w(TAG, "Error notifying listener", e);
            }
        }
    }
    
    private void notifyCapabilitiesChanged(NetworkCapabilities capabilities) {
        for (ConnectionListener listener : mListeners) {
            try {
                listener.onNetworkCapabilitiesChanged(capabilities);
            } catch (Exception e) {
                LoggingHelper.w(TAG, "Error notifying capabilities change", e);
            }
        }
    }
}
