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
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

/**
 * ConnectionQualityHelper - Monitors and assesses network connection quality.
 * 
 * Provides:
 * - Connection type detection
 * - Signal strength assessment
 * - Bandwidth estimation
 * - Latency measurement
 * - Network stability monitoring
 * 
 * Usage:
 * {@code
 * ConnectionQualityHelper helper = ConnectionQualityHelper.getInstance(context);
 * 
 * // Get connection quality
 * ConnectionQuality quality = helper.getConnectionQuality();
 * 
 * // Check if good enough for scanning
 * if (helper.isGoodForScanning()) {
 *     // Proceed with scan
 * }
 * }
 */
public class ConnectionQualityHelper {
    
    public static final String TAG = "ConnectionQualityHelper";
    
    private static volatile ConnectionQualityHelper instance;
    
    private final Context context;
    private final ConnectivityManager connectivityManager;
    
    // Quality metrics
    private ConnectionQuality lastQuality = ConnectionQuality.UNKNOWN;
    private long lastLatencyMs = -1;
    private long lastBandwidthBps = -1;
    private long lastCheckTime = 0;
    private int consecutiveFailures = 0;
    
    /**
     * Connection quality levels.
     */
    public enum ConnectionQuality {
        EXCELLENT("Excellent", 5),
        GOOD("Good", 4),
        MODERATE("Moderate", 3),
        POOR("Poor", 2),
        VERY_POOR("Very Poor", 1),
        UNKNOWN("Unknown", 0);
        
        private final String displayName;
        private final int level;
        
        ConnectionQuality(String displayName, int level) {
            this.displayName = displayName;
            this.level = level;
        }
        
        public String getDisplayName() {
            return displayName;
        }
        
        public int getLevel() {
            return level;
        }
    }
    
    /**
     * Connection type.
     */
    public enum ConnectionType {
        WIFI("WiFi"),
        CELLULAR("Cellular"),
        ETHERNET("Ethernet"),
        VPN("VPN"),
        BLUETOOTH("Bluetooth"),
        NONE("None"),
        UNKNOWN("Unknown");
        
        private final String displayName;
        
        ConnectionType(String displayName) {
            this.displayName = displayName;
        }
        
        public String getDisplayName() {
            return displayName;
        }
    }
    
    /**
     * Detailed connection info.
     */
    public static class ConnectionInfo {
        public final ConnectionType type;
        public final ConnectionQuality quality;
        public final long latencyMs;
        public final long bandwidthBps;
        public final String ipAddress;
        public final String networkName;
        public final boolean isMetered;
        public final boolean hasInternet;
        public final int signalStrength;
        
        ConnectionInfo(ConnectionType type, ConnectionQuality quality, long latencyMs,
                      long bandwidthBps, String ipAddress, String networkName,
                      boolean isMetered, boolean hasInternet, int signalStrength) {
            this.type = type;
            this.quality = quality;
            this.latencyMs = latencyMs;
            this.bandwidthBps = bandwidthBps;
            this.ipAddress = ipAddress;
            this.networkName = networkName;
            this.isMetered = isMetered;
            this.hasInternet = hasInternet;
            this.signalStrength = signalStrength;
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("ConnectionInfo{type=%s, quality=%s, latency=%dms, bandwidth=%d bps}",
                    type.displayName, quality.displayName, latencyMs, bandwidthBps);
        }
    }
    
    private ConnectionQualityHelper(Context context) {
        this.context = context.getApplicationContext();
        this.connectivityManager = (ConnectivityManager) 
                context.getSystemService(Context.CONNECTIVITY_SERVICE);
    }
    
    /**
     * Get singleton instance.
     */
    public static ConnectionQualityHelper getInstance(@NonNull Context context) {
        if (instance == null) {
            synchronized (ConnectionQualityHelper.class) {
                if (instance == null) {
                    instance = new ConnectionQualityHelper(context);
                }
            }
        }
        return instance;
    }
    
    /**
     * Get current connection type.
     */
    @NonNull
    public ConnectionType getConnectionType() {
        if (connectivityManager == null) {
            return ConnectionType.UNKNOWN;
        }
        
        Network network = connectivityManager.getActiveNetwork();
        if (network == null) {
            return ConnectionType.NONE;
        }
        
        NetworkCapabilities caps = connectivityManager.getNetworkCapabilities(network);
        if (caps == null) {
            return ConnectionType.UNKNOWN;
        }
        
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
            return ConnectionType.WIFI;
        } else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
            return ConnectionType.CELLULAR;
        } else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) {
            return ConnectionType.ETHERNET;
        } else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
            return ConnectionType.VPN;
        } else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH)) {
            return ConnectionType.BLUETOOTH;
        }
        
        return ConnectionType.UNKNOWN;
    }
    
    /**
     * Get connection quality assessment.
     */
    @NonNull
    public ConnectionQuality getConnectionQuality() {
        if (connectivityManager == null) {
            return ConnectionQuality.UNKNOWN;
        }
        
        Network network = connectivityManager.getActiveNetwork();
        if (network == null) {
            return ConnectionQuality.VERY_POOR;
        }
        
        NetworkCapabilities caps = connectivityManager.getNetworkCapabilities(network);
        if (caps == null) {
            return ConnectionQuality.UNKNOWN;
        }
        
        // Check for validated internet
        if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
            return ConnectionQuality.POOR;
        }
        
        // Estimate quality based on capabilities
        int score = 0;
        
        // Base score from bandwidth
        int downBandwidth = caps.getLinkDownstreamBandwidthKbps();
        if (downBandwidth > 50000) score += 3;       // > 50 Mbps
        else if (downBandwidth > 10000) score += 2;  // > 10 Mbps
        else if (downBandwidth > 1000) score += 1;   // > 1 Mbps
        
        // Bonus for unmetered
        if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)) {
            score += 1;
        }
        
        // Consider latency if available
        if (lastLatencyMs > 0) {
            if (lastLatencyMs < 50) score += 2;
            else if (lastLatencyMs < 100) score += 1;
            else if (lastLatencyMs > 500) score -= 1;
        }
        
        // Consider stability
        if (consecutiveFailures > 5) score -= 2;
        else if (consecutiveFailures > 2) score -= 1;
        
        // Map score to quality
        if (score >= 5) return ConnectionQuality.EXCELLENT;
        if (score >= 4) return ConnectionQuality.GOOD;
        if (score >= 2) return ConnectionQuality.MODERATE;
        if (score >= 1) return ConnectionQuality.POOR;
        return ConnectionQuality.VERY_POOR;
    }
    
    /**
     * Get detailed connection info.
     */
    @NonNull
    public ConnectionInfo getConnectionInfo() {
        ConnectionType type = getConnectionType();
        ConnectionQuality quality = getConnectionQuality();
        String ipAddress = getLocalIpAddress();
        
        boolean isMetered = false;
        boolean hasInternet = false;
        long bandwidthBps = 0;
        
        if (connectivityManager != null) {
            Network network = connectivityManager.getActiveNetwork();
            if (network != null) {
                NetworkCapabilities caps = connectivityManager.getNetworkCapabilities(network);
                if (caps != null) {
                    isMetered = !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED);
                    hasInternet = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET);
                    bandwidthBps = caps.getLinkDownstreamBandwidthKbps() * 1000L;
                }
            }
        }
        
        return new ConnectionInfo(
                type, quality, lastLatencyMs, bandwidthBps,
                ipAddress, null, isMetered, hasInternet, -1
        );
    }
    
    /**
     * Check if connection is good for scanning.
     */
    public boolean isGoodForScanning() {
        ConnectionQuality quality = getConnectionQuality();
        return quality.level >= ConnectionQuality.MODERATE.level;
    }
    
    /**
     * Check if connection is metered.
     */
    public boolean isMetered() {
        if (connectivityManager == null) {
            return true; // Assume metered if unknown
        }
        
        Network network = connectivityManager.getActiveNetwork();
        if (network == null) {
            return true;
        }
        
        NetworkCapabilities caps = connectivityManager.getNetworkCapabilities(network);
        if (caps == null) {
            return true;
        }
        
        return !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED);
    }
    
    /**
     * Check if connected.
     */
    public boolean isConnected() {
        if (connectivityManager == null) {
            return false;
        }
        
        Network network = connectivityManager.getActiveNetwork();
        if (network == null) {
            return false;
        }
        
        NetworkCapabilities caps = connectivityManager.getNetworkCapabilities(network);
        return caps != null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET);
    }
    
    /**
     * Get local IP address.
     */
    @Nullable
    public String getLocalIpAddress() {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface iface = interfaces.nextElement();
                if (iface.isLoopback() || !iface.isUp()) {
                    continue;
                }
                
                Enumeration<InetAddress> addresses = iface.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    if (!addr.isLoopbackAddress() && addr.getHostAddress().indexOf(':') < 0) {
                        return addr.getHostAddress();
                    }
                }
            }
        } catch (SocketException e) {
            Log.w(TAG, "Failed to get local IP", e);
        }
        return null;
    }
    
    /**
     * Get all local IP addresses.
     */
    @NonNull
    public List<String> getAllLocalIpAddresses() {
        List<String> addresses = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface iface = interfaces.nextElement();
                if (iface.isLoopback() || !iface.isUp()) {
                    continue;
                }
                
                Enumeration<InetAddress> inetAddresses = iface.getInetAddresses();
                while (inetAddresses.hasMoreElements()) {
                    InetAddress addr = inetAddresses.nextElement();
                    if (!addr.isLoopbackAddress()) {
                        addresses.add(addr.getHostAddress());
                    }
                }
            }
        } catch (SocketException e) {
            Log.w(TAG, "Failed to enumerate interfaces", e);
        }
        return addresses;
    }
    
    /**
     * Measure latency to a host.
     * 
     * @param host target host
     * @param timeoutMs timeout in milliseconds
     * @return latency in milliseconds or -1 if failed
     */
    public long measureLatency(@NonNull String host, int timeoutMs) {
        try {
            InetAddress address = InetAddress.getByName(host);
            long start = System.currentTimeMillis();
            boolean reachable = address.isReachable(timeoutMs);
            long elapsed = System.currentTimeMillis() - start;
            
            if (reachable) {
                lastLatencyMs = elapsed;
                consecutiveFailures = 0;
                return elapsed;
            } else {
                consecutiveFailures++;
                return -1;
            }
        } catch (Exception e) {
            Log.w(TAG, "Latency measurement failed: " + e.getMessage());
            consecutiveFailures++;
            return -1;
        }
    }
    
    /**
     * Record connection failure.
     */
    public void recordFailure() {
        consecutiveFailures++;
    }
    
    /**
     * Record connection success.
     */
    public void recordSuccess() {
        consecutiveFailures = 0;
    }
    
    /**
     * Get recommended timeout based on connection quality.
     */
    public int getRecommendedTimeout() {
        ConnectionQuality quality = getConnectionQuality();
        
        switch (quality) {
            case EXCELLENT:
                return 1000;
            case GOOD:
                return 2000;
            case MODERATE:
                return 3000;
            case POOR:
                return 5000;
            case VERY_POOR:
                return 10000;
            default:
                return 3000;
        }
    }
    
    /**
     * Get recommended parallel connections based on connection quality.
     */
    public int getRecommendedParallelConnections() {
        ConnectionQuality quality = getConnectionQuality();
        ConnectionType type = getConnectionType();
        
        // Base on connection type
        int base;
        switch (type) {
            case WIFI:
            case ETHERNET:
                base = 20;
                break;
            case CELLULAR:
                base = 10;
                break;
            case VPN:
                base = 15;
                break;
            default:
                base = 5;
        }
        
        // Adjust for quality
        switch (quality) {
            case EXCELLENT:
                return base;
            case GOOD:
                return (int) (base * 0.8);
            case MODERATE:
                return (int) (base * 0.5);
            case POOR:
                return (int) (base * 0.3);
            default:
                return 2;
        }
    }
}
