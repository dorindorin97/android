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
import android.net.ConnectivityManager;
import org.csploit.android.helpers.LoggingHelper;
import android.net.Network;
import org.csploit.android.helpers.LoggingHelper;
import android.net.NetworkCapabilities;
import org.csploit.android.helpers.LoggingHelper;
import android.net.NetworkRequest;
import org.csploit.android.helpers.LoggingHelper;
import android.net.TrafficStats;
import org.csploit.android.helpers.LoggingHelper;
import android.os.Build;
import org.csploit.android.helpers.LoggingHelper;

import androidx.annotation.NonNull;
import org.csploit.android.helpers.LoggingHelper;
import androidx.annotation.Nullable;
import org.csploit.android.helpers.LoggingHelper;

import java.util.ArrayList;
import org.csploit.android.helpers.LoggingHelper;
import java.util.Collections;
import org.csploit.android.helpers.LoggingHelper;
import java.util.List;
import org.csploit.android.helpers.LoggingHelper;
import java.util.Map;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.ConcurrentHashMap;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.CopyOnWriteArrayList;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.ScheduledFuture;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.TimeUnit;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.atomic.AtomicBoolean;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.atomic.AtomicLong;
import org.csploit.android.helpers.LoggingHelper;

/**
 * NetworkMonitor - Real-time network traffic monitoring
 *
 * Provides comprehensive network monitoring capabilities including:
 * - Real-time bandwidth usage tracking
 * - Network connection state monitoring
 * - Traffic statistics per application
 * - Network latency monitoring
 * - Connection event tracking
 *
 * Features:
 * - Background monitoring with configurable intervals
 * - Historical data collection
 * - Bandwidth alerts and thresholds
 * - Network quality metrics
 * - Event-based notifications
 *
 * Usage:
 * {@code
 * NetworkMonitor monitor = NetworkMonitor.getInstance();
 * monitor.init(context);
 * monitor.addListener(new NetworkMonitor.NetworkListener() { ... });
 * monitor.startMonitoring();
 * }
 */
public final class NetworkMonitor {

    private static final String TAG = "NetworkMonitor";

    private static volatile NetworkMonitor instance;

    private Context context;
    private ConnectivityManager connectivityManager;
    private ConnectivityManager.NetworkCallback networkCallback;

    private final AtomicBoolean isMonitoring = new AtomicBoolean(false);
    private final AtomicLong lastRxBytes = new AtomicLong(0);
    private final AtomicLong lastTxBytes = new AtomicLong(0);
    private final AtomicLong lastUpdateTime = new AtomicLong(0);

    private ScheduledFuture<?> monitoringTask;
    private long monitoringIntervalMs = 1000; // Default 1 second

    private final List<NetworkListener> listeners = new CopyOnWriteArrayList<>();
    private final List<TrafficSample> trafficHistory = Collections.synchronizedList(new ArrayList<>());
    private static final int MAX_HISTORY_SIZE = 3600; // 1 hour at 1 sample/second

    private final Map<Integer, AppTrafficStats> appTrafficStats = new ConcurrentHashMap<>();

    /**
     * Network connection state
     */
    public enum ConnectionState {
        CONNECTED,
        DISCONNECTED,
        CONNECTING,
        UNKNOWN
    }

    /**
     * Network type
     */
    public enum NetworkType {
        WIFI,
        CELLULAR,
        ETHERNET,
        VPN,
        UNKNOWN
    }

    /**
     * Traffic sample data point
     */
    public static class TrafficSample {
        public final long timestamp;
        public final long rxBytes;
        public final long txBytes;
        public final long rxBytesPerSecond;
        public final long txBytesPerSecond;
        public final long totalBytesPerSecond;

        public TrafficSample(long timestamp, long rxBytes, long txBytes,
                            long rxBps, long txBps) {
            this.timestamp = timestamp;
            this.rxBytes = rxBytes;
            this.txBytes = txBytes;
            this.rxBytesPerSecond = rxBps;
            this.txBytesPerSecond = txBps;
            this.totalBytesPerSecond = rxBps + txBps;
        }

        @NonNull
        @Override
        public String toString() {
            return String.format("Traffic[↓%s/s ↑%s/s]",
                    SystemHelper.formatBytes(rxBytesPerSecond),
                    SystemHelper.formatBytes(txBytesPerSecond));
        }
    }

    /**
     * Per-application traffic statistics
     */
    public static class AppTrafficStats {
        public final int uid;
        public final String packageName;
        public long rxBytes;
        public long txBytes;
        public long lastUpdateTime;

        public AppTrafficStats(int uid, String packageName) {
            this.uid = uid;
            this.packageName = packageName;
            this.rxBytes = 0;
            this.txBytes = 0;
            this.lastUpdateTime = System.currentTimeMillis();
        }

        public void update(long newRxBytes, long newTxBytes) {
            this.rxBytes = newRxBytes;
            this.txBytes = newTxBytes;
            this.lastUpdateTime = System.currentTimeMillis();
        }

        public long getTotalBytes() {
            return rxBytes + txBytes;
        }
    }

    /**
     * Network status information
     */
    public static class NetworkStatus {
        public final ConnectionState state;
        public final NetworkType type;
        public final String networkName;
        public final int signalStrength;
        public final boolean isMetered;
        public final long downloadSpeed;
        public final long uploadSpeed;
        public final long latencyMs;

        public NetworkStatus(ConnectionState state, NetworkType type, String networkName,
                           int signalStrength, boolean isMetered, long downloadSpeed,
                           long uploadSpeed, long latencyMs) {
            this.state = state;
            this.type = type;
            this.networkName = networkName;
            this.signalStrength = signalStrength;
            this.isMetered = isMetered;
            this.downloadSpeed = downloadSpeed;
            this.uploadSpeed = uploadSpeed;
            this.latencyMs = latencyMs;
        }

        @NonNull
        @Override
        public String toString() {
            return String.format("Network[%s/%s, ↓%s/s, ↑%s/s, %dms]",
                    state, type,
                    SystemHelper.formatBytes(downloadSpeed),
                    SystemHelper.formatBytes(uploadSpeed),
                    latencyMs);
        }
    }

    /**
     * Listener interface for network events
     */
    public interface NetworkListener {
        void onTrafficUpdate(TrafficSample sample);
        void onConnectionStateChanged(ConnectionState state, NetworkType type);
        void onNetworkStatusChanged(NetworkStatus status);
        void onBandwidthThresholdExceeded(long currentBps, long thresholdBps);
    }

    /**
     * Simple adapter for NetworkListener
     */
    public static abstract class SimpleNetworkListener implements NetworkListener {
        @Override
        public void onTrafficUpdate(TrafficSample sample) {}
        @Override
        public void onConnectionStateChanged(ConnectionState state, NetworkType type) {}
        @Override
        public void onNetworkStatusChanged(NetworkStatus status) {}
        @Override
        public void onBandwidthThresholdExceeded(long currentBps, long thresholdBps) {}
    }

    private NetworkMonitor() {}

    public static NetworkMonitor getInstance() {
        if (instance == null) {
            synchronized (NetworkMonitor.class) {
                if (instance == null) {
                    instance = new NetworkMonitor();
                }
            }
        }
        return instance;
    }

    /**
     * Initialize with context
     */
    public void init(@NonNull Context context) {
        this.context = context.getApplicationContext();
        this.connectivityManager = (ConnectivityManager)
                context.getSystemService(Context.CONNECTIVITY_SERVICE);
        setupNetworkCallback();
        LoggingHelper.d(TAG, "NetworkMonitor initialized");
    }

    /**
     * Start monitoring network traffic
     */
    public void startMonitoring() {
        startMonitoring(monitoringIntervalMs);
    }

    /**
     * Start monitoring with custom interval
     */
    public void startMonitoring(long intervalMs) {
        if (isMonitoring.getAndSet(true)) {
            LoggingHelper.w(TAG, "Already monitoring");
            return;
        }

        this.monitoringIntervalMs = intervalMs;

        // Initialize baseline
        lastRxBytes.set(TrafficStats.getTotalRxBytes());
        lastTxBytes.set(TrafficStats.getTotalTxBytes());
        lastUpdateTime.set(System.currentTimeMillis());

        // Start periodic monitoring
        monitoringTask = ThreadHelper.scheduleAtFixedRate(
                this::collectTrafficSample,
                0,
                intervalMs,
                TimeUnit.MILLISECONDS
        );

        // Register network callback
        if (connectivityManager != null && networkCallback != null) {
            NetworkRequest request = new NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .build();
            connectivityManager.registerNetworkCallback(request, networkCallback);
        }

        LoggingHelper.d(TAG, "Started monitoring with interval: " + intervalMs + "ms");
    }

    /**
     * Stop monitoring
     */
    public void stopMonitoring() {
        if (!isMonitoring.getAndSet(false)) {
            return;
        }

        if (monitoringTask != null) {
            monitoringTask.cancel(false);
            monitoringTask = null;
        }

        if (connectivityManager != null && networkCallback != null) {
            try {
                connectivityManager.unregisterNetworkCallback(networkCallback);
            } catch (IllegalArgumentException e) {
                // Already unregistered
            }
        }

        LoggingHelper.d(TAG, "Stopped monitoring");
    }

    /**
     * Check if monitoring is active
     */
    public boolean isMonitoring() {
        return isMonitoring.get();
    }

    /**
     * Get current network status
     */
    @NonNull
    public NetworkStatus getCurrentStatus() {
        ConnectionState state = ConnectionState.UNKNOWN;
        NetworkType type = NetworkType.UNKNOWN;
        String networkName = "";
        int signalStrength = 0;
        boolean isMetered = false;

        if (connectivityManager != null) {
            Network network = connectivityManager.getActiveNetwork();
            if (network != null) {
                NetworkCapabilities caps = connectivityManager.getNetworkCapabilities(network);
                if (caps != null) {
                    state = ConnectionState.CONNECTED;

                    if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                        type = NetworkType.WIFI;
                    } else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                        type = NetworkType.CELLULAR;
                    } else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) {
                        type = NetworkType.ETHERNET;
                    } else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                        type = NetworkType.VPN;
                    }

                    isMetered = !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED);

                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        signalStrength = caps.getSignalStrength();
                    }
                }
            } else {
                state = ConnectionState.DISCONNECTED;
            }
        }

        // Get current speeds from latest sample
        long downloadSpeed = 0;
        long uploadSpeed = 0;
        synchronized (trafficHistory) {
            if (!trafficHistory.isEmpty()) {
                TrafficSample latest = trafficHistory.get(trafficHistory.size() - 1);
                downloadSpeed = latest.rxBytesPerSecond;
                uploadSpeed = latest.txBytesPerSecond;
            }
        }

        return new NetworkStatus(state, type, networkName, signalStrength,
                isMetered, downloadSpeed, uploadSpeed, 0);
    }

    /**
     * Get traffic history
     */
    @NonNull
    public List<TrafficSample> getTrafficHistory() {
        synchronized (trafficHistory) {
            return new ArrayList<>(trafficHistory);
        }
    }

    /**
     * Get traffic history for last N seconds
     */
    @NonNull
    public List<TrafficSample> getRecentTraffic(int seconds) {
        long cutoffTime = System.currentTimeMillis() - (seconds * 1000L);
        List<TrafficSample> result = new ArrayList<>();
        synchronized (trafficHistory) {
            for (int i = trafficHistory.size() - 1; i >= 0; i--) {
                TrafficSample sample = trafficHistory.get(i);
                if (sample.timestamp >= cutoffTime) {
                    result.add(0, sample);
                } else {
                    break;
                }
            }
        }
        return result;
    }

    /**
     * Get average bandwidth over time period
     */
    public long getAverageBandwidth(int seconds) {
        List<TrafficSample> samples = getRecentTraffic(seconds);
        if (samples.isEmpty()) return 0;

        long total = 0;
        for (TrafficSample sample : samples) {
            total += sample.totalBytesPerSecond;
        }
        return total / samples.size();
    }

    /**
     * Get peak bandwidth over time period
     */
    public long getPeakBandwidth(int seconds) {
        List<TrafficSample> samples = getRecentTraffic(seconds);
        long peak = 0;
        for (TrafficSample sample : samples) {
            if (sample.totalBytesPerSecond > peak) {
                peak = sample.totalBytesPerSecond;
            }
        }
        return peak;
    }

    /**
     * Get total data transferred
     */
    public long getTotalDataTransferred() {
        return TrafficStats.getTotalRxBytes() + TrafficStats.getTotalTxBytes();
    }

    /**
     * Get application traffic stats
     */
    @Nullable
    public AppTrafficStats getAppTrafficStats(int uid) {
        return appTrafficStats.get(uid);
    }

    /**
     * Update application traffic stats
     */
    public void updateAppTrafficStats(int uid, String packageName) {
        long rxBytes = TrafficStats.getUidRxBytes(uid);
        long txBytes = TrafficStats.getUidTxBytes(uid);

        if (rxBytes != TrafficStats.UNSUPPORTED && txBytes != TrafficStats.UNSUPPORTED) {
            AppTrafficStats stats = appTrafficStats.computeIfAbsent(uid,
                    k -> new AppTrafficStats(uid, packageName));
            stats.update(rxBytes, txBytes);
        }
    }

    /**
     * Clear traffic history
     */
    public void clearHistory() {
        synchronized (trafficHistory) {
            trafficHistory.clear();
        }
        LoggingHelper.d(TAG, "Traffic history cleared");
    }

    /**
     * Add listener
     */
    public void addListener(@NonNull NetworkListener listener) {
        if (!listeners.contains(listener)) {
            listeners.add(listener);
        }
    }

    /**
     * Remove listener
     */
    public void removeListener(@NonNull NetworkListener listener) {
        listeners.remove(listener);
    }

    /**
     * Set monitoring interval
     */
    public void setMonitoringInterval(long intervalMs) {
        boolean wasMonitoring = isMonitoring.get();
        if (wasMonitoring) {
            stopMonitoring();
        }
        this.monitoringIntervalMs = intervalMs;
        if (wasMonitoring) {
            startMonitoring();
        }
    }

    /**
     * Get current monitoring interval
     */
    public long getMonitoringInterval() {
        return monitoringIntervalMs;
    }

    // Private methods
    private void setupNetworkCallback() {
        networkCallback = new ConnectivityManager.NetworkCallback() {
            @Override
            public void onAvailable(@NonNull Network network) {
                notifyConnectionStateChanged(ConnectionState.CONNECTED, getNetworkType(network));
            }

            @Override
            public void onLost(@NonNull Network network) {
                notifyConnectionStateChanged(ConnectionState.DISCONNECTED, NetworkType.UNKNOWN);
            }

            @Override
            public void onCapabilitiesChanged(@NonNull Network network,
                                             @NonNull NetworkCapabilities caps) {
                notifyNetworkStatusChanged(getCurrentStatus());
            }
        };
    }

    private NetworkType getNetworkType(Network network) {
        if (connectivityManager == null) return NetworkType.UNKNOWN;

        NetworkCapabilities caps = connectivityManager.getNetworkCapabilities(network);
        if (caps == null) return NetworkType.UNKNOWN;

        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
            return NetworkType.WIFI;
        } else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
            return NetworkType.CELLULAR;
        } else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) {
            return NetworkType.ETHERNET;
        } else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
            return NetworkType.VPN;
        }
        return NetworkType.UNKNOWN;
    }

    private void collectTrafficSample() {
        try {
            long currentTime = System.currentTimeMillis();
            long currentRx = TrafficStats.getTotalRxBytes();
            long currentTx = TrafficStats.getTotalTxBytes();

            long prevRx = lastRxBytes.getAndSet(currentRx);
            long prevTx = lastTxBytes.getAndSet(currentTx);
            long prevTime = lastUpdateTime.getAndSet(currentTime);

            long timeDiff = currentTime - prevTime;
            if (timeDiff <= 0) timeDiff = 1; // Avoid division by zero

            long rxDiff = currentRx - prevRx;
            long txDiff = currentTx - prevTx;

            // Calculate bytes per second
            long rxBps = (rxDiff * 1000) / timeDiff;
            long txBps = (txDiff * 1000) / timeDiff;

            TrafficSample sample = new TrafficSample(currentTime, currentRx, currentTx, rxBps, txBps);

            // Add to history
            synchronized (trafficHistory) {
                trafficHistory.add(sample);
                while (trafficHistory.size() > MAX_HISTORY_SIZE) {
                    trafficHistory.remove(0);
                }
            }

            // Notify listeners
            notifyTrafficUpdate(sample);

        } catch (Exception e) {
            LoggingHelper.e(TAG, "Error collecting traffic sample", e);
        }
    }

    private void notifyTrafficUpdate(TrafficSample sample) {
        for (NetworkListener listener : listeners) {
            try {
                listener.onTrafficUpdate(sample);
            } catch (Exception e) {
                LoggingHelper.e(TAG, "Error notifying listener", e);
            }
        }
    }

    private void notifyConnectionStateChanged(ConnectionState state, NetworkType type) {
        for (NetworkListener listener : listeners) {
            try {
                listener.onConnectionStateChanged(state, type);
            } catch (Exception e) {
                LoggingHelper.e(TAG, "Error notifying listener", e);
            }
        }
    }

    private void notifyNetworkStatusChanged(NetworkStatus status) {
        for (NetworkListener listener : listeners) {
            try {
                listener.onNetworkStatusChanged(status);
            } catch (Exception e) {
                LoggingHelper.e(TAG, "Error notifying listener", e);
            }
        }
    }

    /**
     * Cleanup resources
     */
    public void cleanup() {
        stopMonitoring();
        listeners.clear();
        trafficHistory.clear();
        appTrafficStats.clear();
        LoggingHelper.d(TAG, "NetworkMonitor cleaned up");
    }
}
