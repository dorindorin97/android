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
import android.net.TrafficStats;
import android.os.Build;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * TrafficMonitor - Network traffic monitoring and analysis.
 * 
 * Provides:
 * - Real-time traffic statistics
 * - Per-application traffic tracking
 * - Bandwidth usage monitoring
 * - Traffic anomaly detection
 * 
 * Usage:
 * {@code
 * TrafficMonitor monitor = new TrafficMonitor(context);
 * monitor.startMonitoring();
 * 
 * // Get current stats
 * TrafficStats stats = monitor.getCurrentStats();
 * 
 * // Stop monitoring
 * monitor.stopMonitoring();
 * }
 */
public final class TrafficMonitor {
    
    private static final String TAG = "TrafficMonitor";
    private static final long DEFAULT_POLL_INTERVAL_MS = 1000; // 1 second
    
    private final Context context;
    private final AtomicBoolean isMonitoring = new AtomicBoolean(false);
    private final ConcurrentHashMap<Integer, AppTrafficInfo> appTrafficMap = new ConcurrentHashMap<>();
    private final List<TrafficSnapshot> history = new ArrayList<>();
    private final int maxHistorySize;
    
    private Thread monitorThread;
    private long pollIntervalMs = DEFAULT_POLL_INTERVAL_MS;
    private TrafficListener listener;
    
    // Base values for delta calculation
    private long baseRxBytes = 0;
    private long baseTxBytes = 0;
    private long baseRxPackets = 0;
    private long baseTxPackets = 0;
    
    // Current values
    private final AtomicLong currentRxBytesPerSec = new AtomicLong(0);
    private final AtomicLong currentTxBytesPerSec = new AtomicLong(0);
    
    /**
     * Traffic snapshot at a point in time.
     */
    public static class TrafficSnapshot {
        public long timestamp;
        public long rxBytes;
        public long txBytes;
        public long rxPackets;
        public long txPackets;
        public long rxBytesPerSec;
        public long txBytesPerSec;
        
        @NonNull
        @Override
        public String toString() {
            return String.format("Traffic{rx=%s/s, tx=%s/s}",
                    formatBytes(rxBytesPerSec), formatBytes(txBytesPerSec));
        }
    }
    
    /**
     * Per-application traffic information.
     */
    public static class AppTrafficInfo {
        public int uid;
        public String packageName;
        public long rxBytes;
        public long txBytes;
        public long rxPackets;
        public long txPackets;
        public long lastUpdateTime;
        
        // Delta tracking
        public long previousRxBytes;
        public long previousTxBytes;
        public long rxBytesPerSec;
        public long txBytesPerSec;
        
        @NonNull
        @Override
        public String toString() {
            return String.format("App{pkg='%s', rx=%s, tx=%s}",
                    packageName, formatBytes(rxBytes), formatBytes(txBytes));
        }
    }
    
    /**
     * Listener for traffic updates.
     */
    public interface TrafficListener {
        void onTrafficUpdate(TrafficSnapshot snapshot);
        void onAnomalyDetected(String type, String description);
    }
    
    /**
     * Create traffic monitor with default history size.
     */
    public TrafficMonitor(@NonNull Context context) {
        this(context, 300); // 5 minutes of history at 1 second intervals
    }
    
    /**
     * Create traffic monitor with custom history size.
     */
    public TrafficMonitor(@NonNull Context context, int maxHistorySize) {
        this.context = context.getApplicationContext();
        this.maxHistorySize = maxHistorySize;
    }
    
    /**
     * Set traffic listener.
     */
    public void setListener(@Nullable TrafficListener listener) {
        this.listener = listener;
    }
    
    /**
     * Set poll interval.
     */
    public void setPollInterval(long intervalMs) {
        this.pollIntervalMs = Math.max(100, intervalMs);
    }
    
    /**
     * Start traffic monitoring.
     */
    public void startMonitoring() {
        if (isMonitoring.getAndSet(true)) {
            return; // Already monitoring
        }
        
        // Initialize base values
        baseRxBytes = TrafficStats.getTotalRxBytes();
        baseTxBytes = TrafficStats.getTotalTxBytes();
        baseRxPackets = TrafficStats.getTotalRxPackets();
        baseTxPackets = TrafficStats.getTotalTxPackets();
        
        monitorThread = new Thread(this::monitoringLoop, "TrafficMonitor");
        monitorThread.setDaemon(true);
        monitorThread.start();
        
        Log.i(TAG, "Traffic monitoring started");
    }
    
    /**
     * Stop traffic monitoring.
     */
    public void stopMonitoring() {
        if (!isMonitoring.getAndSet(false)) {
            return; // Not monitoring
        }
        
        if (monitorThread != null) {
            monitorThread.interrupt();
            try {
                monitorThread.join(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            monitorThread = null;
        }
        
        Log.i(TAG, "Traffic monitoring stopped");
    }
    
    /**
     * Check if monitoring is active.
     */
    public boolean isMonitoring() {
        return isMonitoring.get();
    }
    
    /**
     * Main monitoring loop.
     */
    private void monitoringLoop() {
        long previousRxBytes = baseRxBytes;
        long previousTxBytes = baseTxBytes;
        long previousTime = java.lang.System.currentTimeMillis();
        
        while (isMonitoring.get()) {
            try {
                Thread.sleep(pollIntervalMs);
                
                long currentTime = java.lang.System.currentTimeMillis();
                long elapsedMs = currentTime - previousTime;
                
                long currentRxBytes = TrafficStats.getTotalRxBytes();
                long currentTxBytes = TrafficStats.getTotalTxBytes();
                long currentRxPackets = TrafficStats.getTotalRxPackets();
                long currentTxPackets = TrafficStats.getTotalTxPackets();
                
                // Calculate rates
                long deltaRxBytes = currentRxBytes - previousRxBytes;
                long deltaTxBytes = currentTxBytes - previousTxBytes;
                
                long rxBytesPerSec = (deltaRxBytes * 1000) / Math.max(elapsedMs, 1);
                long txBytesPerSec = (deltaTxBytes * 1000) / Math.max(elapsedMs, 1);
                
                currentRxBytesPerSec.set(rxBytesPerSec);
                currentTxBytesPerSec.set(txBytesPerSec);
                
                // Create snapshot
                TrafficSnapshot snapshot = new TrafficSnapshot();
                snapshot.timestamp = currentTime;
                snapshot.rxBytes = currentRxBytes - baseRxBytes;
                snapshot.txBytes = currentTxBytes - baseTxBytes;
                snapshot.rxPackets = currentRxPackets - baseRxPackets;
                snapshot.txPackets = currentTxPackets - baseTxPackets;
                snapshot.rxBytesPerSec = rxBytesPerSec;
                snapshot.txBytesPerSec = txBytesPerSec;
                
                // Add to history
                synchronized (history) {
                    history.add(snapshot);
                    while (history.size() > maxHistorySize) {
                        history.remove(0);
                    }
                }
                
                // Check for anomalies
                checkForAnomalies(snapshot);
                
                // Notify listener
                if (listener != null) {
                    try {
                        listener.onTrafficUpdate(snapshot);
                    } catch (Exception e) {
                        Log.w(TAG, "Listener error", e);
                    }
                }
                
                previousRxBytes = currentRxBytes;
                previousTxBytes = currentTxBytes;
                previousTime = currentTime;
                
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                Log.e(TAG, "Monitoring error", e);
            }
        }
    }
    
    /**
     * Check for traffic anomalies.
     */
    private void checkForAnomalies(TrafficSnapshot current) {
        if (listener == null) return;
        
        synchronized (history) {
            if (history.size() < 10) return;
            
            // Calculate average rates
            long avgRxRate = 0;
            long avgTxRate = 0;
            int count = Math.min(30, history.size() - 1);
            
            for (int i = history.size() - count - 1; i < history.size() - 1; i++) {
                avgRxRate += history.get(i).rxBytesPerSec;
                avgTxRate += history.get(i).txBytesPerSec;
            }
            avgRxRate /= count;
            avgTxRate /= count;
            
            // Detect spikes (more than 5x average)
            if (avgRxRate > 0 && current.rxBytesPerSec > avgRxRate * 5) {
                listener.onAnomalyDetected("RX_SPIKE", 
                        String.format("Receive rate spike: %s/s (avg: %s/s)",
                                formatBytes(current.rxBytesPerSec), formatBytes(avgRxRate)));
            }
            
            if (avgTxRate > 0 && current.txBytesPerSec > avgTxRate * 5) {
                listener.onAnomalyDetected("TX_SPIKE",
                        String.format("Transmit rate spike: %s/s (avg: %s/s)",
                                formatBytes(current.txBytesPerSec), formatBytes(avgTxRate)));
            }
        }
    }
    
    /**
     * Get current traffic statistics.
     */
    @NonNull
    public TrafficSnapshot getCurrentStats() {
        TrafficSnapshot snapshot = new TrafficSnapshot();
        snapshot.timestamp = java.lang.System.currentTimeMillis();
        snapshot.rxBytes = TrafficStats.getTotalRxBytes() - baseRxBytes;
        snapshot.txBytes = TrafficStats.getTotalTxBytes() - baseTxBytes;
        snapshot.rxPackets = TrafficStats.getTotalRxPackets() - baseRxPackets;
        snapshot.txPackets = TrafficStats.getTotalTxPackets() - baseTxPackets;
        snapshot.rxBytesPerSec = currentRxBytesPerSec.get();
        snapshot.txBytesPerSec = currentTxBytesPerSec.get();
        return snapshot;
    }
    
    /**
     * Get traffic history.
     */
    @NonNull
    public List<TrafficSnapshot> getHistory() {
        synchronized (history) {
            return new ArrayList<>(history);
        }
    }
    
    /**
     * Get traffic for specific UID.
     */
    @NonNull
    public AppTrafficInfo getUidTraffic(int uid) {
        AppTrafficInfo info = appTrafficMap.get(uid);
        if (info == null) {
            info = new AppTrafficInfo();
            info.uid = uid;
        }
        
        info.rxBytes = TrafficStats.getUidRxBytes(uid);
        info.txBytes = TrafficStats.getUidTxBytes(uid);
        info.rxPackets = TrafficStats.getUidRxPackets(uid);
        info.txPackets = TrafficStats.getUidTxPackets(uid);
        info.lastUpdateTime = java.lang.System.currentTimeMillis();
        
        return info;
    }
    
    /**
     * Get total bytes received since monitoring started.
     */
    public long getTotalRxBytes() {
        return TrafficStats.getTotalRxBytes() - baseRxBytes;
    }
    
    /**
     * Get total bytes transmitted since monitoring started.
     */
    public long getTotalTxBytes() {
        return TrafficStats.getTotalTxBytes() - baseTxBytes;
    }
    
    /**
     * Get current receive rate in bytes per second.
     */
    public long getRxBytesPerSecond() {
        return currentRxBytesPerSec.get();
    }
    
    /**
     * Get current transmit rate in bytes per second.
     */
    public long getTxBytesPerSecond() {
        return currentTxBytesPerSec.get();
    }
    
    /**
     * Get mobile traffic statistics.
     */
    @NonNull
    public Map<String, Long> getMobileStats() {
        Map<String, Long> stats = new HashMap<>();
        stats.put("rxBytes", TrafficStats.getMobileRxBytes());
        stats.put("txBytes", TrafficStats.getMobileTxBytes());
        stats.put("rxPackets", TrafficStats.getMobileRxPackets());
        stats.put("txPackets", TrafficStats.getMobileTxPackets());
        return stats;
    }
    
    /**
     * Reset statistics.
     */
    public void resetStats() {
        baseRxBytes = TrafficStats.getTotalRxBytes();
        baseTxBytes = TrafficStats.getTotalTxBytes();
        baseRxPackets = TrafficStats.getTotalRxPackets();
        baseTxPackets = TrafficStats.getTotalTxPackets();
        
        synchronized (history) {
            history.clear();
        }
        
        appTrafficMap.clear();
        
        Log.i(TAG, "Statistics reset");
    }
    
    /**
     * Format bytes to human readable string.
     */
    @NonNull
    public static String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024));
        return String.format("%.1f GB", bytes / (1024.0 * 1024 * 1024));
    }
    
    /**
     * Format rate to human readable string.
     */
    @NonNull
    public static String formatRate(long bytesPerSec) {
        return formatBytes(bytesPerSec) + "/s";
    }
}
