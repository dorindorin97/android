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
import android.net.TrafficStats;
import org.csploit.android.helpers.LoggingHelper;
import android.os.Handler;
import org.csploit.android.helpers.LoggingHelper;
import android.os.Looper;
import org.csploit.android.helpers.LoggingHelper;

import androidx.annotation.NonNull;
import org.csploit.android.helpers.LoggingHelper;
import androidx.annotation.Nullable;
import org.csploit.android.helpers.LoggingHelper;

import java.io.BufferedReader;
import org.csploit.android.helpers.LoggingHelper;
import java.io.FileReader;
import org.csploit.android.helpers.LoggingHelper;
import java.io.IOException;
import org.csploit.android.helpers.LoggingHelper;
import java.util.ArrayList;
import org.csploit.android.helpers.LoggingHelper;
import java.util.List;
import org.csploit.android.helpers.LoggingHelper;
import java.util.Locale;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.ScheduledExecutorService;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.ScheduledFuture;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.Executors;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.TimeUnit;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.atomic.AtomicBoolean;
import org.csploit.android.helpers.LoggingHelper;

/**
 * BandwidthMonitor - Real-time network bandwidth monitoring.
 * 
 * Provides methods for:
 * - Real-time bandwidth monitoring (upload/download)
 * - Per-interface traffic stats
 * - Bandwidth history tracking
 * - Traffic peak detection
 * - Data usage statistics
 * 
 * Usage:
 * {@code
 * // Start monitoring
 * BandwidthMonitor monitor = new BandwidthMonitor();
 * monitor.startMonitoring(1000, new BandwidthCallback() {
 *     public void onUpdate(BandwidthStats stats) {
 *         Log.d(TAG, "Download: " + stats.getDownloadSpeedFormatted());
 *         Log.d(TAG, "Upload: " + stats.getUploadSpeedFormatted());
 *     }
 * });
 * 
 * // Stop monitoring
 * monitor.stopMonitoring();
 * }
 */
public class BandwidthMonitor {
  private static final String TAG = "BandwidthMonitor";
    
    private static final int DEFAULT_INTERVAL_MS = 1000;
    private static final int HISTORY_SIZE = 60; // 1 minute of history at 1s intervals
    
    private final ScheduledExecutorService scheduler;
    private final Handler mainHandler;
    private final List<BandwidthStats> history;
    private final AtomicBoolean running;
    
    private ScheduledFuture<?> monitoringTask;
    private long lastRxBytes;
    private long lastTxBytes;
    private long lastTimestamp;
    private long peakDownloadSpeed;
    private long peakUploadSpeed;
    private long sessionStartRx;
    private long sessionStartTx;
    private long sessionStartTime;
    
    /**
     * Bandwidth statistics snapshot.
     */
    public static class BandwidthStats {
        public final long timestamp;
        public final long downloadSpeed;  // bytes per second
        public final long uploadSpeed;    // bytes per second
        public final long totalRxBytes;
        public final long totalTxBytes;
        public final long sessionRxBytes;
        public final long sessionTxBytes;
        
        public BandwidthStats(long timestamp, long downloadSpeed, long uploadSpeed,
                             long totalRxBytes, long totalTxBytes,
                             long sessionRxBytes, long sessionTxBytes) {
            this.timestamp = timestamp;
            this.downloadSpeed = downloadSpeed;
            this.uploadSpeed = uploadSpeed;
            this.totalRxBytes = totalRxBytes;
            this.totalTxBytes = totalTxBytes;
            this.sessionRxBytes = sessionRxBytes;
            this.sessionTxBytes = sessionTxBytes;
        }
        
        /**
         * Get formatted download speed string.
         */
        @NonNull
        public String getDownloadSpeedFormatted() {
            return formatSpeed(downloadSpeed);
        }
        
        /**
         * Get formatted upload speed string.
         */
        @NonNull
        public String getUploadSpeedFormatted() {
            return formatSpeed(uploadSpeed);
        }
        
        /**
         * Get formatted session download total.
         */
        @NonNull
        public String getSessionDownloadFormatted() {
            return formatBytes(sessionRxBytes);
        }
        
        /**
         * Get formatted session upload total.
         */
        @NonNull
        public String getSessionUploadFormatted() {
            return formatBytes(sessionTxBytes);
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format(Locale.US, "↓ %s  ↑ %s", 
                    getDownloadSpeedFormatted(), getUploadSpeedFormatted());
        }
    }
    
    /**
     * Interface statistics for a specific network interface.
     */
    public static class InterfaceStats {
        public final String interfaceName;
        public final long rxBytes;
        public final long txBytes;
        public final long rxPackets;
        public final long txPackets;
        public final long rxErrors;
        public final long txErrors;
        
        public InterfaceStats(String interfaceName, long rxBytes, long txBytes,
                             long rxPackets, long txPackets, long rxErrors, long txErrors) {
            this.interfaceName = interfaceName;
            this.rxBytes = rxBytes;
            this.txBytes = txBytes;
            this.rxPackets = rxPackets;
            this.txPackets = txPackets;
            this.rxErrors = rxErrors;
            this.txErrors = txErrors;
        }
    }
    
    /**
     * Callback for bandwidth updates.
     */
    public interface BandwidthCallback {
        void onUpdate(BandwidthStats stats);
    }
    
    /**
     * Create a new bandwidth monitor.
     */
    public BandwidthMonitor() {
        this.scheduler = Executors.newSingleThreadScheduledExecutor();
        this.mainHandler = new Handler(Looper.getMainLooper());
        this.history = new ArrayList<>();
        this.running = new AtomicBoolean(false);
        this.peakDownloadSpeed = 0;
        this.peakUploadSpeed = 0;
    }
    
    /**
     * Start bandwidth monitoring.
     * 
     * @param intervalMs update interval in milliseconds
     * @param callback callback for bandwidth updates (on main thread)
     */
    public void startMonitoring(int intervalMs, @NonNull BandwidthCallback callback) {
        if (running.getAndSet(true)) {
            LoggingHelper.w(TAG, "Monitoring already running");
            return;
        }
        
        // Initialize baseline
        lastRxBytes = TrafficStats.getTotalRxBytes();
        lastTxBytes = TrafficStats.getTotalTxBytes();
        lastTimestamp = System.currentTimeMillis();
        sessionStartRx = lastRxBytes;
        sessionStartTx = lastTxBytes;
        sessionStartTime = lastTimestamp;
        
        history.clear();
        
        monitoringTask = scheduler.scheduleAtFixedRate(() -> {
            if (!running.get()) return;
            
            long currentRxBytes = TrafficStats.getTotalRxBytes();
            long currentTxBytes = TrafficStats.getTotalTxBytes();
            long currentTime = System.currentTimeMillis();
            
            long timeDelta = currentTime - lastTimestamp;
            if (timeDelta <= 0) timeDelta = 1;
            
            long rxDelta = currentRxBytes - lastRxBytes;
            long txDelta = currentTxBytes - lastTxBytes;
            
            // Calculate speed in bytes per second
            long downloadSpeed = (rxDelta * 1000) / timeDelta;
            long uploadSpeed = (txDelta * 1000) / timeDelta;
            
            // Update peaks
            if (downloadSpeed > peakDownloadSpeed) {
                peakDownloadSpeed = downloadSpeed;
            }
            if (uploadSpeed > peakUploadSpeed) {
                peakUploadSpeed = uploadSpeed;
            }
            
            // Create stats
            BandwidthStats stats = new BandwidthStats(
                    currentTime,
                    downloadSpeed,
                    uploadSpeed,
                    currentRxBytes,
                    currentTxBytes,
                    currentRxBytes - sessionStartRx,
                    currentTxBytes - sessionStartTx
            );
            
            // Update history
            synchronized (history) {
                history.add(stats);
                while (history.size() > HISTORY_SIZE) {
                    history.remove(0);
                }
            }
            
            // Update last values
            lastRxBytes = currentRxBytes;
            lastTxBytes = currentTxBytes;
            lastTimestamp = currentTime;
            
            // Callback on main thread
            mainHandler.post(() -> callback.onUpdate(stats));
            
        }, 0, intervalMs, TimeUnit.MILLISECONDS);
        
        LoggingHelper.i(TAG, "Bandwidth monitoring started with " + intervalMs + "ms interval");
    }
    
    /**
     * Start monitoring with default interval (1 second).
     * 
     * @param callback callback for updates
     */
    public void startMonitoring(@NonNull BandwidthCallback callback) {
        startMonitoring(DEFAULT_INTERVAL_MS, callback);
    }
    
    /**
     * Stop bandwidth monitoring.
     */
    public void stopMonitoring() {
        if (!running.getAndSet(false)) {
            return;
        }
        
        if (monitoringTask != null) {
            monitoringTask.cancel(false);
            monitoringTask = null;
        }
        
        LoggingHelper.i(TAG, "Bandwidth monitoring stopped");
    }
    
    /**
     * Check if monitoring is running.
     */
    public boolean isMonitoring() {
        return running.get();
    }
    
    /**
     * Get bandwidth history.
     * 
     * @return copy of history list
     */
    @NonNull
    public List<BandwidthStats> getHistory() {
        synchronized (history) {
            return new ArrayList<>(history);
        }
    }
    
    /**
     * Get average download speed over history period.
     * 
     * @return average bytes per second
     */
    public long getAverageDownloadSpeed() {
        synchronized (history) {
            if (history.isEmpty()) return 0;
            
            long total = 0;
            for (BandwidthStats stats : history) {
                total += stats.downloadSpeed;
            }
            return total / history.size();
        }
    }
    
    /**
     * Get average upload speed over history period.
     * 
     * @return average bytes per second
     */
    public long getAverageUploadSpeed() {
        synchronized (history) {
            if (history.isEmpty()) return 0;
            
            long total = 0;
            for (BandwidthStats stats : history) {
                total += stats.uploadSpeed;
            }
            return total / history.size();
        }
    }
    
    /**
     * Get peak download speed since monitoring started.
     */
    public long getPeakDownloadSpeed() {
        return peakDownloadSpeed;
    }
    
    /**
     * Get peak upload speed since monitoring started.
     */
    public long getPeakUploadSpeed() {
        return peakUploadSpeed;
    }
    
    /**
     * Get session duration in milliseconds.
     */
    public long getSessionDuration() {
        if (sessionStartTime == 0) return 0;
        return System.currentTimeMillis() - sessionStartTime;
    }
    
    /**
     * Get current bandwidth stats snapshot.
     * 
     * @return current stats or null if not monitoring
     */
    @Nullable
    public BandwidthStats getCurrentStats() {
        synchronized (history) {
            if (history.isEmpty()) return null;
            return history.get(history.size() - 1);
        }
    }
    
    /**
     * Get stats for a specific network interface.
     * 
     * @param interfaceName interface name (e.g., "wlan0", "eth0")
     * @return interface stats or null if not found
     */
    @Nullable
    public static InterfaceStats getInterfaceStats(@NonNull String interfaceName) {
        String path = "/sys/class/net/" + interfaceName + "/statistics/";
        
        try {
            long rxBytes = readLongFromFile(path + "rx_bytes");
            long txBytes = readLongFromFile(path + "tx_bytes");
            long rxPackets = readLongFromFile(path + "rx_packets");
            long txPackets = readLongFromFile(path + "tx_packets");
            long rxErrors = readLongFromFile(path + "rx_errors");
            long txErrors = readLongFromFile(path + "tx_errors");
            
            return new InterfaceStats(interfaceName, rxBytes, txBytes, 
                    rxPackets, txPackets, rxErrors, txErrors);
            
        } catch (IOException e) {
            LoggingHelper.d(TAG, "Failed to read interface stats: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Read a long value from a file.
     */
    private static long readLongFromFile(String path) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(path))) {
            String line = reader.readLine();
            return Long.parseLong(line.trim());
        }
    }
    
    /**
     * Get total mobile data usage.
     * 
     * @return bytes used on mobile network
     */
    public static long getMobileDataUsage() {
        return TrafficStats.getMobileRxBytes() + TrafficStats.getMobileTxBytes();
    }
    
    /**
     * Get total WiFi data usage.
     * 
     * @return bytes used on WiFi (total minus mobile)
     */
    public static long getWifiDataUsage() {
        long total = TrafficStats.getTotalRxBytes() + TrafficStats.getTotalTxBytes();
        long mobile = getMobileDataUsage();
        return Math.max(0, total - mobile);
    }
    
    /**
     * Get data usage for a specific UID (app).
     * 
     * @param uid application UID
     * @return total bytes used by the app
     */
    public static long getAppDataUsage(int uid) {
        return TrafficStats.getUidRxBytes(uid) + TrafficStats.getUidTxBytes(uid);
    }
    
    /**
     * Format bytes per second to human-readable speed string.
     * 
     * @param bytesPerSecond speed in bytes per second
     * @return formatted string (e.g., "1.5 MB/s")
     */
    @NonNull
    public static String formatSpeed(long bytesPerSecond) {
        if (bytesPerSecond < 0) return "N/A";
        
        if (bytesPerSecond < 1024) {
            return bytesPerSecond + " B/s";
        } else if (bytesPerSecond < 1024 * 1024) {
            return String.format(Locale.US, "%.1f KB/s", bytesPerSecond / 1024.0);
        } else if (bytesPerSecond < 1024 * 1024 * 1024) {
            return String.format(Locale.US, "%.2f MB/s", bytesPerSecond / (1024.0 * 1024.0));
        } else {
            return String.format(Locale.US, "%.2f GB/s", bytesPerSecond / (1024.0 * 1024.0 * 1024.0));
        }
    }
    
    /**
     * Format bytes to human-readable string.
     * 
     * @param bytes byte count
     * @return formatted string (e.g., "1.5 GB")
     */
    @NonNull
    public static String formatBytes(long bytes) {
        if (bytes < 0) return "N/A";
        
        if (bytes < 1024) {
            return bytes + " B";
        } else if (bytes < 1024 * 1024) {
            return String.format(Locale.US, "%.1f KB", bytes / 1024.0);
        } else if (bytes < 1024 * 1024 * 1024) {
            return String.format(Locale.US, "%.2f MB", bytes / (1024.0 * 1024.0));
        } else {
            return String.format(Locale.US, "%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0));
        }
    }
    
    /**
     * Shutdown the monitor and release resources.
     */
    public void shutdown() {
        stopMonitoring();
        scheduler.shutdownNow();
    }
}
