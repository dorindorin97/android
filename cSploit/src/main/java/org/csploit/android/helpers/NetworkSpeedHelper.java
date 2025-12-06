/*
 * This file is part of the cSploit.
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
import android.net.TrafficStats;
import android.os.Build;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.ref.WeakReference;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Helper for measuring network speed and latency.
 *
 * Provides:
 * - Real-time upload/download speed monitoring
 * - Ping latency measurement
 * - Network quality assessment
 * - Bandwidth utilization tracking
 */
public final class NetworkSpeedHelper {

    private static final String TAG = "NetworkSpeedHelper";

    private static NetworkSpeedHelper sInstance;
    private WeakReference<Context> mContext;

    private final AtomicLong mLastRxBytes = new AtomicLong(0);
    private final AtomicLong mLastTxBytes = new AtomicLong(0);
    private final AtomicLong mLastTimestamp = new AtomicLong(0);

    private long mDownloadSpeed = 0; // bytes per second
    private long mUploadSpeed = 0;   // bytes per second
    private final AtomicBoolean mMonitoring = new AtomicBoolean(false);

    /**
     * Network quality levels.
     */
    public enum NetworkQuality {
        EXCELLENT,  // > 10 Mbps, < 50ms latency
        GOOD,       // > 2 Mbps, < 100ms latency
        FAIR,       // > 500 Kbps, < 200ms latency
        POOR,       // < 500 Kbps or > 200ms latency
        UNKNOWN
    }

    /**
     * Speed test result.
     */
    public static class SpeedTestResult {
        public final long downloadSpeedBps;
        public final long uploadSpeedBps;
        public final long pingMs;
        public final NetworkQuality quality;
        public final long timestamp;

        public SpeedTestResult(long download, long upload, long ping, NetworkQuality quality) {
            this.downloadSpeedBps = download;
            this.uploadSpeedBps = upload;
            this.pingMs = ping;
            this.quality = quality;
            this.timestamp = java.lang.System.currentTimeMillis();
        }

        public String getDownloadSpeedFormatted() {
            return formatSpeed(downloadSpeedBps);
        }

        public String getUploadSpeedFormatted() {
            return formatSpeed(uploadSpeedBps);
        }

        @Override
        public String toString() {
            return String.format("Download: %s, Upload: %s, Ping: %dms, Quality: %s",
                    getDownloadSpeedFormatted(), getUploadSpeedFormatted(), pingMs, quality);
        }
    }

    private NetworkSpeedHelper(Context context) {
        mContext = new WeakReference<>(context.getApplicationContext());
    }

    /**
     * Get the singleton instance.
     *
     * @param context Application context
     * @return NetworkSpeedHelper instance
     */
    public static synchronized NetworkSpeedHelper getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new NetworkSpeedHelper(context);
        }
        return sInstance;
    }

    /**
     * Start monitoring network speed.
     */
    public void startMonitoring() {
        if (mMonitoring.getAndSet(true)) {
            return; // Already monitoring
        }

        mLastRxBytes.set(TrafficStats.getTotalRxBytes());
        mLastTxBytes.set(TrafficStats.getTotalTxBytes());
        mLastTimestamp.set(java.lang.System.currentTimeMillis());

        ThreadHelper.scheduleAtFixedRate(this::updateSpeed, 1, 1, java.util.concurrent.TimeUnit.SECONDS);
        LoggingHelper.d(TAG, "Started speed monitoring");
    }

    /**
     * Stop monitoring network speed.
     */
    public void stopMonitoring() {
        mMonitoring.set(false);
        LoggingHelper.d(TAG, "Stopped speed monitoring");
    }

    private void updateSpeed() {
        if (!mMonitoring.get()) {
            return;
        }

        long currentRxBytes = TrafficStats.getTotalRxBytes();
        long currentTxBytes = TrafficStats.getTotalTxBytes();
        long currentTime = java.lang.System.currentTimeMillis();

        long timeDelta = currentTime - mLastTimestamp.get();
        if (timeDelta > 0) {
            long rxDelta = currentRxBytes - mLastRxBytes.get();
            long txDelta = currentTxBytes - mLastTxBytes.get();

            mDownloadSpeed = (rxDelta * 1000) / timeDelta;
            mUploadSpeed = (txDelta * 1000) / timeDelta;
        }

        mLastRxBytes.set(currentRxBytes);
        mLastTxBytes.set(currentTxBytes);
        mLastTimestamp.set(currentTime);
    }

    /**
     * Get current download speed in bytes per second.
     *
     * @return Download speed in Bps
     */
    public long getDownloadSpeed() {
        return mDownloadSpeed;
    }

    /**
     * Get current upload speed in bytes per second.
     *
     * @return Upload speed in Bps
     */
    public long getUploadSpeed() {
        return mUploadSpeed;
    }

    /**
     * Get formatted download speed string.
     *
     * @return Formatted speed (e.g., "5.2 Mbps")
     */
    public String getDownloadSpeedFormatted() {
        return formatSpeed(mDownloadSpeed);
    }

    /**
     * Get formatted upload speed string.
     *
     * @return Formatted speed (e.g., "1.5 Mbps")
     */
    public String getUploadSpeedFormatted() {
        return formatSpeed(mUploadSpeed);
    }

    /**
     * Measure ping latency to a host.
     *
     * @param host Hostname or IP to ping
     * @return Latency in milliseconds, or -1 if failed
     */
    public long measurePing(String host) {
        try {
            long startTime = java.lang.System.currentTimeMillis();
            InetAddress address = InetAddress.getByName(host);
            boolean reachable = address.isReachable(5000);
            long endTime = java.lang.System.currentTimeMillis();

            if (reachable) {
                return endTime - startTime;
            }
        } catch (Exception e) {
            LoggingHelper.d(TAG, "Ping failed: " + e.getMessage());
        }
        return -1;
    }

    /**
     * Measure ping to gateway.
     *
     * @return Latency in milliseconds, or -1 if failed
     */
    public long measureGatewayPing() {
        try {
            org.csploit.android.net.Network network = org.csploit.android.core.System.getNetwork();
            if (network != null && network.getGatewayAddress() != null) {
                return measurePing(network.getGatewayAddress().getHostAddress());
            }
        } catch (Exception e) {
            LoggingHelper.d(TAG, "Gateway ping failed: " + e.getMessage());
        }
        return -1;
    }

    /**
     * Get total bytes received since device boot.
     *
     * @return Total received bytes
     */
    public long getTotalRxBytes() {
        return TrafficStats.getTotalRxBytes();
    }

    /**
     * Get total bytes transmitted since device boot.
     *
     * @return Total transmitted bytes
     */
    public long getTotalTxBytes() {
        return TrafficStats.getTotalTxBytes();
    }

    /**
     * Get the current network link speed (WiFi only).
     *
     * @return Link speed in Mbps, or -1 if not available
     */
    public int getLinkSpeed() {
        Context ctx = mContext.get();
        if (ctx == null) {
            return -1;
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm != null) {
                Network network = cm.getActiveNetwork();
                if (network != null) {
                    NetworkCapabilities caps = cm.getNetworkCapabilities(network);
                    if (caps != null) {
                        return caps.getLinkDownstreamBandwidthKbps() / 1000;
                    }
                }
            }
        }
        return -1;
    }

    /**
     * Assess current network quality based on speed and latency.
     *
     * @return NetworkQuality assessment
     */
    public NetworkQuality assessNetworkQuality() {
        long ping = measureGatewayPing();
        long speed = Math.max(mDownloadSpeed, mUploadSpeed);

        if (ping < 0) {
            return NetworkQuality.UNKNOWN;
        }

        // Convert to Mbps for comparison
        double speedMbps = speed / (1024.0 * 1024.0) * 8;

        if (speedMbps > 10 && ping < 50) {
            return NetworkQuality.EXCELLENT;
        } else if (speedMbps > 2 && ping < 100) {
            return NetworkQuality.GOOD;
        } else if (speedMbps > 0.5 && ping < 200) {
            return NetworkQuality.FAIR;
        } else {
            return NetworkQuality.POOR;
        }
    }

    /**
     * Run a basic speed test.
     *
     * @param callback Callback with results
     */
    public void runSpeedTest(SpeedTestCallback callback) {
        ThreadHelper.executeBackground(() -> {
            long ping = measureGatewayPing();
            long downloadSpeed = measureDownloadSpeed();
            long uploadSpeed = mUploadSpeed; // Use current upload speed as estimate

            NetworkQuality quality = NetworkQuality.UNKNOWN;
            if (ping >= 0 && downloadSpeed >= 0) {
                double speedMbps = downloadSpeed / (1024.0 * 1024.0) * 8;
                if (speedMbps > 10 && ping < 50) {
                    quality = NetworkQuality.EXCELLENT;
                } else if (speedMbps > 2 && ping < 100) {
                    quality = NetworkQuality.GOOD;
                } else if (speedMbps > 0.5 && ping < 200) {
                    quality = NetworkQuality.FAIR;
                } else {
                    quality = NetworkQuality.POOR;
                }
            }

            SpeedTestResult result = new SpeedTestResult(downloadSpeed, uploadSpeed, ping, quality);

            if (callback != null) {
                ThreadHelper.runOnMainThread(() -> callback.onResult(result));
            }
        });
    }

    private long measureDownloadSpeed() {
        // Simple download speed test using a small file
        try {
            // Use current speed if monitoring is active
            if (mMonitoring.get() && mDownloadSpeed > 0) {
                return mDownloadSpeed;
            }

            // Otherwise, attempt a quick measurement
            long startBytes = TrafficStats.getTotalRxBytes();
            long startTime = java.lang.System.currentTimeMillis();

            // Wait a bit for traffic to accumulate
            Thread.sleep(2000);

            long endBytes = TrafficStats.getTotalRxBytes();
            long endTime = java.lang.System.currentTimeMillis();

            long timeDelta = endTime - startTime;
            long bytesDelta = endBytes - startBytes;

            if (timeDelta > 0) {
                return (bytesDelta * 1000) / timeDelta;
            }
        } catch (Exception e) {
            LoggingHelper.d(TAG, "Download speed measurement failed: " + e.getMessage());
        }
        return mDownloadSpeed;
    }

    /**
     * Callback for speed test results.
     */
    public interface SpeedTestCallback {
        void onResult(SpeedTestResult result);
    }

    /**
     * Format bytes per second to human-readable string.
     *
     * @param bytesPerSecond Speed in bytes per second
     * @return Formatted string (e.g., "5.2 Mbps")
     */
    public static String formatSpeed(long bytesPerSecond) {
        double bitsPerSecond = bytesPerSecond * 8;

        if (bitsPerSecond >= 1_000_000_000) {
            return String.format("%.1f Gbps", bitsPerSecond / 1_000_000_000);
        } else if (bitsPerSecond >= 1_000_000) {
            return String.format("%.1f Mbps", bitsPerSecond / 1_000_000);
        } else if (bitsPerSecond >= 1_000) {
            return String.format("%.1f Kbps", bitsPerSecond / 1_000);
        } else {
            return String.format("%.0f bps", bitsPerSecond);
        }
    }

    /**
     * Format bytes to human-readable string.
     *
     * @param bytes Number of bytes
     * @return Formatted string (e.g., "5.2 MB")
     */
    public static String formatBytes(long bytes) {
        if (bytes >= 1_000_000_000) {
            return String.format("%.1f GB", bytes / 1_000_000_000.0);
        } else if (bytes >= 1_000_000) {
            return String.format("%.1f MB", bytes / 1_000_000.0);
        } else if (bytes >= 1_000) {
            return String.format("%.1f KB", bytes / 1_000.0);
        } else {
            return bytes + " B";
        }
    }

    /**
     * Get a summary of network statistics.
     *
     * @return Human-readable network stats summary
     */
    public String getStatsSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("Download: ").append(getDownloadSpeedFormatted()).append("\n");
        sb.append("Upload: ").append(getUploadSpeedFormatted()).append("\n");
        sb.append("Total Rx: ").append(formatBytes(getTotalRxBytes())).append("\n");
        sb.append("Total Tx: ").append(formatBytes(getTotalTxBytes())).append("\n");
        sb.append("Link Speed: ");
        int linkSpeed = getLinkSpeed();
        if (linkSpeed > 0) {
            sb.append(linkSpeed).append(" Mbps\n");
        } else {
            sb.append("Unknown\n");
        }
        sb.append("Quality: ").append(assessNetworkQuality());
        return sb.toString();
    }
}
