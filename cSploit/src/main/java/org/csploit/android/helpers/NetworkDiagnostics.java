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
import java.io.IOException;
import org.csploit.android.helpers.LoggingHelper;
import java.io.InputStreamReader;
import org.csploit.android.helpers.LoggingHelper;
import java.net.HttpURLConnection;
import org.csploit.android.helpers.LoggingHelper;
import java.net.InetAddress;
import org.csploit.android.helpers.LoggingHelper;
import java.net.URL;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.ExecutorService;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.Executors;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.Future;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.TimeUnit;
import org.csploit.android.helpers.LoggingHelper;
import java.util.regex.Matcher;
import org.csploit.android.helpers.LoggingHelper;
import java.util.regex.Pattern;
import org.csploit.android.helpers.LoggingHelper;

/**
 * NetworkDiagnostics - Network diagnostic and troubleshooting utilities.
 * 
 * Provides methods for:
 * - Ping tests
 * - DNS resolution tests
 * - HTTP connectivity checks
 * - Traceroute (simplified)
 * - Network latency measurements
 * - Connection health monitoring
 * 
 * Usage:
 * {@code
 * // Check internet connectivity
 * NetworkDiagnostics.checkConnectivity(context, new DiagnosticCallback() {
 *     public void onResult(DiagnosticResult result) {
 *         if (result.isSuccess()) {
 *             // Connected
 *         }
 *     }
 * });
 * 
 * // Ping a host
 * PingResult result = NetworkDiagnostics.ping("google.com", 3);
 * }
 */
public final class NetworkDiagnostics {
    
    public static final String TAG = "NetworkDiagnostics";
    
    private static final ExecutorService executor = Executors.newCachedThreadPool();
    private static final Handler mainHandler = new Handler(Looper.getMainLooper());
    
    // Connectivity check URLs
    private static final String[] CONNECTIVITY_URLS = {
            "https://www.google.com/generate_204",
            "https://connectivity.google.com/generate_204",
            "https://www.gstatic.com/generate_204"
    };
    
    private static final int DEFAULT_TIMEOUT_MS = 5000;
    private static final int DEFAULT_PING_COUNT = 4;
    
    private NetworkDiagnostics() {}
    
    /**
     * Diagnostic result callback.
     */
    public interface DiagnosticCallback {
        void onResult(DiagnosticResult result);
    }
    
    /**
     * Generic diagnostic result.
     */
    public static class DiagnosticResult {
        public final boolean success;
        public final String message;
        public final long latencyMs;
        public final String details;
        
        public DiagnosticResult(boolean success, String message, long latencyMs, String details) {
            this.success = success;
            this.message = message;
            this.latencyMs = latencyMs;
            this.details = details;
        }
        
        public boolean isSuccess() {
            return success;
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("DiagnosticResult{success=%s, message='%s', latency=%dms}", 
                    success, message, latencyMs);
        }
    }
    
    /**
     * Ping result data.
     */
    public static class PingResult {
        public final boolean success;
        public final String host;
        public final int packetsSent;
        public final int packetsReceived;
        public final float packetLoss;
        public final float minLatency;
        public final float avgLatency;
        public final float maxLatency;
        public final String rawOutput;
        
        public PingResult(boolean success, String host, int packetsSent, int packetsReceived,
                         float minLatency, float avgLatency, float maxLatency, String rawOutput) {
            this.success = success;
            this.host = host;
            this.packetsSent = packetsSent;
            this.packetsReceived = packetsReceived;
            this.packetLoss = packetsSent > 0 
                    ? ((packetsSent - packetsReceived) * 100.0f / packetsSent) 
                    : 100f;
            this.minLatency = minLatency;
            this.avgLatency = avgLatency;
            this.maxLatency = maxLatency;
            this.rawOutput = rawOutput;
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("PingResult{host='%s', sent=%d, received=%d, loss=%.1f%%, avg=%.1fms}", 
                    host, packetsSent, packetsReceived, packetLoss, avgLatency);
        }
    }
    
    /**
     * Perform a ping test.
     * 
     * @param host hostname or IP to ping
     * @param count number of packets
     * @return ping result
     */
    @NonNull
    public static PingResult ping(@NonNull String host, int count) {
        if (count <= 0) count = DEFAULT_PING_COUNT;
        
        StringBuilder output = new StringBuilder();
        int received = 0;
        float min = Float.MAX_VALUE;
        float max = 0;
        float sum = 0;
        
        try {
            ProcessBuilder pb = new ProcessBuilder("ping", "-c", String.valueOf(count), host);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
            
            String line;
            Pattern timePattern = Pattern.compile("time=([\\d.]+)\\s*ms");
            Pattern statsPattern = Pattern.compile("(\\d+)\\s+packets transmitted.*?(\\d+)\\s+received");
            
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
                
                // Extract time from each ping reply
                Matcher timeMatcher = timePattern.matcher(line);
                if (timeMatcher.find()) {
                    float time = Float.parseFloat(timeMatcher.group(1));
                    received++;
                    sum += time;
                    if (time < min) min = time;
                    if (time > max) max = time;
                }
            }
            
            process.waitFor(30, TimeUnit.SECONDS);
            reader.close();
            
            float avg = received > 0 ? sum / received : 0;
            if (min == Float.MAX_VALUE) min = 0;
            
            return new PingResult(received > 0, host, count, received, min, avg, max, output.toString());
            
        } catch (Exception e) {
            LoggingHelper.e(TAG, "Ping failed", e);
            return new PingResult(false, host, count, 0, 0, 0, 0, "Error: " + e.getMessage());
        }
    }
    
    /**
     * Ping asynchronously with callback.
     * 
     * @param host hostname or IP
     * @param count packet count
     * @param callback result callback
     */
    public static void pingAsync(@NonNull String host, int count, @NonNull DiagnosticCallback callback) {
        executor.execute(() -> {
            PingResult result = ping(host, count);
            DiagnosticResult diagResult = new DiagnosticResult(
                    result.success,
                    result.success ? "Ping successful" : "Ping failed",
                    (long) result.avgLatency,
                    result.rawOutput
            );
            mainHandler.post(() -> callback.onResult(diagResult));
        });
    }
    
    /**
     * Check internet connectivity by connecting to known endpoints.
     * 
     * @param callback result callback
     */
    public static void checkConnectivity(@NonNull DiagnosticCallback callback) {
        executor.execute(() -> {
            for (String urlStr : CONNECTIVITY_URLS) {
                try {
                    long start = System.currentTimeMillis();
                    URL url = new URL(urlStr);
                    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                    conn.setConnectTimeout(DEFAULT_TIMEOUT_MS);
                    conn.setReadTimeout(DEFAULT_TIMEOUT_MS);
                    conn.setRequestMethod("GET");
                    conn.setInstanceFollowRedirects(false);
                    
                    int responseCode = conn.getResponseCode();
                    long latency = System.currentTimeMillis() - start;
                    conn.disconnect();
                    
                    if (responseCode == 204 || responseCode == 200) {
                        DiagnosticResult result = new DiagnosticResult(
                                true,
                                "Internet connected",
                                latency,
                                "Connected via " + urlStr
                        );
                        mainHandler.post(() -> callback.onResult(result));
                        return;
                    }
                } catch (Exception e) {
                    // Try next URL
                    LoggingHelper.d(TAG, "Connectivity check failed for " + urlStr + ": " + e.getMessage());
                }
            }
            
            DiagnosticResult result = new DiagnosticResult(
                    false,
                    "No internet connection",
                    -1,
                    "Failed to reach any connectivity endpoint"
            );
            mainHandler.post(() -> callback.onResult(result));
        });
    }
    
    /**
     * Test DNS resolution.
     * 
     * @param hostname hostname to resolve
     * @return diagnostic result
     */
    @NonNull
    public static DiagnosticResult testDns(@NonNull String hostname) {
        long start = System.currentTimeMillis();
        try {
            InetAddress[] addresses = InetAddress.getAllByName(hostname);
            long latency = System.currentTimeMillis() - start;
            
            StringBuilder details = new StringBuilder();
            details.append("Resolved addresses for ").append(hostname).append(":\n");
            for (InetAddress addr : addresses) {
                details.append("  ").append(addr.getHostAddress()).append("\n");
            }
            
            return new DiagnosticResult(true, "DNS resolution successful", latency, details.toString());
        } catch (Exception e) {
            long latency = System.currentTimeMillis() - start;
            return new DiagnosticResult(false, "DNS resolution failed", latency, e.getMessage());
        }
    }
    
    /**
     * Test DNS resolution asynchronously.
     * 
     * @param hostname hostname to resolve
     * @param callback result callback
     */
    public static void testDnsAsync(@NonNull String hostname, @NonNull DiagnosticCallback callback) {
        executor.execute(() -> {
            DiagnosticResult result = testDns(hostname);
            mainHandler.post(() -> callback.onResult(result));
        });
    }
    
    /**
     * Measure HTTP latency to a URL.
     * 
     * @param urlStr URL to test
     * @return latency in milliseconds, or -1 on failure
     */
    public static long measureHttpLatency(@NonNull String urlStr) {
        try {
            URL url = new URL(urlStr);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(DEFAULT_TIMEOUT_MS);
            conn.setReadTimeout(DEFAULT_TIMEOUT_MS);
            conn.setRequestMethod("HEAD");
            
            long start = System.currentTimeMillis();
            conn.connect();
            int responseCode = conn.getResponseCode();
            long latency = System.currentTimeMillis() - start;
            conn.disconnect();
            
            return responseCode >= 200 && responseCode < 400 ? latency : -1;
        } catch (Exception e) {
            LoggingHelper.d(TAG, "HTTP latency test failed: " + e.getMessage());
            return -1;
        }
    }
    
    /**
     * Check if a host is reachable via TCP.
     * 
     * @param host hostname or IP
     * @param port port number
     * @param timeoutMs timeout in milliseconds
     * @return true if reachable
     */
    public static boolean isPortReachable(@NonNull String host, int port, int timeoutMs) {
        try (java.net.Socket socket = new java.net.Socket()) {
            socket.connect(new java.net.InetSocketAddress(host, port), timeoutMs);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Check common service ports on a host.
     * 
     * @param host hostname or IP
     * @return diagnostic result with port status
     */
    @NonNull
    public static DiagnosticResult checkCommonPorts(@NonNull String host) {
        int[] ports = {22, 80, 443, 21, 23, 25, 53, 110, 143, 3306, 5432, 8080};
        String[] names = {"SSH", "HTTP", "HTTPS", "FTP", "Telnet", "SMTP", "DNS", 
                         "POP3", "IMAP", "MySQL", "PostgreSQL", "HTTP-Alt"};
        
        StringBuilder details = new StringBuilder();
        details.append("Port scan results for ").append(host).append(":\n\n");
        
        int openCount = 0;
        long start = System.currentTimeMillis();
        
        for (int i = 0; i < ports.length; i++) {
            boolean open = isPortReachable(host, ports[i], 1000);
            details.append(String.format("  Port %5d (%s): %s\n", 
                    ports[i], names[i], open ? "OPEN" : "closed"));
            if (open) openCount++;
        }
        
        long duration = System.currentTimeMillis() - start;
        
        return new DiagnosticResult(
                true,
                openCount + " open ports found",
                duration,
                details.toString()
        );
    }
    
    /**
     * Run comprehensive network diagnostics.
     * 
     * @param callback result callback (called multiple times)
     */
    public static void runFullDiagnostics(@NonNull DiagnosticCallback callback) {
        executor.execute(() -> {
            StringBuilder report = new StringBuilder();
            report.append("=== Network Diagnostics Report ===\n\n");
            
            // 1. DNS Test
            report.append("1. DNS Resolution Test\n");
            DiagnosticResult dnsResult = testDns("google.com");
            report.append("   Status: ").append(dnsResult.success ? "PASS" : "FAIL").append("\n");
            report.append("   Latency: ").append(dnsResult.latencyMs).append("ms\n\n");
            
            // 2. Ping Test
            report.append("2. Ping Test (8.8.8.8)\n");
            PingResult pingResult = ping("8.8.8.8", 4);
            report.append("   Status: ").append(pingResult.success ? "PASS" : "FAIL").append("\n");
            report.append("   Packet Loss: ").append(String.format("%.1f%%", pingResult.packetLoss)).append("\n");
            report.append("   Avg Latency: ").append(String.format("%.1fms", pingResult.avgLatency)).append("\n\n");
            
            // 3. HTTP Test
            report.append("3. HTTP Connectivity Test\n");
            long httpLatency = measureHttpLatency("https://www.google.com");
            report.append("   Status: ").append(httpLatency >= 0 ? "PASS" : "FAIL").append("\n");
            if (httpLatency >= 0) {
                report.append("   Latency: ").append(httpLatency).append("ms\n");
            }
            report.append("\n");
            
            // Overall assessment
            boolean allPass = dnsResult.success && pingResult.success && httpLatency >= 0;
            report.append("=== Overall: ").append(allPass ? "HEALTHY" : "ISSUES DETECTED").append(" ===\n");
            
            DiagnosticResult finalResult = new DiagnosticResult(
                    allPass,
                    allPass ? "Network is healthy" : "Network issues detected",
                    pingResult.success ? (long) pingResult.avgLatency : -1,
                    report.toString()
            );
            
            mainHandler.post(() -> callback.onResult(finalResult));
        });
    }
    
    /**
     * Shutdown the executor service.
     * Call this when the app is terminating.
     */
    public static void shutdown() {
        executor.shutdownNow();
    }
}
