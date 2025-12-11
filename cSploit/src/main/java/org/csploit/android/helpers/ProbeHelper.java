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

import android.os.Handler;
import org.csploit.android.helpers.LoggingHelper;
import android.os.Looper;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * ProbeHelper - Fast network probing utilities for quick host/port discovery.
 * 
 * Provides methods for:
 * - TCP connect probes
 * - Concurrent port probing
 * - Host reachability checks
 * - Quick service availability checks
 * - Latency measurements
 * 
 * This is a lightweight alternative to nmap for quick checks.
 * 
 * Usage:
 * {@code
 * // Quick port check
 * boolean open = ProbeHelper.isPortOpen("192.168.1.1", 80, 1000);
 * 
 * // Probe multiple ports
 * ProbeHelper.probePortsAsync("192.168.1.1", new int[]{22, 80, 443}, result -> {
 *     for (PortResult pr : result.getResults()) {
 *         Log.d(TAG, "Port " + pr.port + ": " + (pr.open ? "OPEN" : "closed"));
 *     }
 * });
 * }
 */
public final class ProbeHelper {
    
    public static final String TAG = "ProbeHelper";
    
    private static final int DEFAULT_TIMEOUT_MS = 2000;
    private static final int PROBE_THREAD_POOL_SIZE = 20;
    
    private static final ExecutorService executor = 
            Executors.newFixedThreadPool(PROBE_THREAD_POOL_SIZE);
    private static final Handler mainHandler = new Handler(Looper.getMainLooper());
    
    // Common ports for quick scans
    public static final int[] COMMON_PORTS = {
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
        993, 995, 1723, 3306, 3389, 5900, 8080, 8443
    };
    
    public static final int[] WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888};
    public static final int[] DATABASE_PORTS = {1433, 1521, 3306, 5432, 6379, 27017};
    public static final int[] REMOTE_ACCESS_PORTS = {22, 23, 3389, 5900, 5901};
    
    private ProbeHelper() {}
    
    /**
     * Result of a single port probe.
     */
    public static class PortResult {
        public final String host;
        public final int port;
        public final boolean open;
        public final long latencyMs;
        public final String error;
        
        public PortResult(String host, int port, boolean open, long latencyMs, String error) {
            this.host = host;
            this.port = port;
            this.open = open;
            this.latencyMs = latencyMs;
            this.error = error;
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("Port %d: %s (%dms)", port, open ? "OPEN" : "closed", latencyMs);
        }
    }
    
    /**
     * Result of a multi-port probe.
     */
    public static class ProbeResult {
        public final String host;
        public final List<PortResult> results;
        public final int openCount;
        public final int closedCount;
        public final long totalTimeMs;
        
        public ProbeResult(String host, List<PortResult> results, long totalTimeMs) {
            this.host = host;
            this.results = results;
            this.totalTimeMs = totalTimeMs;
            
            int open = 0;
            for (PortResult r : results) {
                if (r.open) open++;
            }
            this.openCount = open;
            this.closedCount = results.size() - open;
        }
        
        public List<PortResult> getOpenPorts() {
            List<PortResult> open = new ArrayList<>();
            for (PortResult r : results) {
                if (r.open) open.add(r);
            }
            return open;
        }
        
        public List<PortResult> getResults() {
            return results;
        }
        
        public boolean hasOpenPorts() {
            return openCount > 0;
        }
    }
    
    /**
     * Callback for async probe operations.
     */
    public interface ProbeCallback {
        void onComplete(ProbeResult result);
    }
    
    /**
     * Callback for single port probe.
     */
    public interface SinglePortCallback {
        void onComplete(PortResult result);
    }
    
    /**
     * Check if a TCP port is open on a host.
     * 
     * @param host hostname or IP address
     * @param port port number
     * @param timeoutMs timeout in milliseconds
     * @return true if port is open
     */
    public static boolean isPortOpen(@NonNull String host, int port, int timeoutMs) {
        PortResult result = probePort(host, port, timeoutMs);
        return result.open;
    }
    
    /**
     * Check if a TCP port is open with default timeout.
     * 
     * @param host hostname or IP address
     * @param port port number
     * @return true if port is open
     */
    public static boolean isPortOpen(@NonNull String host, int port) {
        return isPortOpen(host, port, DEFAULT_TIMEOUT_MS);
    }
    
    /**
     * Probe a single port and get detailed result.
     * 
     * @param host hostname or IP address
     * @param port port number
     * @param timeoutMs timeout in milliseconds
     * @return probe result
     */
    @NonNull
    public static PortResult probePort(@NonNull String host, int port, int timeoutMs) {
        long start = System.currentTimeMillis();
        
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            long latency = System.currentTimeMillis() - start;
            return new PortResult(host, port, true, latency, null);
        } catch (IOException e) {
            long latency = System.currentTimeMillis() - start;
            return new PortResult(host, port, false, latency, e.getMessage());
        }
    }
    
    /**
     * Probe a single port asynchronously.
     * 
     * @param host hostname or IP address
     * @param port port number
     * @param timeoutMs timeout in milliseconds
     * @param callback result callback (on main thread)
     */
    public static void probePortAsync(@NonNull String host, int port, int timeoutMs, 
                                      @NonNull SinglePortCallback callback) {
        executor.execute(() -> {
            PortResult result = probePort(host, port, timeoutMs);
            mainHandler.post(() -> callback.onComplete(result));
        });
    }
    
    /**
     * Probe multiple ports on a host concurrently.
     * 
     * @param host hostname or IP address
     * @param ports array of port numbers
     * @param timeoutMs timeout per port in milliseconds
     * @return probe result with all port statuses
     */
    @NonNull
    public static ProbeResult probePorts(@NonNull String host, @NonNull int[] ports, int timeoutMs) {
        long startTime = System.currentTimeMillis();
        List<Future<PortResult>> futures = new ArrayList<>();
        
        // Submit all probes concurrently
        for (int port : ports) {
            Future<PortResult> future = executor.submit(() -> probePort(host, port, timeoutMs));
            futures.add(future);
        }
        
        // Collect results
        List<PortResult> results = new ArrayList<>();
        for (Future<PortResult> future : futures) {
            try {
                results.add(future.get(timeoutMs + 1000, TimeUnit.MILLISECONDS));
            } catch (Exception e) {
                // Future timed out or failed
                LoggingHelper.w(TAG, "Probe future failed: " + e.getMessage());
            }
        }
        
        long totalTime = System.currentTimeMillis() - startTime;
        return new ProbeResult(host, results, totalTime);
    }
    
    /**
     * Probe multiple ports asynchronously.
     * 
     * @param host hostname or IP address
     * @param ports array of port numbers
     * @param timeoutMs timeout per port
     * @param callback result callback (on main thread)
     */
    public static void probePortsAsync(@NonNull String host, @NonNull int[] ports, 
                                       int timeoutMs, @NonNull ProbeCallback callback) {
        executor.execute(() -> {
            ProbeResult result = probePorts(host, ports, timeoutMs);
            mainHandler.post(() -> callback.onComplete(result));
        });
    }
    
    /**
     * Probe common ports on a host.
     * 
     * @param host hostname or IP address
     * @param callback result callback
     */
    public static void probeCommonPorts(@NonNull String host, @NonNull ProbeCallback callback) {
        probePortsAsync(host, COMMON_PORTS, DEFAULT_TIMEOUT_MS, callback);
    }
    
    /**
     * Probe web-related ports.
     * 
     * @param host hostname or IP address
     * @param callback result callback
     */
    public static void probeWebPorts(@NonNull String host, @NonNull ProbeCallback callback) {
        probePortsAsync(host, WEB_PORTS, DEFAULT_TIMEOUT_MS, callback);
    }
    
    /**
     * Check if host is reachable via ICMP-like check (TCP connect to common ports).
     * 
     * @param host hostname or IP address
     * @param timeoutMs timeout in milliseconds
     * @return true if host responds on any common port
     */
    public static boolean isHostReachable(@NonNull String host, int timeoutMs) {
        // Try a few common ports that are often open
        int[] quickPorts = {80, 443, 22, 7};
        
        for (int port : quickPorts) {
            if (isPortOpen(host, port, timeoutMs / quickPorts.length)) {
                return true;
            }
        }
        
        // Fall back to InetAddress.isReachable
        try {
            InetAddress addr = InetAddress.getByName(host);
            return addr.isReachable(timeoutMs);
        } catch (IOException e) {
            return false;
        }
    }
    
    /**
     * Measure latency to a host by connecting to a specific port.
     * 
     * @param host hostname or IP address
     * @param port port number
     * @param samples number of samples to average
     * @return average latency in milliseconds, or -1 if unreachable
     */
    public static long measureLatency(@NonNull String host, int port, int samples) {
        if (samples <= 0) samples = 3;
        
        long totalLatency = 0;
        int successCount = 0;
        
        for (int i = 0; i < samples; i++) {
            PortResult result = probePort(host, port, DEFAULT_TIMEOUT_MS);
            if (result.open) {
                totalLatency += result.latencyMs;
                successCount++;
            }
        }
        
        return successCount > 0 ? totalLatency / successCount : -1;
    }
    
    /**
     * Check if a web server is running on a host.
     * 
     * @param host hostname or IP address
     * @return true if HTTP (80) or HTTPS (443) is open
     */
    public static boolean hasWebServer(@NonNull String host) {
        return isPortOpen(host, 80, DEFAULT_TIMEOUT_MS) || 
               isPortOpen(host, 443, DEFAULT_TIMEOUT_MS);
    }
    
    /**
     * Check if SSH is running on a host.
     * 
     * @param host hostname or IP address
     * @return true if SSH (22) is open
     */
    public static boolean hasSSH(@NonNull String host) {
        return isPortOpen(host, 22, DEFAULT_TIMEOUT_MS);
    }
    
    /**
     * Check if a database server is running on a host.
     * 
     * @param host hostname or IP address
     * @return true if any database port is open
     */
    public static boolean hasDatabase(@NonNull String host) {
        for (int port : DATABASE_PORTS) {
            if (isPortOpen(host, port, DEFAULT_TIMEOUT_MS)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Scan a port range on a host.
     * 
     * @param host hostname or IP address
     * @param startPort start of range
     * @param endPort end of range (inclusive)
     * @param callback result callback
     */
    public static void scanPortRange(@NonNull String host, int startPort, int endPort,
                                     @NonNull ProbeCallback callback) {
        if (startPort > endPort || startPort < 1 || endPort > 65535) {
            throw new IllegalArgumentException("Invalid port range");
        }
        
        int[] ports = new int[endPort - startPort + 1];
        for (int i = 0; i < ports.length; i++) {
            ports[i] = startPort + i;
        }
        
        probePortsAsync(host, ports, DEFAULT_TIMEOUT_MS / 2, callback);
    }
    
    /**
     * Quick service detection based on port banner.
     * This is a simplified version - full banner grabbing requires more time.
     * 
     * @param host hostname or IP address
     * @param port port number
     * @return detected service name or null
     */
    @Nullable
    public static String guessService(int port) {
        switch (port) {
            case 21: return "FTP";
            case 22: return "SSH";
            case 23: return "Telnet";
            case 25: return "SMTP";
            case 53: return "DNS";
            case 80: return "HTTP";
            case 110: return "POP3";
            case 111: return "RPC";
            case 135: return "MSRPC";
            case 139: return "NetBIOS";
            case 143: return "IMAP";
            case 443: return "HTTPS";
            case 445: return "SMB";
            case 993: return "IMAPS";
            case 995: return "POP3S";
            case 1433: return "MSSQL";
            case 1521: return "Oracle";
            case 1723: return "PPTP";
            case 3306: return "MySQL";
            case 3389: return "RDP";
            case 5432: return "PostgreSQL";
            case 5900: return "VNC";
            case 6379: return "Redis";
            case 8080: return "HTTP-Proxy";
            case 8443: return "HTTPS-Alt";
            case 27017: return "MongoDB";
            default: return null;
        }
    }
    
    /**
     * Shutdown the probe executor service.
     */
    public static void shutdown() {
        executor.shutdownNow();
    }
}
