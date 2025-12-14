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

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Helper class for quick port and host scanning operations.
 * Provides fast, parallel scanning with customizable timeouts.
 */
public final class QuickScanHelper {

    private static final String TAG = "QuickScanHelper";

    // Common ports for quick scans
    public static final int[] TOP_20_PORTS = {
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
            143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080
    };

    public static final int[] TOP_100_PORTS = {
            7, 9, 13, 21, 22, 23, 25, 26, 37, 53,
            79, 80, 81, 82, 83, 84, 85, 88, 89, 90,
            99, 100, 106, 110, 111, 113, 119, 135, 139, 143,
            144, 179, 199, 211, 212, 220, 254, 255, 256, 259,
            264, 280, 301, 306, 311, 340, 366, 389, 406, 407,
            416, 417, 425, 427, 443, 444, 445, 458, 464, 465,
            481, 497, 500, 512, 513, 514, 515, 524, 541, 543,
            544, 545, 548, 554, 555, 563, 587, 593, 616, 617,
            625, 631, 636, 646, 648, 666, 667, 668, 683, 687,
            691, 700, 705, 711, 714, 720, 722, 726, 749, 765
    };

    public static final int[] WEB_PORTS = {
            80, 443, 8080, 8443, 8000, 8888, 9000, 9090, 3000, 5000
    };

    public static final int[] DATABASE_PORTS = {
            3306, 5432, 1433, 1521, 27017, 6379, 9200, 5984, 7474, 28015
    };

    public static final int[] REMOTE_ACCESS_PORTS = {
            22, 23, 3389, 5900, 5901, 5902, 5903, 5904, 5905
    };

    // Default settings
    private static final int DEFAULT_TIMEOUT_MS = 1000;
    private static final int DEFAULT_THREAD_COUNT = 50;

    /**
     * Result of a port scan.
     */
    public static class PortScanResult {
        public final String host;
        public final int port;
        public final boolean open;
        public final long latencyMs;
        public final String service;

        public PortScanResult(String host, int port, boolean open, long latencyMs) {
            this.host = host;
            this.port = port;
            this.open = open;
            this.latencyMs = latencyMs;
            this.service = getServiceName(port);
        }

        @NonNull
        @Override
        public String toString() {
            return String.format("%s:%d - %s (%s) [%dms]",
                    host, port, open ? "OPEN" : "CLOSED", service, latencyMs);
        }
    }

    /**
     * Result of a host scan.
     */
    public static class HostScanResult {
        public final String host;
        public final boolean alive;
        public final long latencyMs;
        public final List<Integer> openPorts;

        public HostScanResult(String host, boolean alive, long latencyMs, List<Integer> openPorts) {
            this.host = host;
            this.alive = alive;
            this.latencyMs = latencyMs;
            this.openPorts = openPorts != null ? openPorts : new ArrayList<>();
        }

        @NonNull
        @Override
        public String toString() {
            return String.format("%s - %s [%dms] - %d open ports",
                    host, alive ? "ALIVE" : "DOWN", latencyMs, openPorts.size());
        }
    }

    /**
     * Callback for scan progress.
     */
    public interface ScanCallback {
        void onProgress(int current, int total);
        void onResult(PortScanResult result);
        void onComplete(List<PortScanResult> results);
        void onError(String error);
    }

    /**
     * Callback for host scan progress.
     */
    public interface HostScanCallback {
        void onProgress(int current, int total);
        void onHostFound(HostScanResult result);
        void onComplete(List<HostScanResult> results);
        void onError(String error);
    }

    private QuickScanHelper() {
        // Prevent instantiation
    }

    /**
     * Quick check if a single port is open.
     *
     * @param host Target host
     * @param port Port to check
     * @param timeoutMs Connection timeout
     * @return true if port is open
     */
    public static boolean isPortOpen(@NonNull String host, int port, int timeoutMs) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Quick check if a single port is open with default timeout.
     */
    public static boolean isPortOpen(@NonNull String host, int port) {
        return isPortOpen(host, port, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Scan a single port with timing.
     */
    @NonNull
    public static PortScanResult scanPort(@NonNull String host, int port, int timeoutMs) {
        long start = System.currentTimeMillis();
        boolean open = false;

        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            open = true;
        } catch (IOException e) {
            // Port is closed or filtered
        }

        long latency = System.currentTimeMillis() - start;
        return new PortScanResult(host, port, open, latency);
    }

    /**
     * Scan multiple ports on a host.
     *
     * @param host Target host
     * @param ports Ports to scan
     * @param timeoutMs Connection timeout per port
     * @param threadCount Number of parallel threads
     * @return List of scan results
     */
    @NonNull
    public static List<PortScanResult> scanPorts(@NonNull String host, @NonNull int[] ports,
                                                  int timeoutMs, int threadCount) {
        List<PortScanResult> results = new CopyOnWriteArrayList<>();
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);

        List<Future<?>> futures = new ArrayList<>();
        for (int port : ports) {
            futures.add(executor.submit(() -> {
                PortScanResult result = scanPort(host, port, timeoutMs);
                results.add(result);
            }));
        }

        // Wait for all scans to complete
        for (Future<?> future : futures) {
            try {
                future.get(timeoutMs * 2L, TimeUnit.MILLISECONDS);
            } catch (Exception e) {
                // Ignore timeout/cancellation
            }
        }

        executor.shutdown();
        return new ArrayList<>(results);
    }

    /**
     * Scan multiple ports with default settings.
     */
    @NonNull
    public static List<PortScanResult> scanPorts(@NonNull String host, @NonNull int[] ports) {
        return scanPorts(host, ports, DEFAULT_TIMEOUT_MS, DEFAULT_THREAD_COUNT);
    }

    /**
     * Scan top 20 most common ports.
     */
    @NonNull
    public static List<PortScanResult> scanTop20Ports(@NonNull String host) {
        return scanPorts(host, TOP_20_PORTS);
    }

    /**
     * Scan top 100 most common ports.
     */
    @NonNull
    public static List<PortScanResult> scanTop100Ports(@NonNull String host) {
        return scanPorts(host, TOP_100_PORTS);
    }

    /**
     * Scan web server ports.
     */
    @NonNull
    public static List<PortScanResult> scanWebPorts(@NonNull String host) {
        return scanPorts(host, WEB_PORTS);
    }

    /**
     * Scan database ports.
     */
    @NonNull
    public static List<PortScanResult> scanDatabasePorts(@NonNull String host) {
        return scanPorts(host, DATABASE_PORTS);
    }

    /**
     * Scan remote access ports.
     */
    @NonNull
    public static List<PortScanResult> scanRemoteAccessPorts(@NonNull String host) {
        return scanPorts(host, REMOTE_ACCESS_PORTS);
    }

    /**
     * Scan ports asynchronously with callback.
     */
    public static void scanPortsAsync(@NonNull String host, @NonNull int[] ports,
                                      int timeoutMs, int threadCount,
                                      @NonNull ScanCallback callback) {
        ThreadHelper.executeBackground(() -> {
            List<PortScanResult> results = new CopyOnWriteArrayList<>();
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            AtomicInteger completed = new AtomicInteger(0);
            int total = ports.length;

            List<Future<?>> futures = new ArrayList<>();
            for (int port : ports) {
                futures.add(executor.submit(() -> {
                    try {
                        PortScanResult result = scanPort(host, port, timeoutMs);
                        results.add(result);
                        callback.onResult(result);
                        callback.onProgress(completed.incrementAndGet(), total);
                    } catch (Exception e) {
                        LoggingHelper.debug("Scan error for port " + port + ": " + e.getMessage());
                    }
                }));
            }

            // Wait for completion
            for (Future<?> future : futures) {
                try {
                    future.get(timeoutMs * 2L, TimeUnit.MILLISECONDS);
                } catch (Exception e) {
                    // Ignore
                }
            }

            executor.shutdown();
            callback.onComplete(new ArrayList<>(results));
        });
    }

    /**
     * Scan a port range.
     */
    @NonNull
    public static List<PortScanResult> scanPortRange(@NonNull String host, int startPort,
                                                      int endPort, int timeoutMs, int threadCount) {
        int[] ports = new int[endPort - startPort + 1];
        for (int i = 0; i < ports.length; i++) {
            ports[i] = startPort + i;
        }
        return scanPorts(host, ports, timeoutMs, threadCount);
    }

    /**
     * Get only open ports from scan results.
     */
    @NonNull
    public static List<PortScanResult> getOpenPorts(@NonNull List<PortScanResult> results) {
        List<PortScanResult> openPorts = new ArrayList<>();
        for (PortScanResult result : results) {
            if (result.open) {
                openPorts.add(result);
            }
        }
        return openPorts;
    }

    /**
     * Check if host is alive (responds to ping or has any open ports).
     */
    public static boolean isHostAlive(@NonNull String host, int timeoutMs) {
        try {
            InetAddress addr = InetAddress.getByName(host);
            if (addr.isReachable(timeoutMs)) {
                return true;
            }
        } catch (Exception e) {
            // Ping failed, try port scan
        }

        // Try common ports
        for (int port : new int[]{80, 443, 22, 21}) {
            if (isPortOpen(host, port, timeoutMs / 4)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Scan a subnet for live hosts.
     *
     * @param baseIp Base IP (e.g., "192.168.1")
     * @param startHost Start host number (e.g., 1)
     * @param endHost End host number (e.g., 254)
     * @param timeoutMs Connection timeout
     * @param threadCount Number of parallel threads
     * @return List of live hosts
     */
    @NonNull
    public static List<HostScanResult> scanSubnet(@NonNull String baseIp, int startHost, int endHost,
                                                   int timeoutMs, int threadCount) {
        List<HostScanResult> results = new CopyOnWriteArrayList<>();
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);

        List<Future<?>> futures = new ArrayList<>();
        for (int i = startHost; i <= endHost; i++) {
            final String host = baseIp + "." + i;
            futures.add(executor.submit(() -> {
                long start = System.currentTimeMillis();
                boolean alive = isHostAlive(host, timeoutMs);
                long latency = System.currentTimeMillis() - start;

                if (alive) {
                    // Quick port scan to get open ports
                    List<PortScanResult> portResults = scanPorts(host, TOP_20_PORTS, timeoutMs / 2, 10);
                    List<Integer> openPorts = new ArrayList<>();
                    for (PortScanResult pr : portResults) {
                        if (pr.open) {
                            openPorts.add(pr.port);
                        }
                    }
                    results.add(new HostScanResult(host, true, latency, openPorts));
                }
            }));
        }

        // Wait for completion
        for (Future<?> future : futures) {
            try {
                future.get(timeoutMs * 3L, TimeUnit.MILLISECONDS);
            } catch (Exception e) {
                // Ignore
            }
        }

        executor.shutdown();
        return new ArrayList<>(results);
    }

    /**
     * Scan subnet asynchronously with callback.
     */
    public static void scanSubnetAsync(@NonNull String baseIp, int startHost, int endHost,
                                       int timeoutMs, int threadCount,
                                       @NonNull HostScanCallback callback) {
        ThreadHelper.executeBackground(() -> {
            List<HostScanResult> results = new CopyOnWriteArrayList<>();
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            AtomicInteger completed = new AtomicInteger(0);
            int total = endHost - startHost + 1;

            List<Future<?>> futures = new ArrayList<>();
            for (int i = startHost; i <= endHost; i++) {
                final String host = baseIp + "." + i;
                futures.add(executor.submit(() -> {
                    try {
                        long start = System.currentTimeMillis();
                        boolean alive = isHostAlive(host, timeoutMs);
                        long latency = System.currentTimeMillis() - start;

                        if (alive) {
                            List<PortScanResult> portResults = scanPorts(host, TOP_20_PORTS, timeoutMs / 2, 10);
                            List<Integer> openPorts = new ArrayList<>();
                            for (PortScanResult pr : portResults) {
                                if (pr.open) {
                                    openPorts.add(pr.port);
                                }
                            }
                            HostScanResult result = new HostScanResult(host, true, latency, openPorts);
                            results.add(result);
                            callback.onHostFound(result);
                        }
                        callback.onProgress(completed.incrementAndGet(), total);
                    } catch (Exception e) {
                        LoggingHelper.debug("Scan error for host " + host + ": " + e.getMessage());
                    }
                }));
            }

            // Wait for completion
            for (Future<?> future : futures) {
                try {
                    future.get(timeoutMs * 3L, TimeUnit.MILLISECONDS);
                } catch (Exception e) {
                    // Ignore
                }
            }

            executor.shutdown();
            callback.onComplete(new ArrayList<>(results));
        });
    }

    /**
     * Get service name for a port.
     */
    @NonNull
    public static String getServiceName(int port) {
        switch (port) {
            case 21: return "FTP";
            case 22: return "SSH";
            case 23: return "Telnet";
            case 25: return "SMTP";
            case 53: return "DNS";
            case 80: return "HTTP";
            case 110: return "POP3";
            case 111: return "RPCbind";
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
            case 5901: return "VNC-1";
            case 6379: return "Redis";
            case 8080: return "HTTP-Proxy";
            case 8443: return "HTTPS-Alt";
            case 27017: return "MongoDB";
            default: return "Unknown";
        }
    }

    /**
     * Get ports for a specific service type.
     */
    @NonNull
    public static int[] getServicePorts(@NonNull String serviceType) {
        switch (serviceType.toLowerCase()) {
            case "web":
                return WEB_PORTS;
            case "database":
            case "db":
                return DATABASE_PORTS;
            case "remote":
            case "access":
                return REMOTE_ACCESS_PORTS;
            case "top20":
                return TOP_20_PORTS;
            case "top100":
                return TOP_100_PORTS;
            default:
                return TOP_20_PORTS;
        }
    }
}
