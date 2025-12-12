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

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Batch scanning utility for efficient multi-target scanning.
 *
 * Provides:
 * - Parallel host discovery
 * - Batch port scanning
 * - Service version detection
 * - Progress tracking
 * - Cancellation support
 * - Configurable concurrency
 */
public final class BatchScanner {

    private static final String TAG = "BatchScanner";

    // Common service ports
    public static final int[] TOP_20_PORTS = {
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
        143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080
    };

    public static final int[] TOP_100_PORTS = {
        7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106,
        110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427,
        443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587,
        631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029,
        1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121,
        2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
        5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
        6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888,
        9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156
    };

    // Scan result for a single target
    public static class ScanResult {
        public final String host;
        public final boolean alive;
        public final List<PortResult> openPorts;
        public final long scanTimeMs;
        public final String error;

        private ScanResult(String host, boolean alive, List<PortResult> openPorts,
                          long scanTimeMs, String error) {
            this.host = host;
            this.alive = alive;
            this.openPorts = openPorts;
            this.scanTimeMs = scanTimeMs;
            this.error = error;
        }

        public static ScanResult alive(String host, List<PortResult> ports, long timeMs) {
            return new ScanResult(host, true, ports, timeMs, null);
        }

        public static ScanResult dead(String host, long timeMs) {
            return new ScanResult(host, false, new ArrayList<>(), timeMs, null);
        }

        public static ScanResult error(String host, String error) {
            return new ScanResult(host, false, new ArrayList<>(), 0, error);
        }

        public boolean hasOpenPorts() {
            return openPorts != null && !openPorts.isEmpty();
        }

        public String getSummary() {
            StringBuilder sb = new StringBuilder();
            sb.append(host).append(": ");
            if (!alive) {
                sb.append("Down");
            } else if (openPorts.isEmpty()) {
                sb.append("Up (no open ports in scan)");
            } else {
                sb.append("Up, ").append(openPorts.size()).append(" ports open [");
                for (int i = 0; i < Math.min(openPorts.size(), 5); i++) {
                    if (i > 0) sb.append(",");
                    sb.append(openPorts.get(i).port);
                }
                if (openPorts.size() > 5) {
                    sb.append("...");
                }
                sb.append("]");
            }
            return sb.toString();
        }
    }

    // Port scan result
    public static class PortResult {
        public final int port;
        public final boolean open;
        public final String service;
        public final String banner;
        public final long responseTimeMs;

        public PortResult(int port, boolean open, String service, String banner, long responseTimeMs) {
            this.port = port;
            this.open = open;
            this.service = service;
            this.banner = banner;
            this.responseTimeMs = responseTimeMs;
        }

        public static PortResult open(int port, long responseTimeMs) {
            String service = DeviceDiscoveryHelper.identifyService(port);
            return new PortResult(port, true, service, null, responseTimeMs);
        }

        public static PortResult closed(int port) {
            return new PortResult(port, false, null, null, 0);
        }
    }

    // Progress callback
    public interface ScanCallback {
        void onProgress(int completed, int total, String currentHost);
        void onHostScanned(ScanResult result);
        void onComplete(List<ScanResult> results);
        void onError(String error);
        void onCancelled();
    }

    // Scan configuration
    public static class ScanConfig {
        public final int threadCount;
        public final int connectTimeoutMs;
        public final int readTimeoutMs;
        public final int[] ports;
        public final boolean hostDiscoveryFirst;
        public final boolean grabBanners;

        private ScanConfig(Builder builder) {
            this.threadCount = builder.threadCount;
            this.connectTimeoutMs = builder.connectTimeoutMs;
            this.readTimeoutMs = builder.readTimeoutMs;
            this.ports = builder.ports;
            this.hostDiscoveryFirst = builder.hostDiscoveryFirst;
            this.grabBanners = builder.grabBanners;
        }

        public static class Builder {
            private int threadCount = 50;
            private int connectTimeoutMs = 1000;
            private int readTimeoutMs = 2000;
            private int[] ports = TOP_20_PORTS;
            private boolean hostDiscoveryFirst = true;
            private boolean grabBanners = false;

            public Builder threads(int count) {
                this.threadCount = Math.max(1, Math.min(count, 256));
                return this;
            }

            public Builder connectTimeout(int ms) {
                this.connectTimeoutMs = ms;
                return this;
            }

            public Builder readTimeout(int ms) {
                this.readTimeoutMs = ms;
                return this;
            }

            public Builder ports(int[] ports) {
                this.ports = ports;
                return this;
            }

            public Builder top20Ports() {
                this.ports = TOP_20_PORTS;
                return this;
            }

            public Builder top100Ports() {
                this.ports = TOP_100_PORTS;
                return this;
            }

            public Builder customPorts(int... ports) {
                this.ports = ports;
                return this;
            }

            public Builder hostDiscoveryFirst(boolean discover) {
                this.hostDiscoveryFirst = discover;
                return this;
            }

            public Builder grabBanners(boolean grab) {
                this.grabBanners = grab;
                return this;
            }

            public ScanConfig build() {
                return new ScanConfig(this);
            }
        }

        public static Builder builder() {
            return new Builder();
        }

        public static ScanConfig fast() {
            return new Builder()
                .threads(100)
                .connectTimeout(500)
                .top20Ports()
                .hostDiscoveryFirst(true)
                .grabBanners(false)
                .build();
        }

        public static ScanConfig thorough() {
            return new Builder()
                .threads(50)
                .connectTimeout(2000)
                .top100Ports()
                .hostDiscoveryFirst(true)
                .grabBanners(true)
                .build();
        }

        public static ScanConfig stealthy() {
            return new Builder()
                .threads(10)
                .connectTimeout(3000)
                .top20Ports()
                .hostDiscoveryFirst(false)
                .grabBanners(false)
                .build();
        }
    }

    // Batch scanner instance
    private final ScanConfig config;
    private final AtomicBoolean cancelled = new AtomicBoolean(false);
    private ExecutorService executor;

    public BatchScanner(ScanConfig config) {
        this.config = config;
    }

    public BatchScanner() {
        this(ScanConfig.fast());
    }

    // ==================== Scanning Methods ====================

    /**
     * Scan a list of hosts
     */
    public void scan(List<String> hosts, ScanCallback callback) {
        if (hosts == null || hosts.isEmpty()) {
            callback.onError("No hosts to scan");
            return;
        }

        cancelled.set(false);
        executor = Executors.newFixedThreadPool(config.threadCount);

        final ConcurrentHashMap<String, ScanResult> results = new ConcurrentHashMap<>();
        final AtomicInteger completed = new AtomicInteger(0);
        final int total = hosts.size();

        List<Future<?>> futures = new ArrayList<>();

        for (String host : hosts) {
            futures.add(executor.submit(() -> {
                if (cancelled.get()) return;

                try {
                    callback.onProgress(completed.get(), total, host);
                    ScanResult result = scanHost(host);
                    results.put(host, result);
                    callback.onHostScanned(result);
                } catch (Exception e) {
                    results.put(host, ScanResult.error(host, e.getMessage()));
                } finally {
                    completed.incrementAndGet();
                }
            }));
        }

        // Wait for completion in background
        ThreadHelper.executeBackground(() -> {
            for (Future<?> future : futures) {
                try {
                    if (cancelled.get()) break;
                    future.get(60, TimeUnit.SECONDS);
                } catch (Exception e) {
                    LoggingHelper.d(TAG, "Scan task error: " + e.getMessage());
                }
            }

            executor.shutdown();

            if (cancelled.get()) {
                callback.onCancelled();
            } else {
                callback.onComplete(new ArrayList<>(results.values()));
            }
        });
    }

    /**
     * Scan a subnet range
     */
    public void scanSubnet(String baseIp, int startHost, int endHost, ScanCallback callback) {
        List<String> hosts = new ArrayList<>();
        for (int i = startHost; i <= endHost; i++) {
            hosts.add(baseIp + "." + i);
        }
        scan(hosts, callback);
    }

    /**
     * Scan a /24 subnet
     */
    public void scanNetwork(String networkIp, ScanCallback callback) {
        String baseIp = networkIp;
        if (networkIp.endsWith(".0")) {
            baseIp = networkIp.substring(0, networkIp.length() - 2);
        } else if (networkIp.split("\\.").length == 4) {
            baseIp = networkIp.substring(0, networkIp.lastIndexOf('.'));
        }
        scanSubnet(baseIp, 1, 254, callback);
    }

    /**
     * Scan a single host
     */
    public ScanResult scanHost(String host) {
        long startTime = System.currentTimeMillis();

        // Host discovery
        boolean alive = true;
        if (config.hostDiscoveryFirst) {
            alive = isHostAlive(host);
            if (!alive) {
                return ScanResult.dead(host, System.currentTimeMillis() - startTime);
            }
        }

        // Port scan
        List<PortResult> openPorts = new ArrayList<>();
        for (int port : config.ports) {
            if (cancelled.get()) break;

            PortResult result = scanPort(host, port);
            if (result.open) {
                openPorts.add(result);
            }
        }

        return ScanResult.alive(host, openPorts, System.currentTimeMillis() - startTime);
    }

    /**
     * Scan a single port
     */
    public PortResult scanPort(String host, int port) {
        Socket socket = null;
        long startTime = System.currentTimeMillis();

        try {
            socket = new Socket();
            socket.connect(new InetSocketAddress(host, port), config.connectTimeoutMs);

            long responseTime = System.currentTimeMillis() - startTime;
            return PortResult.open(port, responseTime);

        } catch (IOException e) {
            return PortResult.closed(port);
        } finally {
            CloseableHelper.close(socket);
        }
    }

    /**
     * Check if host is alive
     */
    public boolean isHostAlive(String host) {
        // Try ICMP
        try {
            InetAddress address = InetAddress.getByName(host);
            if (address.isReachable(config.connectTimeoutMs)) {
                return true;
            }
        } catch (IOException ignored) {}

        // Try common ports
        for (int port : new int[]{80, 443, 22, 445}) {
            if (scanPort(host, port).open) {
                return true;
            }
        }

        return false;
    }

    /**
     * Cancel ongoing scan
     */
    public void cancel() {
        cancelled.set(true);
        if (executor != null) {
            executor.shutdownNow();
        }
    }

    /**
     * Check if scan was cancelled
     */
    public boolean isCancelled() {
        return cancelled.get();
    }

    // ==================== Static Convenience Methods ====================

    /**
     * Quick scan a host with default settings
     */
    public static ScanResult quickScan(String host) {
        BatchScanner scanner = new BatchScanner(ScanConfig.fast());
        return scanner.scanHost(host);
    }

    /**
     * Quick port check
     */
    public static boolean isPortOpen(String host, int port) {
        return isPortOpen(host, port, 1000);
    }

    /**
     * Quick port check with custom timeout
     */
    public static boolean isPortOpen(String host, int port, int timeoutMs) {
        Socket socket = null;
        try {
            socket = new Socket();
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            return true;
        } catch (IOException e) {
            return false;
        } finally {
            CloseableHelper.close(socket);
        }
    }

    /**
     * Scan multiple ports on a single host
     */
    public static List<Integer> findOpenPorts(String host, int[] ports) {
        return findOpenPorts(host, ports, 1000);
    }

    /**
     * Scan multiple ports on a single host with custom timeout
     */
    public static List<Integer> findOpenPorts(String host, int[] ports, int timeoutMs) {
        List<Integer> openPorts = new ArrayList<>();
        ExecutorService executor = Executors.newFixedThreadPool(20);
        Map<Integer, Future<Boolean>> futures = new HashMap<>();

        for (int port : ports) {
            final int p = port;
            futures.put(port, executor.submit(() -> isPortOpen(host, p, timeoutMs)));
        }

        for (Map.Entry<Integer, Future<Boolean>> entry : futures.entrySet()) {
            try {
                if (entry.getValue().get(timeoutMs * 2, TimeUnit.MILLISECONDS)) {
                    openPorts.add(entry.getKey());
                }
            } catch (Exception ignored) {}
        }

        executor.shutdown();
        return openPorts;
    }

    /**
     * Find live hosts in a range
     */
    public static List<String> findLiveHosts(String baseIp, int startHost, int endHost) {
        List<String> liveHosts = new ArrayList<>();
        ExecutorService executor = Executors.newFixedThreadPool(50);
        Map<String, Future<Boolean>> futures = new ConcurrentHashMap<>();

        for (int i = startHost; i <= endHost; i++) {
            final String ip = baseIp + "." + i;
            futures.put(ip, executor.submit(() -> {
                try {
                    return InetAddress.getByName(ip).isReachable(1000) ||
                           isPortOpen(ip, 80, 500) ||
                           isPortOpen(ip, 443, 500);
                } catch (Exception e) {
                    return false;
                }
            }));
        }

        for (Map.Entry<String, Future<Boolean>> entry : futures.entrySet()) {
            try {
                if (entry.getValue().get(5, TimeUnit.SECONDS)) {
                    liveHosts.add(entry.getKey());
                }
            } catch (Exception ignored) {}
        }

        executor.shutdown();
        return liveHosts;
    }

    /**
     * Generate IP range from CIDR notation
     */
    public static List<String> expandCidr(String cidr) {
        List<String> ips = new ArrayList<>();

        if (!cidr.contains("/")) {
            ips.add(cidr);
            return ips;
        }

        try {
            String[] parts = cidr.split("/");
            String baseIp = parts[0];
            int prefixLength = Integer.parseInt(parts[1]);

            if (prefixLength < 16 || prefixLength > 32) {
                // Too large or invalid range
                return ips;
            }

            long ipLong = NetworkHelper.ipToLong(baseIp);
            int hostBits = 32 - prefixLength;
            long numHosts = 1L << hostBits;

            // Limit to reasonable size
            if (numHosts > 65536) {
                numHosts = 65536;
            }

            long networkIp = ipLong & (0xFFFFFFFFL << hostBits);

            for (long i = 1; i < numHosts - 1; i++) { // Skip network and broadcast
                ips.add(NetworkHelper.longToIp(networkIp + i));
            }
        } catch (Exception e) {
            LoggingHelper.e(TAG, "Failed to expand CIDR: " + cidr, e);
        }

        return ips;
    }
}
