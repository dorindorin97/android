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

import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * HostDiscoveryHelper - Network host discovery and liveness detection.
 *
 * Provides:
 * - ICMP ping sweeps
 * - TCP connect scans
 * - ARP cache reading
 * - Multi-threaded host discovery
 * - Subnet scanning
 *
 * Usage:
 * {@code
 * // Quick ping check
 * boolean alive = HostDiscoveryHelper.isHostAlive("192.168.1.1");
 *
 * // Discover hosts in subnet
 * List<DiscoveredHost> hosts = HostDiscoveryHelper.discoverSubnet("192.168.1.0/24");
 *
 * // TCP port probe
 * boolean open = HostDiscoveryHelper.tcpProbe("192.168.1.1", 80, 1000);
 * }
 */
public final class HostDiscoveryHelper {

    private static final String TAG = "HostDiscoveryHelper";
    private static final int DEFAULT_TIMEOUT = 2000;
    private static final int THREAD_POOL_SIZE = 50;

    /**
     * Discovered host information.
     */
    public static class DiscoveredHost {
        public String ipAddress;
        public String hostname;
        public String macAddress;
        public long latencyMs;
        public boolean isAlive;
        public List<Integer> openPorts = new ArrayList<>();
        public String discoveryMethod;

        @NonNull
        @Override
        public String toString() {
            return String.format("Host{ip='%s', hostname='%s', mac='%s', alive=%b, latency=%dms}",
                    ipAddress, hostname, macAddress, isAlive, latencyMs);
        }
    }

    /**
     * Discovery progress callback.
     */
    public interface DiscoveryCallback {
        void onHostDiscovered(DiscoveredHost host);
        void onProgress(int current, int total);
        void onComplete(List<DiscoveredHost> allHosts);
        void onError(String error);
    }

    private HostDiscoveryHelper() {}

    /**
     * Check if a host is alive using ICMP ping.
     */
    public static boolean isHostAlive(@NonNull String host) {
        return isHostAlive(host, DEFAULT_TIMEOUT);
    }

    /**
     * Check if a host is alive with custom timeout.
     */
    public static boolean isHostAlive(@NonNull String host, int timeoutMs) {
        try {
            InetAddress address = InetAddress.getByName(host);
            return address.isReachable(timeoutMs);
        } catch (Exception e) {
            Log.d(TAG, "Host reachability check failed for " + host, e);
            return false;
        }
    }

    /**
     * TCP probe to check if a port is open.
     */
    public static boolean tcpProbe(@NonNull String host, int port, int timeoutMs) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Multi-port TCP probe.
     */
    @NonNull
    public static List<Integer> tcpProbeMultiple(@NonNull String host, @NonNull int[] ports, int timeoutMs) {
        List<Integer> openPorts = new ArrayList<>();
        for (int port : ports) {
            if (tcpProbe(host, port, timeoutMs)) {
                openPorts.add(port);
            }
        }
        return openPorts;
    }

    /**
     * Get host latency in milliseconds.
     */
    public static long getLatency(@NonNull String host) {
        return getLatency(host, DEFAULT_TIMEOUT);
    }

    /**
     * Get host latency with custom timeout.
     */
    public static long getLatency(@NonNull String host, int timeoutMs) {
        long startTime = System.currentTimeMillis();
        try {
            InetAddress address = InetAddress.getByName(host);
            if (address.isReachable(timeoutMs)) {
                return System.currentTimeMillis() - startTime;
            }
        } catch (Exception e) {
            Log.d(TAG, "Latency check failed for " + host, e);
        }
        return -1;
    }

    /**
     * Discover a single host with detailed information.
     */
    @NonNull
    public static DiscoveredHost discoverHost(@NonNull String host) {
        DiscoveredHost result = new DiscoveredHost();
        result.ipAddress = host;

        long startTime = System.currentTimeMillis();

        // Check if alive
        result.isAlive = isHostAlive(host);
        if (result.isAlive) {
            result.latencyMs = System.currentTimeMillis() - startTime;
            result.discoveryMethod = "ICMP";
        } else {
            // Try TCP probe on common ports
            int[] commonPorts = {80, 443, 22, 21, 25, 3389};
            for (int port : commonPorts) {
                if (tcpProbe(host, port, 500)) {
                    result.isAlive = true;
                    result.openPorts.add(port);
                    result.discoveryMethod = "TCP";
                    result.latencyMs = System.currentTimeMillis() - startTime;
                    break;
                }
            }
        }

        // Try to get hostname
        if (result.isAlive) {
            try {
                InetAddress address = InetAddress.getByName(host);
                String hostname = address.getHostName();
                if (!hostname.equals(host)) {
                    result.hostname = hostname;
                }
            } catch (Exception e) {
                Log.d(TAG, "Failed to resolve hostname for " + host, e);
            }
        }

        // Try to get MAC from ARP cache
        result.macAddress = getMacFromArpCache(host);

        return result;
    }

    /**
     * Discover hosts in a subnet (e.g., "192.168.1.0/24").
     */
    @NonNull
    public static List<DiscoveredHost> discoverSubnet(@NonNull String cidr) {
        return discoverSubnet(cidr, null);
    }

    /**
     * Discover hosts in a subnet with callback.
     */
    @NonNull
    public static List<DiscoveredHost> discoverSubnet(@NonNull String cidr, @Nullable DiscoveryCallback callback) {
        List<DiscoveredHost> hosts = new ArrayList<>();
        List<String> ips = expandCidr(cidr);

        if (ips.isEmpty()) {
            if (callback != null) {
                callback.onError("Invalid CIDR notation: " + cidr);
            }
            return hosts;
        }

        ExecutorService executor = Executors.newFixedThreadPool(THREAD_POOL_SIZE);
        Map<String, Future<DiscoveredHost>> futures = new ConcurrentHashMap<>();
        AtomicInteger completed = new AtomicInteger(0);
        int total = ips.size();

        for (String ip : ips) {
            Future<DiscoveredHost> future = executor.submit(() -> discoverHost(ip));
            futures.put(ip, future);
        }

        for (Map.Entry<String, Future<DiscoveredHost>> entry : futures.entrySet()) {
            try {
                DiscoveredHost host = entry.getValue().get(10, TimeUnit.SECONDS);
                if (host.isAlive) {
                    hosts.add(host);
                    if (callback != null) {
                        callback.onHostDiscovered(host);
                    }
                }
                int current = completed.incrementAndGet();
                if (callback != null) {
                    callback.onProgress(current, total);
                }
            } catch (Exception e) {
                Log.d(TAG, "Failed to discover host " + entry.getKey(), e);
            }
        }

        executor.shutdown();

        if (callback != null) {
            callback.onComplete(hosts);
        }

        return hosts;
    }

    /**
     * Expand CIDR notation to list of IP addresses.
     */
    @NonNull
    public static List<String> expandCidr(@NonNull String cidr) {
        List<String> ips = new ArrayList<>();

        try {
            String[] parts = cidr.split("/");
            if (parts.length != 2) {
                return ips;
            }

            String baseIp = parts[0];
            int prefixLength = Integer.parseInt(parts[1]);

            if (prefixLength < 0 || prefixLength > 32) {
                return ips;
            }

            String[] octets = baseIp.split("\\.");
            if (octets.length != 4) {
                return ips;
            }

            long baseAddr = 0;
            for (int i = 0; i < 4; i++) {
                baseAddr = (baseAddr << 8) | Integer.parseInt(octets[i]);
            }

            int hostBits = 32 - prefixLength;
            long hostCount = 1L << hostBits;
            long networkMask = ~((1L << hostBits) - 1) & 0xFFFFFFFFL;
            long networkAddr = baseAddr & networkMask;

            // Skip network and broadcast addresses for /24 and smaller
            long start = (hostCount > 2) ? 1 : 0;
            long end = (hostCount > 2) ? hostCount - 1 : hostCount;

            for (long i = start; i < end && i < 256; i++) {
                long addr = networkAddr | i;
                String ip = String.format("%d.%d.%d.%d",
                        (addr >> 24) & 0xFF,
                        (addr >> 16) & 0xFF,
                        (addr >> 8) & 0xFF,
                        addr & 0xFF);
                ips.add(ip);
            }

        } catch (Exception e) {
            Log.e(TAG, "Failed to expand CIDR: " + cidr, e);
        }

        return ips;
    }

    /**
     * Read ARP cache and return all entries.
     */
    @NonNull
    public static List<DiscoveredHost> readArpCache() {
        List<DiscoveredHost> hosts = new ArrayList<>();

        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/net/arp"))) {
            String line;
            boolean isFirstLine = true;

            while ((line = reader.readLine()) != null) {
                if (isFirstLine) {
                    isFirstLine = false;
                    continue; // Skip header
                }

                String[] parts = line.split("\\s+");
                if (parts.length >= 4) {
                    String ip = parts[0];
                    String mac = parts[3];

                    if (!"00:00:00:00:00:00".equals(mac)) {
                        DiscoveredHost host = new DiscoveredHost();
                        host.ipAddress = ip;
                        host.macAddress = mac;
                        host.isAlive = true;
                        host.discoveryMethod = "ARP";
                        hosts.add(host);
                    }
                }
            }
        } catch (IOException e) {
            Log.e(TAG, "Failed to read ARP cache", e);
        }

        return hosts;
    }

    /**
     * Get MAC address from ARP cache for a specific IP.
     */
    @Nullable
    public static String getMacFromArpCache(@NonNull String ip) {
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/net/arp"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split("\\s+");
                if (parts.length >= 4 && parts[0].equals(ip)) {
                    String mac = parts[3];
                    if (!"00:00:00:00:00:00".equals(mac)) {
                        return mac;
                    }
                }
            }
        } catch (IOException e) {
            Log.d(TAG, "Failed to get MAC from ARP cache for " + ip, e);
        }
        return null;
    }

    /**
     * Quick scan common ports to determine if host is alive.
     */
    @NonNull
    public static List<Integer> quickPortScan(@NonNull String host) {
        int[] ports = {21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080};
        return tcpProbeMultiple(host, ports, 500);
    }

    /**
     * Calculate subnet information.
     */
    @NonNull
    public static SubnetInfo calculateSubnet(@NonNull String cidr) {
        SubnetInfo info = new SubnetInfo();

        try {
            String[] parts = cidr.split("/");
            info.baseAddress = parts[0];
            info.prefixLength = Integer.parseInt(parts[1]);

            int hostBits = 32 - info.prefixLength;
            info.hostCount = (1L << hostBits) - 2; // Exclude network and broadcast
            if (info.hostCount < 0) info.hostCount = 0;

            String[] octets = info.baseAddress.split("\\.");
            long addr = 0;
            for (int i = 0; i < 4; i++) {
                addr = (addr << 8) | Integer.parseInt(octets[i]);
            }

            long mask = ~((1L << hostBits) - 1) & 0xFFFFFFFFL;
            long network = addr & mask;
            long broadcast = network | ((1L << hostBits) - 1);

            info.networkAddress = longToIp(network);
            info.broadcastAddress = longToIp(broadcast);
            info.subnetMask = longToIp(mask);
            info.firstHost = longToIp(network + 1);
            info.lastHost = longToIp(broadcast - 1);

        } catch (Exception e) {
            Log.e(TAG, "Failed to calculate subnet for " + cidr, e);
        }

        return info;
    }

    /**
     * Subnet information.
     */
    public static class SubnetInfo {
        public String baseAddress;
        public int prefixLength;
        public String networkAddress;
        public String broadcastAddress;
        public String subnetMask;
        public String firstHost;
        public String lastHost;
        public long hostCount;

        @NonNull
        @Override
        public String toString() {
            return String.format("Subnet{network='%s', mask='%s', hosts=%d}",
                    networkAddress, subnetMask, hostCount);
        }
    }

    /**
     * Convert long to IP address string.
     */
    @NonNull
    private static String longToIp(long addr) {
        return String.format("%d.%d.%d.%d",
                (addr >> 24) & 0xFF,
                (addr >> 16) & 0xFF,
                (addr >> 8) & 0xFF,
                addr & 0xFF);
    }
}
