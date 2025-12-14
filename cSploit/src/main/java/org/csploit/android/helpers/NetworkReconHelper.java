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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * Network reconnaissance helper for security scanning.
 *
 * Features:
 * - Fast host discovery (ping sweep)
 * - TCP/UDP port scanning
 * - Service detection and banner grabbing
 * - OS fingerprinting hints
 * - Network topology mapping
 * - Vulnerability hints based on open ports
 */
public final class NetworkReconHelper {

    private static final String TAG = "NetworkReconHelper";

    /**
     * Common ports to scan for quick service detection
     */
    public static final int[] COMMON_PORTS = {
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
            1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017
    };

    /**
     * Well-known service mappings
     */
    private static final Map<Integer, String> PORT_SERVICES = new HashMap<>();
    static {
        PORT_SERVICES.put(21, "FTP");
        PORT_SERVICES.put(22, "SSH");
        PORT_SERVICES.put(23, "Telnet");
        PORT_SERVICES.put(25, "SMTP");
        PORT_SERVICES.put(53, "DNS");
        PORT_SERVICES.put(80, "HTTP");
        PORT_SERVICES.put(110, "POP3");
        PORT_SERVICES.put(111, "RPC");
        PORT_SERVICES.put(135, "MSRPC");
        PORT_SERVICES.put(139, "NetBIOS-SSN");
        PORT_SERVICES.put(143, "IMAP");
        PORT_SERVICES.put(443, "HTTPS");
        PORT_SERVICES.put(445, "SMB");
        PORT_SERVICES.put(993, "IMAPS");
        PORT_SERVICES.put(995, "POP3S");
        PORT_SERVICES.put(1433, "MSSQL");
        PORT_SERVICES.put(1521, "Oracle");
        PORT_SERVICES.put(3306, "MySQL");
        PORT_SERVICES.put(3389, "RDP");
        PORT_SERVICES.put(5432, "PostgreSQL");
        PORT_SERVICES.put(5900, "VNC");
        PORT_SERVICES.put(6379, "Redis");
        PORT_SERVICES.put(8080, "HTTP-Proxy");
        PORT_SERVICES.put(8443, "HTTPS-Alt");
        PORT_SERVICES.put(27017, "MongoDB");
    }

    /**
     * Host discovery result
     */
    public static class HostInfo {
        public final String ip;
        public String hostname;
        public String mac;
        public boolean isAlive;
        public long responseTimeMs;
        public List<PortInfo> openPorts = new ArrayList<>();
        public Map<String, String> attributes = new HashMap<>();

        public HostInfo(String ip) {
            this.ip = ip;
        }

        @NonNull
        @Override
        public String toString() {
            return String.format("Host{ip=%s, hostname=%s, alive=%b, ports=%d}",
                    ip, hostname, isAlive, openPorts.size());
        }
    }

    /**
     * Port scan result
     */
    public static class PortInfo {
        public final int port;
        public final String protocol;
        public String service;
        public String banner;
        public String version;
        public PortState state;
        public long responseTimeMs;

        public enum PortState {
            OPEN, CLOSED, FILTERED, UNKNOWN
        }

        public PortInfo(int port, String protocol) {
            this.port = port;
            this.protocol = protocol;
            this.state = PortState.UNKNOWN;
        }

        @NonNull
        @Override
        public String toString() {
            return String.format("%d/%s (%s) %s", port, protocol, state, service != null ? service : "");
        }
    }

    /**
     * Scan progress callback
     */
    public interface ScanProgressListener {
        void onProgress(int current, int total, String currentTarget);
        void onHostFound(HostInfo host);
        void onPortFound(String host, PortInfo port);
        void onComplete(List<HostInfo> results);
        void onError(String message);
    }

    private NetworkReconHelper() {}

    // ===================== Host Discovery =====================

    /**
     * Discover live hosts in a subnet using ICMP ping.
     *
     * @param baseIp Network address (e.g., "192.168.1.0")
     * @param cidr CIDR prefix length (e.g., 24)
     * @param timeoutMs Timeout per host in milliseconds
     * @param listener Progress listener
     * @return List of discovered hosts
     */
    @NonNull
    public static List<HostInfo> discoverHosts(@NonNull String baseIp, int cidr,
                                                int timeoutMs, @Nullable ScanProgressListener listener) {
        List<HostInfo> hosts = Collections.synchronizedList(new ArrayList<>());
        int threads = Math.min(50, Runtime.getRuntime().availableProcessors() * 10);
        ExecutorService executor = Executors.newFixedThreadPool(threads);

        try {
            long networkAddr = IpAddressHelper.ipToLong(baseIp);
            int hostBits = 32 - cidr;
            int totalHosts = (1 << hostBits) - 2; // Exclude network and broadcast

            if (totalHosts <= 0 || totalHosts > 65534) {
                if (listener != null) {
                    listener.onError("Invalid subnet size: " + totalHosts);
                }
                return hosts;
            }

            AtomicInteger progress = new AtomicInteger(0);
            List<Future<?>> futures = new ArrayList<>();

            for (int i = 1; i <= totalHosts; i++) {
                final long targetIp = networkAddr + i;
                final String targetStr = IpAddressHelper.longToIp(targetIp);

                Future<?> future = executor.submit(() -> {
                    HostInfo host = pingHost(targetStr, timeoutMs);
                    int current = progress.incrementAndGet();

                    if (listener != null) {
                        listener.onProgress(current, totalHosts, targetStr);
                    }

                    if (host.isAlive) {
                        hosts.add(host);
                        if (listener != null) {
                            listener.onHostFound(host);
                        }
                    }
                });
                futures.add(future);
            }

            // Wait for completion
            for (Future<?> future : futures) {
                try {
                    future.get(timeoutMs + 1000, TimeUnit.MILLISECONDS);
                } catch (Exception e) {
                    // Continue with other hosts
                }
            }

            if (listener != null) {
                listener.onComplete(hosts);
            }

        } finally {
            executor.shutdown();
            try {
                executor.awaitTermination(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                executor.shutdownNow();
            }
        }

        return hosts;
    }

    /**
     * Ping a single host using Java's InetAddress.isReachable.
     */
    @NonNull
    public static HostInfo pingHost(@NonNull String ip, int timeoutMs) {
        HostInfo host = new HostInfo(ip);
        long start = System.currentTimeMillis();

        try {
            InetAddress addr = InetAddress.getByName(ip);
            host.isAlive = addr.isReachable(timeoutMs);
            host.responseTimeMs = System.currentTimeMillis() - start;

            if (host.isAlive) {
                // Try to get hostname
                String hostname = addr.getCanonicalHostName();
                if (!hostname.equals(ip)) {
                    host.hostname = hostname;
                }
            }
        } catch (Exception e) {
            host.isAlive = false;
        }

        return host;
    }

    /**
     * Fast host discovery using TCP connect to common ports.
     * Faster than ICMP ping when hosts don't respond to ping.
     */
    @NonNull
    public static HostInfo tcpProbeHost(@NonNull String ip, int timeoutMs) {
        HostInfo host = new HostInfo(ip);
        int[] probePorts = {80, 443, 22, 445, 3389};

        for (int port : probePorts) {
            try (Socket socket = new Socket()) {
                long start = System.currentTimeMillis();
                socket.connect(new InetSocketAddress(ip, port), timeoutMs);
                host.isAlive = true;
                host.responseTimeMs = System.currentTimeMillis() - start;
                return host;
            } catch (IOException e) {
                // Try next port
            }
        }

        host.isAlive = false;
        return host;
    }

    // ===================== Port Scanning =====================

    /**
     * Scan ports on a target host.
     *
     * @param host Target IP address
     * @param ports Ports to scan
     * @param timeoutMs Timeout per port
     * @param listener Progress listener
     * @return List of port results
     */
    @NonNull
    public static List<PortInfo> scanPorts(@NonNull String host, @NonNull int[] ports,
                                           int timeoutMs, @Nullable ScanProgressListener listener) {
        List<PortInfo> results = Collections.synchronizedList(new ArrayList<>());
        int threads = Math.min(100, ports.length);
        ExecutorService executor = Executors.newFixedThreadPool(threads);

        try {
            AtomicInteger progress = new AtomicInteger(0);
            List<Future<?>> futures = new ArrayList<>();

            for (int port : ports) {
                Future<?> future = executor.submit(() -> {
                    PortInfo info = scanPort(host, port, timeoutMs);
                    int current = progress.incrementAndGet();

                    if (listener != null) {
                        listener.onProgress(current, ports.length, host + ":" + port);
                    }

                    if (info.state == PortInfo.PortState.OPEN) {
                        results.add(info);
                        if (listener != null) {
                            listener.onPortFound(host, info);
                        }
                    }
                });
                futures.add(future);
            }

            for (Future<?> future : futures) {
                try {
                    future.get(timeoutMs + 500, TimeUnit.MILLISECONDS);
                } catch (Exception e) {
                    // Continue
                }
            }

        } finally {
            executor.shutdown();
        }

        // Sort by port number
        Collections.sort(results, (a, b) -> Integer.compare(a.port, b.port));
        return results;
    }

    /**
     * Scan a single TCP port.
     */
    @NonNull
    public static PortInfo scanPort(@NonNull String host, int port, int timeoutMs) {
        PortInfo info = new PortInfo(port, "tcp");
        info.service = PORT_SERVICES.get(port);

        try (Socket socket = new Socket()) {
            long start = System.currentTimeMillis();
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            info.state = PortInfo.PortState.OPEN;
            info.responseTimeMs = System.currentTimeMillis() - start;

            // Try banner grabbing for certain services
            if (shouldGrabBanner(port)) {
                try {
                    socket.setSoTimeout(timeoutMs);
                    BufferedReader reader = new BufferedReader(
                            new InputStreamReader(socket.getInputStream()));
                    char[] buffer = new char[512];
                    int read = reader.read(buffer);
                    if (read > 0) {
                        info.banner = new String(buffer, 0, read).trim();
                        parseServiceVersion(info);
                    }
                } catch (SocketTimeoutException e) {
                    // No banner available
                }
            }
        } catch (SocketTimeoutException e) {
            info.state = PortInfo.PortState.FILTERED;
        } catch (IOException e) {
            String msg = e.getMessage();
            if (msg != null && msg.contains("refused")) {
                info.state = PortInfo.PortState.CLOSED;
            } else {
                info.state = PortInfo.PortState.FILTERED;
            }
        }

        return info;
    }

    /**
     * Generate a range of ports for scanning.
     */
    @NonNull
    public static int[] portRange(int start, int end) {
        if (start > end) {
            int temp = start;
            start = end;
            end = temp;
        }
        int[] ports = new int[end - start + 1];
        for (int i = 0; i < ports.length; i++) {
            ports[i] = start + i;
        }
        return ports;
    }

    /**
     * Quick scan of common ports.
     */
    @NonNull
    public static List<PortInfo> quickScan(@NonNull String host, int timeoutMs) {
        return scanPorts(host, COMMON_PORTS, timeoutMs, null);
    }

    // ===================== Service Detection =====================

    /**
     * Grab service banner and detect version.
     */
    @Nullable
    public static String grabBanner(@NonNull String host, int port, int timeoutMs) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            socket.setSoTimeout(timeoutMs);

            // For HTTP, send request
            if (port == 80 || port == 8080) {
                socket.getOutputStream().write("HEAD / HTTP/1.0\r\n\r\n".getBytes());
            }

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream()));
            StringBuilder banner = new StringBuilder();
            String line;
            int lines = 0;

            while ((line = reader.readLine()) != null && lines < 10) {
                banner.append(line).append("\n");
                lines++;
            }

            return banner.toString().trim();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Detect service and version from banner.
     */
    public static void parseServiceVersion(@NonNull PortInfo info) {
        if (info.banner == null || info.banner.isEmpty()) {
            return;
        }

        String banner = info.banner.toLowerCase();

        // SSH detection
        if (banner.startsWith("ssh-")) {
            info.service = "SSH";
            String[] parts = info.banner.split(" ");
            if (parts.length > 0) {
                info.version = parts[0];
            }
        }
        // HTTP detection
        else if (banner.contains("http/") || banner.contains("apache") ||
                 banner.contains("nginx") || banner.contains("iis")) {
            info.service = "HTTP";
            if (banner.contains("apache")) {
                int idx = banner.indexOf("apache");
                info.version = extractVersion(banner, idx);
            } else if (banner.contains("nginx")) {
                int idx = banner.indexOf("nginx");
                info.version = extractVersion(banner, idx);
            }
        }
        // FTP detection
        else if (banner.contains("ftp") || banner.contains("220 ")) {
            info.service = "FTP";
            if (banner.contains("vsftpd")) {
                info.version = "vsftpd";
            } else if (banner.contains("proftpd")) {
                info.version = "ProFTPD";
            }
        }
        // SMTP detection
        else if (banner.contains("smtp") || banner.contains("220 ") && banner.contains("mail")) {
            info.service = "SMTP";
            if (banner.contains("postfix")) {
                info.version = "Postfix";
            } else if (banner.contains("exim")) {
                info.version = "Exim";
            }
        }
        // MySQL detection
        else if (banner.contains("mysql")) {
            info.service = "MySQL";
        }
    }

    private static String extractVersion(String text, int startIdx) {
        StringBuilder version = new StringBuilder();
        boolean foundSlash = false;
        for (int i = startIdx; i < text.length() && i < startIdx + 30; i++) {
            char c = text.charAt(i);
            if (c == '/') {
                foundSlash = true;
            } else if (foundSlash) {
                if (Character.isDigit(c) || c == '.') {
                    version.append(c);
                } else if (version.length() > 0) {
                    break;
                }
            }
        }
        return version.length() > 0 ? version.toString() : null;
    }

    private static boolean shouldGrabBanner(int port) {
        return port == 21 || port == 22 || port == 25 || port == 80 ||
               port == 110 || port == 143 || port == 3306 || port == 8080;
    }

    // ===================== Security Analysis =====================

    /**
     * Analyze scan results for potential security issues.
     */
    @NonNull
    public static List<String> analyzeSecurityRisks(@NonNull List<PortInfo> ports) {
        List<String> risks = new ArrayList<>();

        for (PortInfo port : ports) {
            if (port.state != PortInfo.PortState.OPEN) continue;

            switch (port.port) {
                case 21:
                    risks.add("FTP (21) - Unencrypted file transfer, consider SFTP");
                    break;
                case 23:
                    risks.add("Telnet (23) - Critical: Unencrypted remote access, use SSH");
                    break;
                case 135:
                case 139:
                case 445:
                    risks.add("Windows SMB (" + port.port + ") - Potential for MS17-010/EternalBlue");
                    break;
                case 3389:
                    risks.add("RDP (3389) - Exposed remote desktop, enable NLA and strong auth");
                    break;
                case 5900:
                    risks.add("VNC (5900) - Remote desktop exposed, ensure strong password");
                    break;
                case 6379:
                    risks.add("Redis (6379) - NoSQL database, ensure authentication is enabled");
                    break;
                case 27017:
                    risks.add("MongoDB (27017) - NoSQL database, ensure authentication is enabled");
                    break;
                case 1433:
                case 3306:
                case 5432:
                    risks.add("Database (" + port.port + ") - Database exposed, restrict network access");
                    break;
            }

            // Check for outdated versions in banners
            if (port.banner != null) {
                if (port.banner.toLowerCase().contains("openssh") &&
                    port.banner.contains("/5.") || port.banner.contains("/6.")) {
                    risks.add("Outdated SSH version detected: " + port.banner);
                }
            }
        }

        return risks;
    }

    /**
     * Get OS hints based on open ports and TTL.
     */
    @NonNull
    public static String guessOS(@NonNull List<PortInfo> ports) {
        boolean hasSmb = false;
        boolean hasRdp = false;
        boolean hasSsh = false;
        boolean hasApache = false;

        for (PortInfo port : ports) {
            if (port.state != PortInfo.PortState.OPEN) continue;

            switch (port.port) {
                case 135:
                case 139:
                case 445:
                    hasSmb = true;
                    break;
                case 3389:
                    hasRdp = true;
                    break;
                case 22:
                    hasSsh = true;
                    if (port.banner != null && port.banner.toLowerCase().contains("ubuntu")) {
                        return "Linux (Ubuntu)";
                    }
                    break;
                case 80:
                case 443:
                    if (port.banner != null) {
                        if (port.banner.toLowerCase().contains("iis")) {
                            return "Windows Server (IIS)";
                        }
                        if (port.banner.toLowerCase().contains("apache")) {
                            hasApache = true;
                        }
                    }
                    break;
            }
        }

        if (hasRdp || (hasSmb && !hasSsh)) {
            return "Windows";
        }
        if (hasSsh && hasApache) {
            return "Linux";
        }
        if (hasSsh) {
            return "Unix/Linux";
        }

        return "Unknown";
    }
}
