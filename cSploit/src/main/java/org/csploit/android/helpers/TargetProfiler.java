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

import androidx.annotation.NonNull;
import org.csploit.android.helpers.LoggingHelper;
import androidx.annotation.Nullable;
import org.csploit.android.helpers.LoggingHelper;

import java.io.BufferedReader;
import org.csploit.android.helpers.LoggingHelper;
import java.io.InputStreamReader;
import org.csploit.android.helpers.LoggingHelper;
import java.net.HttpURLConnection;
import org.csploit.android.helpers.LoggingHelper;
import java.net.InetAddress;
import org.csploit.android.helpers.LoggingHelper;
import java.net.InetSocketAddress;
import org.csploit.android.helpers.LoggingHelper;
import java.net.Socket;
import org.csploit.android.helpers.LoggingHelper;
import java.net.URL;
import org.csploit.android.helpers.LoggingHelper;
import java.util.ArrayList;
import org.csploit.android.helpers.LoggingHelper;
import java.util.HashMap;
import org.csploit.android.helpers.LoggingHelper;
import java.util.List;
import org.csploit.android.helpers.LoggingHelper;
import java.util.Map;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.Callable;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.ExecutorService;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.Executors;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.Future;
import org.csploit.android.helpers.LoggingHelper;
import java.util.regex.Matcher;
import org.csploit.android.helpers.LoggingHelper;
import java.util.regex.Pattern;
import org.csploit.android.helpers.LoggingHelper;

/**
 * TargetProfiler - Comprehensive target profiling and fingerprinting utilities.
 *
 * Provides:
 * - OS detection/fingerprinting
 * - Service identification
 * - Banner grabbing
 * - HTTP header analysis
 * - Technology detection
 * - Risk assessment
 *
 * Usage:
 * {@code
 * TargetProfile profile = TargetProfiler.profileTarget("192.168.1.1");
 *
 * // Get OS guess
 * String os = profile.osGuess;
 *
 * // Get services
 * List<ServiceInfo> services = profile.services;
 * }
 */
public final class TargetProfiler {

    private static final String TAG = "TargetProfiler";
    private static final int DEFAULT_TIMEOUT = 5000;
    private static final ExecutorService executor = Executors.newFixedThreadPool(10);

    // Common ports for quick profiling
    private static final int[] QUICK_SCAN_PORTS = {
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017
    };

    private TargetProfiler() {}

    /**
     * Target profile container.
     */
    public static class TargetProfile {
        public String ipAddress;
        public String hostname;
        public String macAddress;
        public String osGuess;
        public float osConfidence;
        public List<String> osPossibilities;
        public List<ServiceInfo> services;
        public Map<String, String> httpHeaders;
        public List<String> technologies;
        public List<String> vulnerabilities;
        public DeviceType deviceType;
        public RiskLevel riskLevel;
        public int openPortCount;
        public long profileTimeMs;
        public boolean isAlive;

        public TargetProfile() {
            osPossibilities = new ArrayList<>();
            services = new ArrayList<>();
            httpHeaders = new HashMap<>();
            technologies = new ArrayList<>();
            vulnerabilities = new ArrayList<>();
        }

        @NonNull
        @Override
        public String toString() {
            return String.format("TargetProfile{ip='%s', os='%s', services=%d, risk=%s}",
                    ipAddress, osGuess, services.size(), riskLevel);
        }
    }

    /**
     * Service information.
     */
    public static class ServiceInfo {
        public int port;
        public String protocol;
        public String serviceName;
        public String version;
        public String banner;
        public boolean isSsl;
        public String product;
        public List<String> vulnerabilities;

        public ServiceInfo(int port) {
            this.port = port;
            this.vulnerabilities = new ArrayList<>();
        }

        @NonNull
        @Override
        public String toString() {
            return String.format("Service{port=%d, name='%s', version='%s'}", port, serviceName, version);
        }
    }

    /**
     * Device type classification.
     */
    public enum DeviceType {
        ROUTER,
        SWITCH,
        FIREWALL,
        SERVER,
        WORKSTATION,
        MOBILE,
        IOT,
        PRINTER,
        CAMERA,
        NAS,
        UNKNOWN
    }

    /**
     * Risk level classification.
     */
    public enum RiskLevel {
        CRITICAL,
        HIGH,
        MEDIUM,
        LOW,
        INFO,
        UNKNOWN
    }

    /**
     * Profile a target with quick scan.
     */
    @NonNull
    public static TargetProfile profileTarget(@NonNull String target) {
        return profileTarget(target, QUICK_SCAN_PORTS, DEFAULT_TIMEOUT);
    }

    /**
     * Profile a target with custom ports.
     */
    @NonNull
    public static TargetProfile profileTarget(@NonNull String target, @NonNull int[] ports, int timeoutMs) {
        TargetProfile profile = new TargetProfile();
        profile.ipAddress = target;
        long startTime = java.lang.System.currentTimeMillis();

        // Check if host is alive
        profile.isAlive = isHostAlive(target, timeoutMs);
        if (!profile.isAlive) {
            profile.profileTimeMs = java.lang.System.currentTimeMillis() - startTime;
            return profile;
        }

        // Resolve hostname
        profile.hostname = resolveHostname(target);

        // Scan ports and gather service info
        scanPorts(profile, ports, timeoutMs);

        // Guess OS based on open ports and banners
        guessOperatingSystem(profile);

        // Detect technologies
        detectTechnologies(profile);

        // Classify device type
        profile.deviceType = classifyDevice(profile);

        // Assess risk
        profile.riskLevel = assessRisk(profile);

        profile.profileTimeMs = java.lang.System.currentTimeMillis() - startTime;
        return profile;
    }

    /**
     * Check if host is alive.
     */
    public static boolean isHostAlive(@NonNull String host, int timeoutMs) {
        try {
            InetAddress addr = InetAddress.getByName(host);
            return addr.isReachable(timeoutMs);
        } catch (Exception e) {
            // Try TCP connect to common ports as fallback
            int[] fallbackPorts = {80, 443, 22, 21};
            for (int port : fallbackPorts) {
                if (isPortOpen(host, port, timeoutMs / 4)) {
                    return true;
                }
            }
            return false;
        }
    }

    /**
     * Check if a port is open.
     */
    public static boolean isPortOpen(@NonNull String host, int port, int timeoutMs) {
        Socket socket = null;
        try {
            socket = new Socket();
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            return true;
        } catch (Exception e) {
            return false;
        } finally {
            if (socket != null) {
                try { socket.close(); } catch (Exception e) { /* ignore */ }
            }
        }
    }

    /**
     * Scan ports and gather service info.
     */
    private static void scanPorts(@NonNull TargetProfile profile, @NonNull int[] ports, int timeoutMs) {
        List<Future<ServiceInfo>> futures = new ArrayList<>();

        for (int port : ports) {
            final int p = port;
            futures.add(executor.submit(() -> probePort(profile.ipAddress, p, timeoutMs)));
        }

        for (Future<ServiceInfo> future : futures) {
            try {
                ServiceInfo service = future.get();
                if (service != null) {
                    profile.services.add(service);
                    profile.openPortCount++;
                }
            } catch (Exception e) {
                LoggingHelper.d(TAG, "Port scan error: " + e.getMessage());
            }
        }
    }

    /**
     * Probe a single port and gather service info.
     */
    @Nullable
    private static ServiceInfo probePort(@NonNull String host, int port, int timeoutMs) {
        Socket socket = null;
        try {
            socket = new Socket();
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            socket.setSoTimeout(timeoutMs);

            ServiceInfo service = new ServiceInfo(port);
            service.protocol = "tcp";
            service.serviceName = guessServiceName(port);

            // Grab banner
            try {
                socket.getOutputStream().write("\r\n".getBytes());
                socket.getOutputStream().flush();

                byte[] buffer = new byte[1024];
                int read = socket.getInputStream().read(buffer);
                if (read > 0) {
                    service.banner = new String(buffer, 0, read).trim();
                    parseServiceBanner(service);
                }
            } catch (Exception e) {
                // No banner available
            }

            // Special handling for HTTP/HTTPS
            if (port == 80 || port == 8080) {
                fetchHttpInfo(host, port, service, false);
            } else if (port == 443 || port == 8443) {
                service.isSsl = true;
                fetchHttpInfo(host, port, service, true);
            }

            return service;

        } catch (Exception e) {
            return null;
        } finally {
            if (socket != null) {
                try { socket.close(); } catch (Exception e) { /* ignore */ }
            }
        }
    }

    /**
     * Guess service name from port number.
     */
    @NonNull
    private static String guessServiceName(int port) {
        switch (port) {
            case 21: return "ftp";
            case 22: return "ssh";
            case 23: return "telnet";
            case 25: return "smtp";
            case 53: return "dns";
            case 80: return "http";
            case 110: return "pop3";
            case 111: return "rpcbind";
            case 135: return "msrpc";
            case 139: return "netbios-ssn";
            case 143: return "imap";
            case 443: return "https";
            case 445: return "microsoft-ds";
            case 993: return "imaps";
            case 995: return "pop3s";
            case 1433: return "mssql";
            case 1521: return "oracle";
            case 3306: return "mysql";
            case 3389: return "rdp";
            case 5432: return "postgresql";
            case 5900: return "vnc";
            case 6379: return "redis";
            case 8080: return "http-proxy";
            case 8443: return "https-alt";
            case 27017: return "mongodb";
            default: return "unknown";
        }
    }

    /**
     * Parse service banner for version info.
     */
    private static void parseServiceBanner(@NonNull ServiceInfo service) {
        if (service.banner == null || service.banner.isEmpty()) return;

        String banner = service.banner;

        // SSH version detection
        if (banner.startsWith("SSH-")) {
            service.serviceName = "ssh";
            Matcher m = Pattern.compile("SSH-[\\d.]+-(\\S+)").matcher(banner);
            if (m.find()) {
                service.product = m.group(1);
                if (banner.contains("OpenSSH")) {
                    service.product = "OpenSSH";
                    Matcher ver = Pattern.compile("OpenSSH[_\\s]([\\d.]+)").matcher(banner);
                    if (ver.find()) service.version = ver.group(1);
                }
            }
        }

        // FTP version detection
        if (banner.contains("FTP") || banner.startsWith("220")) {
            service.serviceName = "ftp";
            if (banner.contains("vsFTPd")) {
                service.product = "vsFTPd";
                Matcher ver = Pattern.compile("vsFTPd ([\\d.]+)").matcher(banner);
                if (ver.find()) service.version = ver.group(1);
            } else if (banner.contains("ProFTPD")) {
                service.product = "ProFTPD";
                Matcher ver = Pattern.compile("ProFTPD ([\\d.]+)").matcher(banner);
                if (ver.find()) service.version = ver.group(1);
            }
        }

        // SMTP version detection
        if (banner.contains("SMTP") || banner.contains("ESMTP")) {
            service.serviceName = "smtp";
            if (banner.contains("Postfix")) {
                service.product = "Postfix";
            } else if (banner.contains("Sendmail")) {
                service.product = "Sendmail";
            } else if (banner.contains("Exim")) {
                service.product = "Exim";
            }
        }

        // MySQL detection
        if (service.port == 3306 || banner.contains("mysql")) {
            service.serviceName = "mysql";
            service.product = "MySQL";
        }

        // Redis detection
        if (banner.contains("REDIS") || banner.contains("-ERR")) {
            service.serviceName = "redis";
            service.product = "Redis";
        }
    }

    /**
     * Fetch HTTP/HTTPS information.
     */
    private static void fetchHttpInfo(@NonNull String host, int port, @NonNull ServiceInfo service, boolean ssl) {
        HttpURLConnection conn = null;
        try {
            String protocol = ssl ? "https" : "http";
            URL url = new URL(protocol + "://" + host + ":" + port + "/");
            conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            conn.setRequestMethod("GET");
            conn.setInstanceFollowRedirects(false);

            int code = conn.getResponseCode();
            service.banner = "HTTP/" + code;

            // Extract server header
            String server = conn.getHeaderField("Server");
            if (server != null) {
                service.product = server;
                parseServerHeader(service, server);
            }

            // Check for X-Powered-By
            String poweredBy = conn.getHeaderField("X-Powered-By");
            if (poweredBy != null) {
                service.banner += " [" + poweredBy + "]";
            }

        } catch (Exception e) {
            LoggingHelper.d(TAG, "HTTP probe failed for " + host + ":" + port);
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    /**
     * Parse Server header for product/version.
     */
    private static void parseServerHeader(@NonNull ServiceInfo service, @NonNull String server) {
        if (server.contains("Apache")) {
            Matcher m = Pattern.compile("Apache/([\\d.]+)").matcher(server);
            if (m.find()) service.version = m.group(1);
        } else if (server.contains("nginx")) {
            Matcher m = Pattern.compile("nginx/([\\d.]+)").matcher(server);
            if (m.find()) service.version = m.group(1);
        } else if (server.contains("Microsoft-IIS")) {
            Matcher m = Pattern.compile("Microsoft-IIS/([\\d.]+)").matcher(server);
            if (m.find()) service.version = m.group(1);
        }
    }

    /**
     * Resolve hostname from IP.
     */
    @Nullable
    private static String resolveHostname(@NonNull String ip) {
        try {
            InetAddress addr = InetAddress.getByName(ip);
            String hostname = addr.getCanonicalHostName();
            return hostname.equals(ip) ? null : hostname;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Guess OS based on collected data.
     */
    private static void guessOperatingSystem(@NonNull TargetProfile profile) {
        Map<String, Integer> scores = new HashMap<>();

        for (ServiceInfo service : profile.services) {
            // Windows indicators
            if (service.port == 135 || service.port == 139 || service.port == 445 || service.port == 3389) {
                scores.put("Windows", scores.getOrDefault("Windows", 0) + 2);
            }
            if (service.banner != null && service.banner.contains("Microsoft")) {
                scores.put("Windows", scores.getOrDefault("Windows", 0) + 3);
            }

            // Linux indicators
            if (service.product != null) {
                if (service.product.contains("OpenSSH")) {
                    scores.put("Linux", scores.getOrDefault("Linux", 0) + 1);
                }
                if (service.product.contains("Apache") || service.product.contains("nginx")) {
                    scores.put("Linux", scores.getOrDefault("Linux", 0) + 1);
                }
            }

            // Network device indicators
            if (service.banner != null && (service.banner.contains("Cisco") || service.banner.contains("RouterOS"))) {
                scores.put("Network Device", scores.getOrDefault("Network Device", 0) + 5);
            }
        }

        // Find highest score
        String bestGuess = "Unknown";
        int maxScore = 0;
        for (Map.Entry<String, Integer> entry : scores.entrySet()) {
            if (entry.getValue() > maxScore) {
                maxScore = entry.getValue();
                bestGuess = entry.getKey();
            }
            profile.osPossibilities.add(entry.getKey() + " (" + entry.getValue() + ")");
        }

        profile.osGuess = bestGuess;
        profile.osConfidence = maxScore > 0 ? Math.min(maxScore / 10.0f, 1.0f) : 0;
    }

    /**
     * Detect technologies used.
     */
    private static void detectTechnologies(@NonNull TargetProfile profile) {
        for (ServiceInfo service : profile.services) {
            if (service.product != null && !service.product.isEmpty()) {
                profile.technologies.add(service.product);
            }
        }
    }

    /**
     * Classify device type.
     */
    @NonNull
    private static DeviceType classifyDevice(@NonNull TargetProfile profile) {
        // Check for router/network device indicators
        for (ServiceInfo service : profile.services) {
            if (service.banner != null) {
                if (service.banner.contains("Cisco") || service.banner.contains("RouterOS") ||
                    service.banner.contains("Ubiquiti") || service.banner.contains("MikroTik")) {
                    return DeviceType.ROUTER;
                }
            }
        }

        // Check for server indicators
        boolean hasHttp = false, hasSsh = false, hasDb = false;
        for (ServiceInfo service : profile.services) {
            if (service.port == 80 || service.port == 443) hasHttp = true;
            if (service.port == 22) hasSsh = true;
            if (service.port == 3306 || service.port == 5432 || service.port == 1433) hasDb = true;
        }

        if (hasHttp && (hasSsh || hasDb)) {
            return DeviceType.SERVER;
        }

        // Windows workstation
        if (profile.osGuess != null && profile.osGuess.contains("Windows")) {
            for (ServiceInfo service : profile.services) {
                if (service.port == 3389) {
                    return DeviceType.WORKSTATION;
                }
            }
        }

        // NAS indicators
        for (ServiceInfo service : profile.services) {
            if (service.banner != null && (service.banner.contains("Synology") ||
                service.banner.contains("QNAP") || service.banner.contains("FreeNAS"))) {
                return DeviceType.NAS;
            }
        }

        // Printer indicators
        for (ServiceInfo service : profile.services) {
            if (service.port == 9100 || service.port == 515 || service.port == 631) {
                return DeviceType.PRINTER;
            }
        }

        return DeviceType.UNKNOWN;
    }

    /**
     * Assess risk level.
     */
    @NonNull
    private static RiskLevel assessRisk(@NonNull TargetProfile profile) {
        int riskScore = 0;

        for (ServiceInfo service : profile.services) {
            // High-risk services
            if (service.port == 23 || service.port == 21) riskScore += 3; // Telnet, FTP (unencrypted)
            if (service.port == 3389) riskScore += 2; // RDP
            if (service.port == 445) riskScore += 2; // SMB
            if (service.port == 6379) riskScore += 3; // Redis (often exposed)
            if (service.port == 27017) riskScore += 3; // MongoDB
            if (service.port == 5900) riskScore += 2; // VNC

            // Version-based vulnerabilities (simplified)
            if (service.version != null) {
                // Check for known vulnerable versions (example patterns)
                if (service.product != null && service.product.contains("OpenSSH") &&
                    service.version.matches("^[1-6]\\..*")) {
                    riskScore += 2;
                }
            }
        }

        // Large number of open ports
        if (profile.openPortCount > 10) riskScore += 2;
        if (profile.openPortCount > 20) riskScore += 3;

        if (riskScore >= 10) return RiskLevel.CRITICAL;
        if (riskScore >= 7) return RiskLevel.HIGH;
        if (riskScore >= 4) return RiskLevel.MEDIUM;
        if (riskScore >= 1) return RiskLevel.LOW;
        return RiskLevel.INFO;
    }

    /**
     * Shutdown the executor service.
     */
    public static void shutdown() {
        executor.shutdown();
    }
}
