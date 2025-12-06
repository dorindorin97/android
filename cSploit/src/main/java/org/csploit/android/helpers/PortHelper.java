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

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
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

/**
 * PortHelper - TCP/UDP port scanning and service detection utilities.
 * 
 * Provides:
 * - Fast TCP port scanning
 * - Service detection
 * - Well-known port database
 * - Concurrent scanning
 * 
 * Usage:
 * {@code
 * // Scan single port
 * boolean open = PortHelper.isPortOpen("192.168.1.1", 80);
 * 
 * // Scan port range
 * List<Integer> openPorts = PortHelper.scanPorts("192.168.1.1", 1, 1024);
 * 
 * // Get service name
 * String service = PortHelper.getServiceName(80);
 * }
 */
public final class PortHelper {
    
    private static final String TAG = "PortHelper";
    private static final int DEFAULT_TIMEOUT = 1000; // 1 second
    private static final int DEFAULT_THREADS = 50;
    
    // Well-known ports database
    private static final Map<Integer, PortInfo> PORT_DATABASE = new HashMap<>();
    
    // Scan results cache
    private static final Map<String, ScanResult> scanCache = new ConcurrentHashMap<>();
    private static final long CACHE_TTL_MS = 60000; // 1 minute
    
    static {
        initializePortDatabase();
    }
    
    /**
     * Port information.
     */
    public static class PortInfo {
        public int port;
        public String serviceName;
        public String description;
        public String protocol; // tcp, udp, or tcp/udp
        public boolean isSecure;
        public String category;
        
        public PortInfo(int port, String serviceName, String description) {
            this(port, serviceName, description, "tcp", false, "general");
        }
        
        public PortInfo(int port, String serviceName, String description, String protocol, boolean isSecure, String category) {
            this.port = port;
            this.serviceName = serviceName;
            this.description = description;
            this.protocol = protocol;
            this.isSecure = isSecure;
            this.category = category;
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("%d/%s %s", port, protocol, serviceName);
        }
    }
    
    /**
     * Scan result for a single port.
     */
    public static class ScanResult {
        public String host;
        public int port;
        public boolean isOpen;
        public long latencyMs;
        public String serviceName;
        public String banner;
        public long scanTime;
        
        @NonNull
        @Override
        public String toString() {
            return String.format("%s:%d %s (%dms)",
                    host, port, isOpen ? "OPEN" : "CLOSED", latencyMs);
        }
    }
    
    /**
     * Scan progress callback.
     */
    public interface ScanProgressCallback {
        void onProgress(int scannedPorts, int totalPorts, ScanResult result);
        void onComplete(List<ScanResult> results);
    }
    
    private PortHelper() {}
    
    /**
     * Check if a single port is open.
     */
    public static boolean isPortOpen(@NonNull String host, int port) {
        return isPortOpen(host, port, DEFAULT_TIMEOUT);
    }
    
    /**
     * Check if port is open with custom timeout.
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
     * Scan a single port and get detailed result.
     */
    @NonNull
    public static ScanResult scanPort(@NonNull String host, int port) {
        return scanPort(host, port, DEFAULT_TIMEOUT);
    }
    
    /**
     * Scan port with custom timeout.
     */
    @NonNull
    public static ScanResult scanPort(@NonNull String host, int port, int timeoutMs) {
        ScanResult result = new ScanResult();
        result.host = host;
        result.port = port;
        result.scanTime = java.lang.System.currentTimeMillis();
        
        long startTime = java.lang.System.nanoTime();
        
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            result.isOpen = true;
            result.latencyMs = (java.lang.System.nanoTime() - startTime) / 1_000_000;
            result.serviceName = getServiceName(port);
        } catch (IOException e) {
            result.isOpen = false;
            result.latencyMs = (java.lang.System.nanoTime() - startTime) / 1_000_000;
        }
        
        return result;
    }
    
    /**
     * Scan port range synchronously.
     */
    @NonNull
    public static List<ScanResult> scanPorts(@NonNull String host, int startPort, int endPort) {
        return scanPorts(host, startPort, endPort, DEFAULT_TIMEOUT, DEFAULT_THREADS, null);
    }
    
    /**
     * Scan port range with callback.
     */
    @NonNull
    public static List<ScanResult> scanPorts(
            @NonNull String host,
            int startPort,
            int endPort,
            int timeoutMs,
            int threadCount,
            @Nullable ScanProgressCallback callback) {
        
        List<ScanResult> results = Collections.synchronizedList(new ArrayList<>());
        int totalPorts = endPort - startPort + 1;
        AtomicInteger scannedCount = new AtomicInteger(0);
        
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        List<Future<?>> futures = new ArrayList<>();
        
        for (int port = startPort; port <= endPort; port++) {
            final int currentPort = port;
            futures.add(executor.submit(() -> {
                ScanResult result = scanPort(host, currentPort, timeoutMs);
                if (result.isOpen) {
                    results.add(result);
                }
                
                int scanned = scannedCount.incrementAndGet();
                if (callback != null) {
                    callback.onProgress(scanned, totalPorts, result);
                }
            }));
        }
        
        // Wait for all scans to complete
        for (Future<?> future : futures) {
            try {
                future.get(timeoutMs * 2L, TimeUnit.MILLISECONDS);
            } catch (Exception e) {
                Log.w(TAG, "Scan task error", e);
            }
        }
        
        executor.shutdown();
        
        // Sort results by port number
        results.sort((a, b) -> Integer.compare(a.port, b.port));
        
        if (callback != null) {
            callback.onComplete(results);
        }
        
        return results;
    }
    
    /**
     * Scan common ports only.
     */
    @NonNull
    public static List<ScanResult> scanCommonPorts(@NonNull String host) {
        return scanCommonPorts(host, null);
    }
    
    /**
     * Scan common ports with callback.
     */
    @NonNull
    public static List<ScanResult> scanCommonPorts(
            @NonNull String host,
            @Nullable ScanProgressCallback callback) {
        
        int[] commonPorts = getCommonPorts();
        List<ScanResult> results = Collections.synchronizedList(new ArrayList<>());
        AtomicInteger scannedCount = new AtomicInteger(0);
        
        ExecutorService executor = Executors.newFixedThreadPool(DEFAULT_THREADS);
        List<Future<?>> futures = new ArrayList<>();
        
        for (int port : commonPorts) {
            futures.add(executor.submit(() -> {
                ScanResult result = scanPort(host, port, DEFAULT_TIMEOUT);
                if (result.isOpen) {
                    results.add(result);
                }
                
                int scanned = scannedCount.incrementAndGet();
                if (callback != null) {
                    callback.onProgress(scanned, commonPorts.length, result);
                }
            }));
        }
        
        for (Future<?> future : futures) {
            try {
                future.get(DEFAULT_TIMEOUT * 2L, TimeUnit.MILLISECONDS);
            } catch (Exception e) {
                Log.w(TAG, "Scan task error", e);
            }
        }
        
        executor.shutdown();
        results.sort((a, b) -> Integer.compare(a.port, b.port));
        
        if (callback != null) {
            callback.onComplete(results);
        }
        
        return results;
    }
    
    /**
     * Get service name for a port.
     */
    @NonNull
    public static String getServiceName(int port) {
        PortInfo info = PORT_DATABASE.get(port);
        return info != null ? info.serviceName : "unknown";
    }
    
    /**
     * Get port info.
     */
    @Nullable
    public static PortInfo getPortInfo(int port) {
        return PORT_DATABASE.get(port);
    }
    
    /**
     * Get all known ports.
     */
    @NonNull
    public static Map<Integer, PortInfo> getPortDatabase() {
        return Collections.unmodifiableMap(PORT_DATABASE);
    }
    
    /**
     * Get commonly scanned ports.
     */
    @NonNull
    public static int[] getCommonPorts() {
        return new int[]{
            20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 
            110, 111, 119, 123, 135, 137, 138, 139, 143, 161,
            162, 179, 194, 389, 443, 445, 464, 465, 514, 515,
            587, 636, 993, 995, 1080, 1433, 1434, 1521, 1723,
            2049, 2082, 2083, 2086, 2087, 2095, 2096, 3306, 3389,
            5432, 5900, 5901, 6379, 8080, 8443, 8888, 9000, 9090,
            9200, 9300, 11211, 27017, 27018, 27019
        };
    }
    
    /**
     * Get web-related ports.
     */
    @NonNull
    public static int[] getWebPorts() {
        return new int[]{
            80, 443, 8000, 8080, 8443, 8888, 9000, 9443
        };
    }
    
    /**
     * Get database ports.
     */
    @NonNull
    public static int[] getDatabasePorts() {
        return new int[]{
            1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017
        };
    }
    
    /**
     * Check if port is in valid range.
     */
    public static boolean isValidPort(int port) {
        return port > 0 && port <= 65535;
    }
    
    /**
     * Check if port is privileged (requires root).
     */
    public static boolean isPrivilegedPort(int port) {
        return port > 0 && port < 1024;
    }
    
    /**
     * Find port by service name.
     */
    @Nullable
    public static Integer findPortByService(@NonNull String serviceName) {
        String lowerName = serviceName.toLowerCase();
        for (Map.Entry<Integer, PortInfo> entry : PORT_DATABASE.entrySet()) {
            if (entry.getValue().serviceName.toLowerCase().equals(lowerName)) {
                return entry.getKey();
            }
        }
        return null;
    }
    
    /**
     * Initialize port database.
     */
    private static void initializePortDatabase() {
        // File Transfer
        PORT_DATABASE.put(20, new PortInfo(20, "FTP-DATA", "FTP Data Transfer", "tcp", false, "file"));
        PORT_DATABASE.put(21, new PortInfo(21, "FTP", "File Transfer Protocol", "tcp", false, "file"));
        PORT_DATABASE.put(22, new PortInfo(22, "SSH", "Secure Shell", "tcp", true, "remote"));
        PORT_DATABASE.put(23, new PortInfo(23, "Telnet", "Telnet", "tcp", false, "remote"));
        PORT_DATABASE.put(25, new PortInfo(25, "SMTP", "Simple Mail Transfer Protocol", "tcp", false, "mail"));
        
        // DNS
        PORT_DATABASE.put(53, new PortInfo(53, "DNS", "Domain Name System", "tcp/udp", false, "network"));
        
        // DHCP
        PORT_DATABASE.put(67, new PortInfo(67, "DHCP-Server", "DHCP Server", "udp", false, "network"));
        PORT_DATABASE.put(68, new PortInfo(68, "DHCP-Client", "DHCP Client", "udp", false, "network"));
        
        // TFTP
        PORT_DATABASE.put(69, new PortInfo(69, "TFTP", "Trivial File Transfer Protocol", "udp", false, "file"));
        
        // HTTP
        PORT_DATABASE.put(80, new PortInfo(80, "HTTP", "Hypertext Transfer Protocol", "tcp", false, "web"));
        
        // Mail
        PORT_DATABASE.put(110, new PortInfo(110, "POP3", "Post Office Protocol v3", "tcp", false, "mail"));
        PORT_DATABASE.put(143, new PortInfo(143, "IMAP", "Internet Message Access Protocol", "tcp", false, "mail"));
        
        // RPC
        PORT_DATABASE.put(111, new PortInfo(111, "RPC", "Remote Procedure Call", "tcp/udp", false, "network"));
        
        // NNTP
        PORT_DATABASE.put(119, new PortInfo(119, "NNTP", "Network News Transfer Protocol", "tcp", false, "news"));
        
        // NTP
        PORT_DATABASE.put(123, new PortInfo(123, "NTP", "Network Time Protocol", "udp", false, "network"));
        
        // Microsoft
        PORT_DATABASE.put(135, new PortInfo(135, "MS-RPC", "Microsoft RPC", "tcp", false, "microsoft"));
        PORT_DATABASE.put(137, new PortInfo(137, "NetBIOS-NS", "NetBIOS Name Service", "tcp/udp", false, "microsoft"));
        PORT_DATABASE.put(138, new PortInfo(138, "NetBIOS-DG", "NetBIOS Datagram", "udp", false, "microsoft"));
        PORT_DATABASE.put(139, new PortInfo(139, "NetBIOS-SS", "NetBIOS Session Service", "tcp", false, "microsoft"));
        PORT_DATABASE.put(445, new PortInfo(445, "SMB", "Server Message Block", "tcp", false, "microsoft"));
        
        // SNMP
        PORT_DATABASE.put(161, new PortInfo(161, "SNMP", "Simple Network Management Protocol", "udp", false, "network"));
        PORT_DATABASE.put(162, new PortInfo(162, "SNMP-TRAP", "SNMP Trap", "udp", false, "network"));
        
        // BGP
        PORT_DATABASE.put(179, new PortInfo(179, "BGP", "Border Gateway Protocol", "tcp", false, "routing"));
        
        // IRC
        PORT_DATABASE.put(194, new PortInfo(194, "IRC", "Internet Relay Chat", "tcp", false, "chat"));
        
        // LDAP
        PORT_DATABASE.put(389, new PortInfo(389, "LDAP", "Lightweight Directory Access Protocol", "tcp", false, "directory"));
        PORT_DATABASE.put(636, new PortInfo(636, "LDAPS", "LDAP over SSL", "tcp", true, "directory"));
        
        // HTTPS
        PORT_DATABASE.put(443, new PortInfo(443, "HTTPS", "HTTP Secure", "tcp", true, "web"));
        
        // Kerberos
        PORT_DATABASE.put(464, new PortInfo(464, "Kerberos", "Kerberos Password Change", "tcp/udp", true, "auth"));
        
        // Secure Mail
        PORT_DATABASE.put(465, new PortInfo(465, "SMTPS", "SMTP over SSL", "tcp", true, "mail"));
        PORT_DATABASE.put(587, new PortInfo(587, "SMTP-MSA", "SMTP Message Submission", "tcp", false, "mail"));
        PORT_DATABASE.put(993, new PortInfo(993, "IMAPS", "IMAP over SSL", "tcp", true, "mail"));
        PORT_DATABASE.put(995, new PortInfo(995, "POP3S", "POP3 over SSL", "tcp", true, "mail"));
        
        // Syslog
        PORT_DATABASE.put(514, new PortInfo(514, "Syslog", "System Log", "udp", false, "logging"));
        
        // LPD
        PORT_DATABASE.put(515, new PortInfo(515, "LPD", "Line Printer Daemon", "tcp", false, "printing"));
        
        // SOCKS
        PORT_DATABASE.put(1080, new PortInfo(1080, "SOCKS", "SOCKS Proxy", "tcp", false, "proxy"));
        
        // Databases
        PORT_DATABASE.put(1433, new PortInfo(1433, "MSSQL", "Microsoft SQL Server", "tcp", false, "database"));
        PORT_DATABASE.put(1434, new PortInfo(1434, "MSSQL-UDP", "MS SQL Monitor", "udp", false, "database"));
        PORT_DATABASE.put(1521, new PortInfo(1521, "Oracle", "Oracle Database", "tcp", false, "database"));
        PORT_DATABASE.put(3306, new PortInfo(3306, "MySQL", "MySQL Database", "tcp", false, "database"));
        PORT_DATABASE.put(5432, new PortInfo(5432, "PostgreSQL", "PostgreSQL Database", "tcp", false, "database"));
        PORT_DATABASE.put(6379, new PortInfo(6379, "Redis", "Redis Key-Value Store", "tcp", false, "database"));
        PORT_DATABASE.put(11211, new PortInfo(11211, "Memcached", "Memcached", "tcp", false, "database"));
        PORT_DATABASE.put(27017, new PortInfo(27017, "MongoDB", "MongoDB", "tcp", false, "database"));
        PORT_DATABASE.put(9200, new PortInfo(9200, "Elasticsearch", "Elasticsearch HTTP", "tcp", false, "database"));
        PORT_DATABASE.put(9300, new PortInfo(9300, "Elasticsearch", "Elasticsearch Transport", "tcp", false, "database"));
        
        // VPN
        PORT_DATABASE.put(1723, new PortInfo(1723, "PPTP", "Point-to-Point Tunneling", "tcp", false, "vpn"));
        
        // NFS
        PORT_DATABASE.put(2049, new PortInfo(2049, "NFS", "Network File System", "tcp/udp", false, "file"));
        
        // Control Panels
        PORT_DATABASE.put(2082, new PortInfo(2082, "cPanel", "cPanel", "tcp", false, "admin"));
        PORT_DATABASE.put(2083, new PortInfo(2083, "cPanel-SSL", "cPanel SSL", "tcp", true, "admin"));
        PORT_DATABASE.put(2086, new PortInfo(2086, "WHM", "WebHost Manager", "tcp", false, "admin"));
        PORT_DATABASE.put(2087, new PortInfo(2087, "WHM-SSL", "WHM SSL", "tcp", true, "admin"));
        
        // Remote Desktop
        PORT_DATABASE.put(3389, new PortInfo(3389, "RDP", "Remote Desktop Protocol", "tcp", false, "remote"));
        PORT_DATABASE.put(5900, new PortInfo(5900, "VNC", "Virtual Network Computing", "tcp", false, "remote"));
        PORT_DATABASE.put(5901, new PortInfo(5901, "VNC-1", "VNC Display 1", "tcp", false, "remote"));
        
        // Web Servers / Proxies
        PORT_DATABASE.put(8080, new PortInfo(8080, "HTTP-Proxy", "HTTP Proxy", "tcp", false, "web"));
        PORT_DATABASE.put(8443, new PortInfo(8443, "HTTPS-Alt", "HTTPS Alternative", "tcp", true, "web"));
        PORT_DATABASE.put(8888, new PortInfo(8888, "HTTP-Alt", "HTTP Alternative", "tcp", false, "web"));
        PORT_DATABASE.put(9000, new PortInfo(9000, "PHP-FPM", "PHP FastCGI", "tcp", false, "web"));
        PORT_DATABASE.put(9090, new PortInfo(9090, "WebAdmin", "Web Administration", "tcp", false, "admin"));
    }
}
