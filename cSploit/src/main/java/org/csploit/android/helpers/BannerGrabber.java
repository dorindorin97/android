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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * BannerGrabber - Network service banner grabbing utilities.
 * 
 * Provides:
 * - Service banner detection
 * - Version fingerprinting
 * - Protocol identification
 * - Multi-port banner grabbing
 * 
 * Usage:
 * {@code
 * // Grab banner from single port
 * String banner = BannerGrabber.grabBanner("192.168.1.1", 22);
 * 
 * // Detect service
 * ServiceInfo info = BannerGrabber.detectService("192.168.1.1", 80);
 * 
 * // Batch grab
 * Map<Integer, String> banners = BannerGrabber.grabBanners("192.168.1.1", new int[]{21, 22, 80, 443});
 * }
 */
public final class BannerGrabber {
    
    private static final String TAG = "BannerGrabber";
    private static final int DEFAULT_TIMEOUT = 5000; // 5 seconds
    private static final int DEFAULT_BUFFER_SIZE = 4096;
    
    // Protocol probes
    private static final Map<Integer, String> PROTOCOL_PROBES = new HashMap<>();
    
    // Banner cache
    private static final ConcurrentHashMap<String, BannerInfo> bannerCache = new ConcurrentHashMap<>();
    private static final long CACHE_TTL_MS = 300000; // 5 minutes
    
    static {
        // HTTP probe
        PROTOCOL_PROBES.put(80, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n");
        PROTOCOL_PROBES.put(8080, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n");
        
        // HTTPS (won't get banner without SSL, just connection test)
        PROTOCOL_PROBES.put(443, null);
        
        // FTP
        PROTOCOL_PROBES.put(21, null); // FTP sends banner on connect
        
        // SSH
        PROTOCOL_PROBES.put(22, null); // SSH sends banner on connect
        
        // Telnet
        PROTOCOL_PROBES.put(23, null); // Telnet sends banner on connect
        
        // SMTP
        PROTOCOL_PROBES.put(25, "EHLO test\r\n");
        PROTOCOL_PROBES.put(587, "EHLO test\r\n");
        
        // POP3
        PROTOCOL_PROBES.put(110, null);
        
        // IMAP
        PROTOCOL_PROBES.put(143, null);
        
        // MySQL
        PROTOCOL_PROBES.put(3306, null);
        
        // PostgreSQL
        PROTOCOL_PROBES.put(5432, null);
        
        // Redis
        PROTOCOL_PROBES.put(6379, "INFO\r\n");
        
        // MongoDB
        PROTOCOL_PROBES.put(27017, null);
    }
    
    /**
     * Service information from banner analysis.
     */
    public static class ServiceInfo {
        public String serviceName;
        public String version;
        public String operatingSystem;
        public String banner;
        public int port;
        public long responseTimeMs;
        public boolean isSecure;
        public List<String> detectedVulnerabilities;
        
        public ServiceInfo() {
            detectedVulnerabilities = new ArrayList<>();
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("Service{name='%s', version='%s', os='%s', port=%d}",
                    serviceName, version, operatingSystem, port);
        }
    }
    
    /**
     * Banner cache entry.
     */
    private static class BannerInfo {
        String banner;
        long timestamp;
        
        BannerInfo(String banner) {
            this.banner = banner;
            this.timestamp = java.lang.System.currentTimeMillis();
        }
        
        boolean isExpired() {
            return java.lang.System.currentTimeMillis() - timestamp > CACHE_TTL_MS;
        }
    }
    
    private BannerGrabber() {}
    
    /**
     * Grab banner from a single port.
     * 
     * @param host target host
     * @param port target port
     * @return banner string or null
     */
    @Nullable
    public static String grabBanner(@NonNull String host, int port) {
        return grabBanner(host, port, DEFAULT_TIMEOUT);
    }
    
    /**
     * Grab banner with custom timeout.
     */
    @Nullable
    public static String grabBanner(@NonNull String host, int port, int timeoutMs) {
        // Check cache
        String cacheKey = host + ":" + port;
        BannerInfo cached = bannerCache.get(cacheKey);
        if (cached != null && !cached.isExpired()) {
            return cached.banner;
        }
        
        java.net.Socket socket = null;
        try {
            socket = new java.net.Socket();
            socket.connect(new java.net.InetSocketAddress(host, port), timeoutMs);
            socket.setSoTimeout(timeoutMs);
            
            java.io.OutputStream out = socket.getOutputStream();
            java.io.InputStream in = socket.getInputStream();
            
            // Send probe if available
            String probe = PROTOCOL_PROBES.get(port);
            if (probe != null) {
                String formattedProbe = String.format(probe, host);
                out.write(formattedProbe.getBytes());
                out.flush();
            }
            
            // Read response
            byte[] buffer = new byte[DEFAULT_BUFFER_SIZE];
            StringBuilder bannerBuilder = new StringBuilder();
            
            // Give the service time to respond
            Thread.sleep(100);
            
            while (in.available() > 0 || bannerBuilder.length() == 0) {
                int bytesRead = in.read(buffer);
                if (bytesRead <= 0) break;
                
                bannerBuilder.append(new String(buffer, 0, bytesRead));
                
                // Don't read too much
                if (bannerBuilder.length() > DEFAULT_BUFFER_SIZE * 2) break;
                
                // Check if more data coming
                if (in.available() == 0) {
                    Thread.sleep(50);
                    if (in.available() == 0) break;
                }
            }
            
            String banner = bannerBuilder.toString().trim();
            
            // Cache result
            if (!banner.isEmpty()) {
                bannerCache.put(cacheKey, new BannerInfo(banner));
            }
            
            return banner.isEmpty() ? null : banner;
            
        } catch (Exception e) {
            Log.d(TAG, "Failed to grab banner from " + host + ":" + port, e);
            return null;
        } finally {
            if (socket != null) {
                try {
                    socket.close();
                } catch (Exception ignored) {}
            }
        }
    }
    
    /**
     * Grab banners from multiple ports.
     */
    @NonNull
    public static Map<Integer, String> grabBanners(@NonNull String host, @NonNull int[] ports) {
        Map<Integer, String> banners = new HashMap<>();
        
        for (int port : ports) {
            String banner = grabBanner(host, port);
            if (banner != null) {
                banners.put(port, banner);
            }
        }
        
        return banners;
    }
    
    /**
     * Detect service from banner.
     */
    @NonNull
    public static ServiceInfo detectService(@NonNull String host, int port) {
        ServiceInfo info = new ServiceInfo();
        info.port = port;
        
        long startTime = java.lang.System.currentTimeMillis();
        info.banner = grabBanner(host, port);
        info.responseTimeMs = java.lang.System.currentTimeMillis() - startTime;
        
        if (info.banner == null) {
            info.serviceName = "unknown";
            return info;
        }
        
        // Analyze banner
        analyzeBanner(info);
        
        return info;
    }
    
    /**
     * Analyze banner to extract service information.
     */
    private static void analyzeBanner(@NonNull ServiceInfo info) {
        String banner = info.banner.toLowerCase();
        
        // SSH detection
        if (banner.startsWith("ssh-")) {
            info.serviceName = "SSH";
            info.isSecure = true;
            
            // Extract version: SSH-2.0-OpenSSH_8.9p1
            if (info.banner.contains("OpenSSH")) {
                info.version = extractVersion(info.banner, "OpenSSH[_-]?([\\d.p]+)");
            } else if (info.banner.contains("dropbear")) {
                info.version = extractVersion(info.banner, "dropbear[_-]?([\\d.]+)");
            }
            
            // OS detection from SSH banner
            if (banner.contains("ubuntu")) info.operatingSystem = "Ubuntu Linux";
            else if (banner.contains("debian")) info.operatingSystem = "Debian Linux";
            else if (banner.contains("centos")) info.operatingSystem = "CentOS Linux";
            else if (banner.contains("rhel")) info.operatingSystem = "Red Hat Enterprise Linux";
            
            return;
        }
        
        // HTTP/Web server detection
        if (banner.contains("http/") || banner.contains("server:")) {
            info.serviceName = "HTTP";
            
            if (banner.contains("apache")) {
                info.serviceName = "Apache HTTP Server";
                info.version = extractVersion(banner, "apache[/\\s]?([\\d.]+)");
            } else if (banner.contains("nginx")) {
                info.serviceName = "nginx";
                info.version = extractVersion(banner, "nginx[/\\s]?([\\d.]+)");
            } else if (banner.contains("iis")) {
                info.serviceName = "Microsoft IIS";
                info.version = extractVersion(banner, "iis[/\\s]?([\\d.]+)");
                info.operatingSystem = "Windows";
            } else if (banner.contains("lighttpd")) {
                info.serviceName = "lighttpd";
                info.version = extractVersion(banner, "lighttpd[/\\s]?([\\d.]+)");
            }
            
            return;
        }
        
        // FTP detection
        if (banner.contains("ftp") || banner.contains("220 ") || banner.contains("vsftpd") || banner.contains("proftpd")) {
            info.serviceName = "FTP";
            
            if (banner.contains("vsftpd")) {
                info.serviceName = "vsftpd";
                info.version = extractVersion(banner, "vsftpd[\\s]?([\\d.]+)");
            } else if (banner.contains("proftpd")) {
                info.serviceName = "ProFTPD";
                info.version = extractVersion(banner, "proftpd[\\s]?([\\d.]+)");
            } else if (banner.contains("filezilla")) {
                info.serviceName = "FileZilla Server";
                info.operatingSystem = "Windows";
            } else if (banner.contains("pure-ftpd")) {
                info.serviceName = "Pure-FTPd";
            }
            
            return;
        }
        
        // SMTP detection
        if (banner.contains("smtp") || banner.contains("220 ") && banner.contains("mail") || banner.contains("postfix") || banner.contains("sendmail")) {
            info.serviceName = "SMTP";
            
            if (banner.contains("postfix")) {
                info.serviceName = "Postfix";
            } else if (banner.contains("sendmail")) {
                info.serviceName = "Sendmail";
            } else if (banner.contains("exim")) {
                info.serviceName = "Exim";
                info.version = extractVersion(banner, "exim[\\s]?([\\d.]+)");
            } else if (banner.contains("exchange")) {
                info.serviceName = "Microsoft Exchange";
                info.operatingSystem = "Windows";
            }
            
            return;
        }
        
        // MySQL detection
        if (banner.contains("mysql") || (info.port == 3306 && banner.length() > 0)) {
            info.serviceName = "MySQL";
            info.version = extractVersion(banner, "([\\d.]+)-");
            return;
        }
        
        // PostgreSQL detection
        if (banner.contains("postgresql") || info.port == 5432) {
            info.serviceName = "PostgreSQL";
            return;
        }
        
        // Redis detection
        if (banner.contains("redis") || info.port == 6379) {
            info.serviceName = "Redis";
            info.version = extractVersion(banner, "redis_version:([\\d.]+)");
            return;
        }
        
        // Telnet detection
        if (info.port == 23 || banner.contains("telnet")) {
            info.serviceName = "Telnet";
            info.isSecure = false;
            
            // Check for router/device signatures
            if (banner.contains("cisco")) {
                info.operatingSystem = "Cisco IOS";
            } else if (banner.contains("mikrotik")) {
                info.operatingSystem = "MikroTik RouterOS";
            }
            
            return;
        }
        
        // Default: try to identify by port
        info.serviceName = guessServiceByPort(info.port);
    }
    
    /**
     * Extract version using regex pattern.
     */
    @Nullable
    private static String extractVersion(@NonNull String text, @NonNull String pattern) {
        try {
            java.util.regex.Pattern p = java.util.regex.Pattern.compile(pattern, java.util.regex.Pattern.CASE_INSENSITIVE);
            java.util.regex.Matcher m = p.matcher(text);
            if (m.find()) {
                return m.group(1);
            }
        } catch (Exception e) {
            Log.w(TAG, "Failed to extract version", e);
        }
        return null;
    }
    
    /**
     * Guess service name by port number.
     */
    @NonNull
    private static String guessServiceByPort(int port) {
        switch (port) {
            case 20: return "FTP-DATA";
            case 21: return "FTP";
            case 22: return "SSH";
            case 23: return "Telnet";
            case 25: return "SMTP";
            case 53: return "DNS";
            case 67: case 68: return "DHCP";
            case 69: return "TFTP";
            case 80: return "HTTP";
            case 110: return "POP3";
            case 119: return "NNTP";
            case 123: return "NTP";
            case 143: return "IMAP";
            case 161: case 162: return "SNMP";
            case 389: return "LDAP";
            case 443: return "HTTPS";
            case 445: return "SMB";
            case 465: return "SMTPS";
            case 514: return "Syslog";
            case 587: return "SMTP Submission";
            case 636: return "LDAPS";
            case 993: return "IMAPS";
            case 995: return "POP3S";
            case 1433: return "MSSQL";
            case 1521: return "Oracle";
            case 3306: return "MySQL";
            case 3389: return "RDP";
            case 5432: return "PostgreSQL";
            case 5900: return "VNC";
            case 6379: return "Redis";
            case 8080: return "HTTP Proxy";
            case 8443: return "HTTPS Alt";
            case 27017: return "MongoDB";
            default: return "unknown";
        }
    }
    
    /**
     * Clear banner cache.
     */
    public static void clearCache() {
        bannerCache.clear();
    }
    
    /**
     * Get common ports for banner grabbing.
     */
    @NonNull
    public static int[] getCommonPorts() {
        return new int[]{
            21, 22, 23, 25, 53, 80, 110, 143, 443, 
            445, 587, 993, 995, 1433, 3306, 3389, 
            5432, 5900, 6379, 8080, 8443, 27017
        };
    }
}
