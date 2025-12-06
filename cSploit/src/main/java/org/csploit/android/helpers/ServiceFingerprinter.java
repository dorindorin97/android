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
import androidx.annotation.Nullable;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * ServiceFingerprinter - Enhanced service identification utility
 *
 * Provides:
 * - Banner-based service identification
 * - Version extraction from banners
 * - Product name detection
 * - OS fingerprinting from service banners
 * - Known vulnerability matching based on version
 *
 * Usage:
 * {@code
 * ServiceFingerprinter fp = ServiceFingerprinter.getInstance();
 * ServiceInfo info = fp.fingerprint("SSH-2.0-OpenSSH_7.4");
 * // info.getService() -> "ssh"
 * // info.getProduct() -> "OpenSSH"
 * // info.getVersion() -> "7.4"
 * }
 */
public final class ServiceFingerprinter {

    private static final String TAG = "ServiceFingerprinter";
    private static volatile ServiceFingerprinter instance;

    private final List<ServiceSignature> signatures;
    private final Map<Integer, String> defaultServices;

    private ServiceFingerprinter() {
        signatures = new ArrayList<>();
        defaultServices = new HashMap<>();
        initializeSignatures();
        initializeDefaultServices();
    }

    public static ServiceFingerprinter getInstance() {
        if (instance == null) {
            synchronized (ServiceFingerprinter.class) {
                if (instance == null) {
                    instance = new ServiceFingerprinter();
                }
            }
        }
        return instance;
    }

    // ==================== Service Info Class ====================

    /**
     * Information about an identified service
     */
    public static class ServiceInfo {
        private final String service;
        private final String product;
        private final String version;
        private final String os;
        private final String extraInfo;
        private final int confidence; // 0-100

        private ServiceInfo(Builder builder) {
            this.service = builder.service;
            this.product = builder.product;
            this.version = builder.version;
            this.os = builder.os;
            this.extraInfo = builder.extraInfo;
            this.confidence = builder.confidence;
        }

        public String getService() { return service; }
        public String getProduct() { return product; }
        public String getVersion() { return version; }
        public String getOs() { return os; }
        public String getExtraInfo() { return extraInfo; }
        public int getConfidence() { return confidence; }

        public boolean hasVersion() { return version != null && !version.isEmpty(); }
        public boolean hasProduct() { return product != null && !product.isEmpty(); }
        public boolean hasOs() { return os != null && !os.isEmpty(); }

        @NonNull
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            if (product != null) sb.append(product);
            if (version != null) sb.append(" ").append(version);
            if (service != null) sb.append(" (").append(service).append(")");
            if (os != null) sb.append(" [").append(os).append("]");
            return sb.toString().trim();
        }

        public static class Builder {
            private String service;
            private String product;
            private String version;
            private String os;
            private String extraInfo;
            private int confidence = 50;

            public Builder service(String val) { service = val; return this; }
            public Builder product(String val) { product = val; return this; }
            public Builder version(String val) { version = val; return this; }
            public Builder os(String val) { os = val; return this; }
            public Builder extraInfo(String val) { extraInfo = val; return this; }
            public Builder confidence(int val) { confidence = val; return this; }

            public ServiceInfo build() { return new ServiceInfo(this); }
        }
    }

    // ==================== Service Signature Class ====================

    /**
     * Pattern for matching service banners
     */
    private static class ServiceSignature {
        final String service;
        final Pattern pattern;
        final int productGroup;
        final int versionGroup;
        final int osGroup;

        ServiceSignature(String service, String regex, int productGroup, int versionGroup, int osGroup) {
            this.service = service;
            this.pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
            this.productGroup = productGroup;
            this.versionGroup = versionGroup;
            this.osGroup = osGroup;
        }

        ServiceSignature(String service, String regex, int productGroup, int versionGroup) {
            this(service, regex, productGroup, versionGroup, -1);
        }

        ServiceSignature(String service, String regex) {
            this(service, regex, -1, -1, -1);
        }
    }

    // ==================== Fingerprinting ====================

    /**
     * Fingerprint a service from its banner
     */
    @NonNull
    public ServiceInfo fingerprint(@Nullable String banner) {
        if (banner == null || banner.isEmpty()) {
            return new ServiceInfo.Builder()
                    .service("unknown")
                    .confidence(0)
                    .build();
        }

        for (ServiceSignature sig : signatures) {
            Matcher matcher = sig.pattern.matcher(banner);
            if (matcher.find()) {
                ServiceInfo.Builder builder = new ServiceInfo.Builder()
                        .service(sig.service)
                        .confidence(80);

                if (sig.productGroup >= 0 && sig.productGroup <= matcher.groupCount()) {
                    builder.product(matcher.group(sig.productGroup));
                }
                if (sig.versionGroup >= 0 && sig.versionGroup <= matcher.groupCount()) {
                    builder.version(matcher.group(sig.versionGroup));
                }
                if (sig.osGroup >= 0 && sig.osGroup <= matcher.groupCount()) {
                    builder.os(matcher.group(sig.osGroup));
                }

                return builder.build();
            }
        }

        // No signature matched, return unknown with low confidence
        return new ServiceInfo.Builder()
                .service("unknown")
                .extraInfo(banner.length() > 100 ? banner.substring(0, 100) : banner)
                .confidence(10)
                .build();
    }

    /**
     * Fingerprint a service by port number
     */
    @NonNull
    public ServiceInfo fingerprintByPort(int port) {
        String service = defaultServices.get(port);
        if (service != null) {
            return new ServiceInfo.Builder()
                    .service(service)
                    .confidence(30)
                    .build();
        }
        return new ServiceInfo.Builder()
                .service("unknown")
                .confidence(0)
                .build();
    }

    /**
     * Fingerprint with both banner and port
     */
    @NonNull
    public ServiceInfo fingerprint(@Nullable String banner, int port) {
        if (banner != null && !banner.isEmpty()) {
            ServiceInfo bannerInfo = fingerprint(banner);
            if (bannerInfo.getConfidence() > 50) {
                return bannerInfo;
            }
        }

        ServiceInfo portInfo = fingerprintByPort(port);
        if (banner != null && !banner.isEmpty()) {
            // Merge banner info with port info
            return new ServiceInfo.Builder()
                    .service(portInfo.getService())
                    .extraInfo(banner)
                    .confidence(40)
                    .build();
        }
        return portInfo;
    }

    /**
     * Get default service for a port
     */
    @Nullable
    public String getDefaultService(int port) {
        return defaultServices.get(port);
    }

    /**
     * Check if a service version is known to be vulnerable
     */
    public boolean isKnownVulnerable(@NonNull ServiceInfo info) {
        // Check for some well-known vulnerable versions
        if (info.getProduct() == null || info.getVersion() == null) {
            return false;
        }

        String product = info.getProduct().toLowerCase();
        String version = info.getVersion();

        // OpenSSH versions before 7.4 have known vulnerabilities
        if (product.contains("openssh")) {
            return isVersionLessThan(version, "7.4");
        }

        // Apache versions before 2.4.49 have CVE-2021-41773
        if (product.contains("apache")) {
            return isVersionLessThan(version, "2.4.49");
        }

        // OpenSSL versions before 1.1.1k have vulnerabilities
        if (product.contains("openssl")) {
            return isVersionLessThan(version, "1.1.1k");
        }

        return false;
    }

    /**
     * Get security recommendations for a service
     */
    @NonNull
    public List<String> getSecurityRecommendations(@NonNull ServiceInfo info) {
        List<String> recommendations = new ArrayList<>();
        String service = info.getService();

        if (service == null) {
            return recommendations;
        }

        switch (service.toLowerCase()) {
            case "ftp":
                recommendations.add("Consider using SFTP instead of FTP for encrypted file transfers");
                recommendations.add("If FTP is required, use FTPS (FTP over TLS)");
                break;
            case "telnet":
                recommendations.add("Telnet transmits data in cleartext - use SSH instead");
                recommendations.add("Disable telnet service if not required");
                break;
            case "http":
                recommendations.add("Enable HTTPS to encrypt web traffic");
                recommendations.add("Implement security headers (HSTS, CSP, X-Frame-Options)");
                break;
            case "ssh":
                recommendations.add("Disable root login via SSH");
                recommendations.add("Use key-based authentication instead of passwords");
                recommendations.add("Restrict SSH access by IP if possible");
                break;
            case "mysql":
            case "postgresql":
            case "mongodb":
                recommendations.add("Ensure database is not exposed to public internet");
                recommendations.add("Use strong authentication");
                recommendations.add("Enable SSL/TLS for database connections");
                break;
            case "smtp":
                recommendations.add("Enable STARTTLS for encrypted email transmission");
                recommendations.add("Implement SPF, DKIM, and DMARC");
                break;
            case "rdp":
                recommendations.add("Use NLA (Network Level Authentication)");
                recommendations.add("Limit RDP access through firewall rules");
                recommendations.add("Enable account lockout policies");
                break;
            case "vnc":
                recommendations.add("Use VNC over SSH tunnel");
                recommendations.add("Set strong password");
                recommendations.add("Limit VNC access through firewall");
                break;
        }

        if (isKnownVulnerable(info)) {
            recommendations.add(0, "UPDATE REQUIRED: This version has known vulnerabilities");
        }

        return recommendations;
    }

    // ==================== Initialization ====================

    private void initializeSignatures() {
        // SSH signatures
        signatures.add(new ServiceSignature("ssh",
                "SSH-([0-9.]+)-OpenSSH[_]?([0-9.p]+)(?:\\s+(.+))?", 0, 2, 3));
        signatures.add(new ServiceSignature("ssh",
                "SSH-([0-9.]+)-dropbear[_]?([0-9.]+)?", 0, 2));
        signatures.add(new ServiceSignature("ssh",
                "SSH-([0-9.]+)-(.+)", 0, 2));

        // HTTP signatures
        signatures.add(new ServiceSignature("http",
                "HTTP/([0-9.]+)", 0, 1));
        signatures.add(new ServiceSignature("http",
                "Server:\\s*Apache/([0-9.]+)(?:\\s+\\((.+)\\))?", 1, 1, 2));
        signatures.add(new ServiceSignature("http",
                "Server:\\s*nginx/([0-9.]+)", 1, 1));
        signatures.add(new ServiceSignature("http",
                "Server:\\s*Microsoft-IIS/([0-9.]+)", 1, 1));

        // FTP signatures
        signatures.add(new ServiceSignature("ftp",
                "220.*?vsftpd\\s+([0-9.]+)", 1, 1));
        signatures.add(new ServiceSignature("ftp",
                "220.*?ProFTPD\\s+([0-9.]+)", 1, 1));
        signatures.add(new ServiceSignature("ftp",
                "220.*?FileZilla\\s+Server\\s+([0-9.]+)", 1, 1));
        signatures.add(new ServiceSignature("ftp",
                "220.*?FTP", 0, -1));

        // SMTP signatures
        signatures.add(new ServiceSignature("smtp",
                "220.*?Postfix", 0, -1));
        signatures.add(new ServiceSignature("smtp",
                "220.*?Sendmail\\s+([0-9.]+)", 1, 1));
        signatures.add(new ServiceSignature("smtp",
                "220.*?Microsoft ESMTP", 0, -1));
        signatures.add(new ServiceSignature("smtp",
                "220.*?SMTP", 0, -1));

        // MySQL signatures
        signatures.add(new ServiceSignature("mysql",
                "([0-9.]+)-MariaDB", 1, 1));
        signatures.add(new ServiceSignature("mysql",
                "([0-9.]+)-MySQL", 1, 1));

        // PostgreSQL
        signatures.add(new ServiceSignature("postgresql",
                "PostgreSQL\\s+([0-9.]+)", 1, 1));

        // MongoDB
        signatures.add(new ServiceSignature("mongodb",
                "MongoDB", 0, -1));

        // Redis
        signatures.add(new ServiceSignature("redis",
                "REDIS([0-9.]+)", 0, 1));

        // POP3
        signatures.add(new ServiceSignature("pop3",
                "\\+OK.*?(Dovecot|UW|Courier)", 1, -1));

        // IMAP
        signatures.add(new ServiceSignature("imap",
                "\\* OK.*?(Dovecot|Courier|Microsoft)", 1, -1));

        // DNS
        signatures.add(new ServiceSignature("dns",
                "BIND\\s+([0-9.]+)", 1, 1));

        // SMB
        signatures.add(new ServiceSignature("smb",
                "Samba\\s+([0-9.]+)", 1, 1));
        signatures.add(new ServiceSignature("smb",
                "Windows.*?SMB", 0, -1));

        // RDP
        signatures.add(new ServiceSignature("rdp",
                "\\x03\\x00", 0, -1));

        // VNC
        signatures.add(new ServiceSignature("vnc",
                "RFB\\s+([0-9.]+)", 0, 1));

        // Telnet
        signatures.add(new ServiceSignature("telnet",
                "\\xff\\xfd|\\xff\\xfb|login:", 0, -1));
    }

    private void initializeDefaultServices() {
        defaultServices.put(21, "ftp");
        defaultServices.put(22, "ssh");
        defaultServices.put(23, "telnet");
        defaultServices.put(25, "smtp");
        defaultServices.put(53, "dns");
        defaultServices.put(80, "http");
        defaultServices.put(110, "pop3");
        defaultServices.put(111, "rpc");
        defaultServices.put(135, "msrpc");
        defaultServices.put(139, "netbios");
        defaultServices.put(143, "imap");
        defaultServices.put(443, "https");
        defaultServices.put(445, "smb");
        defaultServices.put(465, "smtps");
        defaultServices.put(587, "submission");
        defaultServices.put(636, "ldaps");
        defaultServices.put(993, "imaps");
        defaultServices.put(995, "pop3s");
        defaultServices.put(1433, "mssql");
        defaultServices.put(1521, "oracle");
        defaultServices.put(3306, "mysql");
        defaultServices.put(3389, "rdp");
        defaultServices.put(5432, "postgresql");
        defaultServices.put(5900, "vnc");
        defaultServices.put(6379, "redis");
        defaultServices.put(8080, "http-proxy");
        defaultServices.put(8443, "https-alt");
        defaultServices.put(9200, "elasticsearch");
        defaultServices.put(27017, "mongodb");
    }

    /**
     * Simple version comparison
     */
    private boolean isVersionLessThan(String version, String compareVersion) {
        try {
            String[] v1 = version.split("[.-]");
            String[] v2 = compareVersion.split("[.-]");

            int maxLen = Math.max(v1.length, v2.length);
            for (int i = 0; i < maxLen; i++) {
                int num1 = i < v1.length ? parseVersionPart(v1[i]) : 0;
                int num2 = i < v2.length ? parseVersionPart(v2[i]) : 0;
                if (num1 < num2) return true;
                if (num1 > num2) return false;
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private int parseVersionPart(String part) {
        try {
            return Integer.parseInt(part.replaceAll("[^0-9]", ""));
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}
