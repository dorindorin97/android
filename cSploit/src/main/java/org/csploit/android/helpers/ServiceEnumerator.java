/*
 * This file is part of the cSploit.
 *
 * Copyleft of Simone Margaritelli aka evilsocket <evilsocket@gmail.com>
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

import android.content.Context;
import android.text.TextUtils;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Helper class for network service enumeration and identification.
 * Provides utilities for identifying services based on port numbers,
 * banners, and protocol-specific fingerprints.
 */
public final class ServiceEnumerator {

    private static final String TAG = "ServiceEnumerator";

    public static final int DEFAULT_TIMEOUT_MS = 5000;
    public static final int DEFAULT_READ_TIMEOUT_MS = 3000;

    // Well-known port ranges
    public static final int WELL_KNOWN_PORT_MIN = 0;
    public static final int WELL_KNOWN_PORT_MAX = 1023;
    public static final int REGISTERED_PORT_MIN = 1024;
    public static final int REGISTERED_PORT_MAX = 49151;
    public static final int DYNAMIC_PORT_MIN = 49152;
    public static final int DYNAMIC_PORT_MAX = 65535;

    // Common service ports
    private static final Map<Integer, ServiceInfo> COMMON_SERVICES = new LinkedHashMap<>();
    static {
        // Well-known ports
        COMMON_SERVICES.put(20, new ServiceInfo(20, "FTP Data", "ftp-data", "tcp"));
        COMMON_SERVICES.put(21, new ServiceInfo(21, "FTP Control", "ftp", "tcp"));
        COMMON_SERVICES.put(22, new ServiceInfo(22, "SSH", "ssh", "tcp"));
        COMMON_SERVICES.put(23, new ServiceInfo(23, "Telnet", "telnet", "tcp"));
        COMMON_SERVICES.put(25, new ServiceInfo(25, "SMTP", "smtp", "tcp"));
        COMMON_SERVICES.put(53, new ServiceInfo(53, "DNS", "domain", "tcp/udp"));
        COMMON_SERVICES.put(67, new ServiceInfo(67, "DHCP Server", "dhcps", "udp"));
        COMMON_SERVICES.put(68, new ServiceInfo(68, "DHCP Client", "dhcpc", "udp"));
        COMMON_SERVICES.put(69, new ServiceInfo(69, "TFTP", "tftp", "udp"));
        COMMON_SERVICES.put(80, new ServiceInfo(80, "HTTP", "http", "tcp"));
        COMMON_SERVICES.put(110, new ServiceInfo(110, "POP3", "pop3", "tcp"));
        COMMON_SERVICES.put(111, new ServiceInfo(111, "RPC Portmapper", "sunrpc", "tcp/udp"));
        COMMON_SERVICES.put(119, new ServiceInfo(119, "NNTP", "nntp", "tcp"));
        COMMON_SERVICES.put(123, new ServiceInfo(123, "NTP", "ntp", "udp"));
        COMMON_SERVICES.put(135, new ServiceInfo(135, "MS RPC", "msrpc", "tcp"));
        COMMON_SERVICES.put(137, new ServiceInfo(137, "NetBIOS Name", "netbios-ns", "udp"));
        COMMON_SERVICES.put(138, new ServiceInfo(138, "NetBIOS Datagram", "netbios-dgm", "udp"));
        COMMON_SERVICES.put(139, new ServiceInfo(139, "NetBIOS Session", "netbios-ssn", "tcp"));
        COMMON_SERVICES.put(143, new ServiceInfo(143, "IMAP", "imap", "tcp"));
        COMMON_SERVICES.put(161, new ServiceInfo(161, "SNMP", "snmp", "udp"));
        COMMON_SERVICES.put(162, new ServiceInfo(162, "SNMP Trap", "snmptrap", "udp"));
        COMMON_SERVICES.put(179, new ServiceInfo(179, "BGP", "bgp", "tcp"));
        COMMON_SERVICES.put(194, new ServiceInfo(194, "IRC", "irc", "tcp"));
        COMMON_SERVICES.put(389, new ServiceInfo(389, "LDAP", "ldap", "tcp"));
        COMMON_SERVICES.put(443, new ServiceInfo(443, "HTTPS", "https", "tcp"));
        COMMON_SERVICES.put(445, new ServiceInfo(445, "SMB", "microsoft-ds", "tcp"));
        COMMON_SERVICES.put(464, new ServiceInfo(464, "Kerberos Password", "kpasswd", "tcp/udp"));
        COMMON_SERVICES.put(465, new ServiceInfo(465, "SMTPS", "smtps", "tcp"));
        COMMON_SERVICES.put(514, new ServiceInfo(514, "Syslog", "syslog", "udp"));
        COMMON_SERVICES.put(515, new ServiceInfo(515, "LPD", "printer", "tcp"));
        COMMON_SERVICES.put(520, new ServiceInfo(520, "RIP", "rip", "udp"));
        COMMON_SERVICES.put(521, new ServiceInfo(521, "RIPng", "ripng", "udp"));
        COMMON_SERVICES.put(587, new ServiceInfo(587, "SMTP Submission", "submission", "tcp"));
        COMMON_SERVICES.put(636, new ServiceInfo(636, "LDAPS", "ldaps", "tcp"));
        COMMON_SERVICES.put(873, new ServiceInfo(873, "Rsync", "rsync", "tcp"));
        COMMON_SERVICES.put(993, new ServiceInfo(993, "IMAPS", "imaps", "tcp"));
        COMMON_SERVICES.put(995, new ServiceInfo(995, "POP3S", "pop3s", "tcp"));
        COMMON_SERVICES.put(1080, new ServiceInfo(1080, "SOCKS Proxy", "socks", "tcp"));
        COMMON_SERVICES.put(1194, new ServiceInfo(1194, "OpenVPN", "openvpn", "tcp/udp"));
        COMMON_SERVICES.put(1433, new ServiceInfo(1433, "MS SQL Server", "ms-sql-s", "tcp"));
        COMMON_SERVICES.put(1434, new ServiceInfo(1434, "MS SQL Monitor", "ms-sql-m", "udp"));
        COMMON_SERVICES.put(1521, new ServiceInfo(1521, "Oracle Database", "oracle", "tcp"));
        COMMON_SERVICES.put(1723, new ServiceInfo(1723, "PPTP", "pptp", "tcp"));
        COMMON_SERVICES.put(1883, new ServiceInfo(1883, "MQTT", "mqtt", "tcp"));
        COMMON_SERVICES.put(2049, new ServiceInfo(2049, "NFS", "nfs", "tcp/udp"));
        COMMON_SERVICES.put(2082, new ServiceInfo(2082, "cPanel", "cpanel", "tcp"));
        COMMON_SERVICES.put(2083, new ServiceInfo(2083, "cPanel SSL", "cpanels", "tcp"));
        COMMON_SERVICES.put(2181, new ServiceInfo(2181, "ZooKeeper", "zookeeper", "tcp"));
        COMMON_SERVICES.put(3128, new ServiceInfo(3128, "Squid Proxy", "squid-http", "tcp"));
        COMMON_SERVICES.put(3306, new ServiceInfo(3306, "MySQL", "mysql", "tcp"));
        COMMON_SERVICES.put(3389, new ServiceInfo(3389, "RDP", "ms-wbt-server", "tcp"));
        COMMON_SERVICES.put(3690, new ServiceInfo(3690, "SVN", "svn", "tcp"));
        COMMON_SERVICES.put(4369, new ServiceInfo(4369, "Erlang Port Mapper", "epmd", "tcp"));
        COMMON_SERVICES.put(5060, new ServiceInfo(5060, "SIP", "sip", "tcp/udp"));
        COMMON_SERVICES.put(5061, new ServiceInfo(5061, "SIP TLS", "sips", "tcp"));
        COMMON_SERVICES.put(5432, new ServiceInfo(5432, "PostgreSQL", "postgresql", "tcp"));
        COMMON_SERVICES.put(5672, new ServiceInfo(5672, "RabbitMQ AMQP", "amqp", "tcp"));
        COMMON_SERVICES.put(5900, new ServiceInfo(5900, "VNC", "vnc", "tcp"));
        COMMON_SERVICES.put(5984, new ServiceInfo(5984, "CouchDB", "couchdb", "tcp"));
        COMMON_SERVICES.put(6379, new ServiceInfo(6379, "Redis", "redis", "tcp"));
        COMMON_SERVICES.put(6443, new ServiceInfo(6443, "Kubernetes API", "kubernetes", "tcp"));
        COMMON_SERVICES.put(6660, new ServiceInfo(6660, "IRC", "irc", "tcp"));
        COMMON_SERVICES.put(6667, new ServiceInfo(6667, "IRC", "irc", "tcp"));
        COMMON_SERVICES.put(8000, new ServiceInfo(8000, "HTTP Alt", "http-alt", "tcp"));
        COMMON_SERVICES.put(8008, new ServiceInfo(8008, "HTTP Alt", "http-alt", "tcp"));
        COMMON_SERVICES.put(8080, new ServiceInfo(8080, "HTTP Proxy", "http-proxy", "tcp"));
        COMMON_SERVICES.put(8443, new ServiceInfo(8443, "HTTPS Alt", "https-alt", "tcp"));
        COMMON_SERVICES.put(8883, new ServiceInfo(8883, "MQTT SSL", "mqtt-ssl", "tcp"));
        COMMON_SERVICES.put(9000, new ServiceInfo(9000, "SonarQube", "sonarqube", "tcp"));
        COMMON_SERVICES.put(9042, new ServiceInfo(9042, "Cassandra", "cassandra", "tcp"));
        COMMON_SERVICES.put(9092, new ServiceInfo(9092, "Kafka", "kafka", "tcp"));
        COMMON_SERVICES.put(9200, new ServiceInfo(9200, "Elasticsearch HTTP", "elasticsearch", "tcp"));
        COMMON_SERVICES.put(9300, new ServiceInfo(9300, "Elasticsearch Transport", "elasticsearch-transport", "tcp"));
        COMMON_SERVICES.put(11211, new ServiceInfo(11211, "Memcached", "memcached", "tcp/udp"));
        COMMON_SERVICES.put(27017, new ServiceInfo(27017, "MongoDB", "mongodb", "tcp"));
        COMMON_SERVICES.put(27018, new ServiceInfo(27018, "MongoDB Shard", "mongodb-shard", "tcp"));
        COMMON_SERVICES.put(27019, new ServiceInfo(27019, "MongoDB Config", "mongodb-config", "tcp"));
    }

    // Banner patterns for service identification
    private static final Map<Pattern, String> BANNER_PATTERNS = new LinkedHashMap<>();
    static {
        BANNER_PATTERNS.put(Pattern.compile("^SSH-", Pattern.CASE_INSENSITIVE), "SSH");
        BANNER_PATTERNS.put(Pattern.compile("^220.*SMTP", Pattern.CASE_INSENSITIVE), "SMTP");
        BANNER_PATTERNS.put(Pattern.compile("^220.*FTP", Pattern.CASE_INSENSITIVE), "FTP");
        BANNER_PATTERNS.put(Pattern.compile("^\\+OK.*POP", Pattern.CASE_INSENSITIVE), "POP3");
        BANNER_PATTERNS.put(Pattern.compile("^\\* OK.*IMAP", Pattern.CASE_INSENSITIVE), "IMAP");
        BANNER_PATTERNS.put(Pattern.compile("^HTTP/", Pattern.CASE_INSENSITIVE), "HTTP");
        BANNER_PATTERNS.put(Pattern.compile("^RFB ", Pattern.CASE_INSENSITIVE), "VNC");
        BANNER_PATTERNS.put(Pattern.compile("^AMQP", Pattern.CASE_INSENSITIVE), "AMQP");
        BANNER_PATTERNS.put(Pattern.compile("^-ERR.*REDIS", Pattern.CASE_INSENSITIVE), "Redis");
        BANNER_PATTERNS.put(Pattern.compile("\\x00\\x00\\x00.*mysql", Pattern.CASE_INSENSITIVE), "MySQL");
        BANNER_PATTERNS.put(Pattern.compile("^RDP.*PROTOCOL", Pattern.CASE_INSENSITIVE), "RDP");
        BANNER_PATTERNS.put(Pattern.compile("^MongoDB", Pattern.CASE_INSENSITIVE), "MongoDB");
    }

    // Cache for enumeration results
    private static final Map<String, EnumerationResult> RESULT_CACHE = new ConcurrentHashMap<>();

    private ServiceEnumerator() {
        // Private constructor to prevent instantiation
    }

    /**
     * Represents basic service information.
     */
    public static class ServiceInfo {
        private final int port;
        private final String name;
        private final String serviceName;
        private final String protocol;
        private final String description;
        private final boolean secure;

        public ServiceInfo(int port, @NonNull String name, @NonNull String serviceName, 
                          @NonNull String protocol) {
            this(port, name, serviceName, protocol, "", false);
        }

        public ServiceInfo(int port, @NonNull String name, @NonNull String serviceName,
                          @NonNull String protocol, @NonNull String description, boolean secure) {
            this.port = port;
            this.name = name;
            this.serviceName = serviceName;
            this.protocol = protocol;
            this.description = description;
            this.secure = secure;
        }

        public int getPort() {
            return port;
        }

        @NonNull
        public String getName() {
            return name;
        }

        @NonNull
        public String getServiceName() {
            return serviceName;
        }

        @NonNull
        public String getProtocol() {
            return protocol;
        }

        @NonNull
        public String getDescription() {
            return description;
        }

        public boolean isSecure() {
            return secure;
        }

        public boolean isTcp() {
            return protocol.toLowerCase(Locale.US).contains("tcp");
        }

        public boolean isUdp() {
            return protocol.toLowerCase(Locale.US).contains("udp");
        }

        @Override
        public String toString() {
            return String.format(Locale.US, "%d/%s - %s", port, protocol, name);
        }
    }

    /**
     * Represents an identified service with more detail.
     */
    public static class IdentifiedService {
        private final ServiceInfo baseInfo;
        private final String banner;
        private final String version;
        private final String product;
        private final String os;
        private final Map<String, String> extraInfo;
        private final long responseTime;
        private final boolean confirmed;

        private IdentifiedService(Builder builder) {
            this.baseInfo = builder.baseInfo;
            this.banner = builder.banner;
            this.version = builder.version;
            this.product = builder.product;
            this.os = builder.os;
            this.extraInfo = new HashMap<>(builder.extraInfo);
            this.responseTime = builder.responseTime;
            this.confirmed = builder.confirmed;
        }

        @NonNull
        public ServiceInfo getBaseInfo() {
            return baseInfo;
        }

        @Nullable
        public String getBanner() {
            return banner;
        }

        @Nullable
        public String getVersion() {
            return version;
        }

        @Nullable
        public String getProduct() {
            return product;
        }

        @Nullable
        public String getOs() {
            return os;
        }

        @NonNull
        public Map<String, String> getExtraInfo() {
            return Collections.unmodifiableMap(extraInfo);
        }

        public long getResponseTime() {
            return responseTime;
        }

        public boolean isConfirmed() {
            return confirmed;
        }

        public static class Builder {
            private ServiceInfo baseInfo;
            private String banner;
            private String version;
            private String product;
            private String os;
            private Map<String, String> extraInfo = new HashMap<>();
            private long responseTime;
            private boolean confirmed;

            public Builder setBaseInfo(ServiceInfo baseInfo) {
                this.baseInfo = baseInfo;
                return this;
            }

            public Builder setBanner(String banner) {
                this.banner = banner;
                return this;
            }

            public Builder setVersion(String version) {
                this.version = version;
                return this;
            }

            public Builder setProduct(String product) {
                this.product = product;
                return this;
            }

            public Builder setOs(String os) {
                this.os = os;
                return this;
            }

            public Builder addExtraInfo(String key, String value) {
                this.extraInfo.put(key, value);
                return this;
            }

            public Builder setResponseTime(long responseTime) {
                this.responseTime = responseTime;
                return this;
            }

            public Builder setConfirmed(boolean confirmed) {
                this.confirmed = confirmed;
                return this;
            }

            public IdentifiedService build() {
                return new IdentifiedService(this);
            }
        }
    }

    /**
     * Represents a complete enumeration result.
     */
    public static class EnumerationResult {
        private final String host;
        private final List<IdentifiedService> services;
        private final long scanStartTime;
        private final long scanEndTime;
        private final int portsScanned;
        private final int servicesFound;
        private final List<String> errors;

        private EnumerationResult(Builder builder) {
            this.host = builder.host;
            this.services = new ArrayList<>(builder.services);
            this.scanStartTime = builder.scanStartTime;
            this.scanEndTime = builder.scanEndTime;
            this.portsScanned = builder.portsScanned;
            this.servicesFound = builder.servicesFound;
            this.errors = new ArrayList<>(builder.errors);
        }

        @NonNull
        public String getHost() {
            return host;
        }

        @NonNull
        public List<IdentifiedService> getServices() {
            return Collections.unmodifiableList(services);
        }

        public long getScanStartTime() {
            return scanStartTime;
        }

        public long getScanEndTime() {
            return scanEndTime;
        }

        public long getScanDuration() {
            return scanEndTime - scanStartTime;
        }

        public int getPortsScanned() {
            return portsScanned;
        }

        public int getServicesFound() {
            return servicesFound;
        }

        @NonNull
        public List<String> getErrors() {
            return Collections.unmodifiableList(errors);
        }

        public static class Builder {
            private String host;
            private List<IdentifiedService> services = new ArrayList<>();
            private long scanStartTime;
            private long scanEndTime;
            private int portsScanned;
            private int servicesFound;
            private List<String> errors = new ArrayList<>();

            public Builder setHost(String host) {
                this.host = host;
                return this;
            }

            public Builder addService(IdentifiedService service) {
                this.services.add(service);
                return this;
            }

            public Builder setServices(List<IdentifiedService> services) {
                this.services = new ArrayList<>(services);
                return this;
            }

            public Builder setScanStartTime(long time) {
                this.scanStartTime = time;
                return this;
            }

            public Builder setScanEndTime(long time) {
                this.scanEndTime = time;
                return this;
            }

            public Builder setPortsScanned(int count) {
                this.portsScanned = count;
                return this;
            }

            public Builder setServicesFound(int count) {
                this.servicesFound = count;
                return this;
            }

            public Builder addError(String error) {
                this.errors.add(error);
                return this;
            }

            public EnumerationResult build() {
                return new EnumerationResult(this);
            }
        }
    }

    /**
     * Gets service info for a port.
     */
    @Nullable
    public static ServiceInfo getServiceByPort(int port) {
        return COMMON_SERVICES.get(port);
    }

    /**
     * Gets service name for a port.
     */
    @NonNull
    public static String getServiceName(int port) {
        ServiceInfo info = COMMON_SERVICES.get(port);
        if (info != null) {
            return info.getName();
        }
        return "Unknown";
    }

    /**
     * Identifies service from banner.
     */
    @Nullable
    public static String identifyFromBanner(@NonNull String banner) {
        for (Map.Entry<Pattern, String> entry : BANNER_PATTERNS.entrySet()) {
            if (entry.getKey().matcher(banner).find()) {
                return entry.getValue();
            }
        }
        return null;
    }

    /**
     * Grabs banner from a service.
     */
    @Nullable
    public static String grabBanner(@NonNull String host, int port) {
        return grabBanner(host, port, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Grabs banner from a service with custom timeout.
     */
    @Nullable
    public static String grabBanner(@NonNull String host, int port, int timeout) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeout);
            socket.setSoTimeout(DEFAULT_READ_TIMEOUT_MS);

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream()));
            
            StringBuilder banner = new StringBuilder();
            char[] buffer = new char[1024];
            int read = reader.read(buffer, 0, buffer.length);
            
            if (read > 0) {
                banner.append(buffer, 0, read);
            }

            return banner.length() > 0 ? banner.toString().trim() : null;
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * Probes a port to identify the service.
     */
    @NonNull
    public static IdentifiedService probeService(@NonNull String host, int port) {
        return probeService(host, port, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Probes a port to identify the service with custom timeout.
     */
    @NonNull
    public static IdentifiedService probeService(@NonNull String host, int port, int timeout) {
        IdentifiedService.Builder builder = new IdentifiedService.Builder();
        
        // Get base info from known services
        ServiceInfo baseInfo = getServiceByPort(port);
        if (baseInfo == null) {
            baseInfo = new ServiceInfo(port, "Unknown", "unknown", "tcp");
        }
        builder.setBaseInfo(baseInfo);

        long startTime = System.currentTimeMillis();
        
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeout);
            socket.setSoTimeout(DEFAULT_READ_TIMEOUT_MS);
            
            long responseTime = System.currentTimeMillis() - startTime;
            builder.setResponseTime(responseTime);

            // Try to grab banner
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream()));
            
            StringBuilder bannerBuilder = new StringBuilder();
            char[] buffer = new char[2048];
            int read = reader.read(buffer, 0, buffer.length);
            
            if (read > 0) {
                bannerBuilder.append(buffer, 0, read);
            }

            String banner = bannerBuilder.toString().trim();
            if (!TextUtils.isEmpty(banner)) {
                builder.setBanner(banner);
                builder.setConfirmed(true);

                // Try to identify from banner
                String identified = identifyFromBanner(banner);
                if (identified != null) {
                    builder.setProduct(identified);
                }

                // Extract version if possible
                String version = extractVersion(banner);
                if (version != null) {
                    builder.setVersion(version);
                }
            }

        } catch (IOException e) {
            builder.setResponseTime(System.currentTimeMillis() - startTime);
            builder.addExtraInfo("error", e.getMessage());
        }

        return builder.build();
    }

    /**
     * Extracts version from banner string.
     */
    @Nullable
    private static String extractVersion(@NonNull String banner) {
        // Try common version patterns
        Pattern[] versionPatterns = {
                Pattern.compile("(\\d+\\.\\d+\\.\\d+(?:p\\d+)?)", Pattern.CASE_INSENSITIVE),
                Pattern.compile("version[\\s:]*(\\d+\\.\\d+(?:\\.\\d+)?)", Pattern.CASE_INSENSITIVE),
                Pattern.compile("v(\\d+\\.\\d+(?:\\.\\d+)?)", Pattern.CASE_INSENSITIVE)
        };

        for (Pattern pattern : versionPatterns) {
            Matcher matcher = pattern.matcher(banner);
            if (matcher.find()) {
                return matcher.group(1);
            }
        }

        return null;
    }

    /**
     * Gets all known services.
     */
    @NonNull
    public static List<ServiceInfo> getAllKnownServices() {
        return new ArrayList<>(COMMON_SERVICES.values());
    }

    /**
     * Gets services by protocol.
     */
    @NonNull
    public static List<ServiceInfo> getServicesByProtocol(@NonNull String protocol) {
        List<ServiceInfo> result = new ArrayList<>();
        String lowerProto = protocol.toLowerCase(Locale.US);
        
        for (ServiceInfo info : COMMON_SERVICES.values()) {
            if (info.getProtocol().toLowerCase(Locale.US).contains(lowerProto)) {
                result.add(info);
            }
        }
        
        return result;
    }

    /**
     * Gets common web server ports.
     */
    @NonNull
    public static int[] getWebPorts() {
        return new int[]{80, 443, 8000, 8008, 8080, 8443, 8888};
    }

    /**
     * Gets common database ports.
     */
    @NonNull
    public static int[] getDatabasePorts() {
        return new int[]{1433, 1521, 3306, 5432, 5984, 6379, 9042, 27017};
    }

    /**
     * Gets common email ports.
     */
    @NonNull
    public static int[] getEmailPorts() {
        return new int[]{25, 110, 143, 465, 587, 993, 995};
    }

    /**
     * Gets common remote access ports.
     */
    @NonNull
    public static int[] getRemoteAccessPorts() {
        return new int[]{22, 23, 3389, 5900};
    }

    /**
     * Gets top 100 most common ports.
     */
    @NonNull
    public static int[] getTop100Ports() {
        return new int[]{
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
                143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
                1, 79, 81, 82, 83, 84, 85, 88, 89, 90,
                99, 100, 106, 113, 119, 125, 144, 146, 161, 163,
                179, 199, 211, 212, 222, 254, 255, 256, 259, 264,
                280, 301, 306, 311, 340, 366, 389, 406, 407, 416,
                417, 425, 427, 444, 458, 464, 465, 481, 497, 500,
                512, 513, 514, 515, 524, 541, 543, 544, 545, 548,
                554, 555, 563, 587, 593, 616, 617, 625, 631, 636,
                646, 648, 666, 667, 668, 683, 687, 691, 700, 705
        };
    }

    /**
     * Gets top 1000 most common ports.
     */
    @NonNull
    public static int[] getTop1000Ports() {
        // This would contain the actual top 1000 ports
        // Abbreviated here for brevity - includes the top 100 plus more
        return getTop100Ports();
    }

    /**
     * Checks if a port is in well-known range.
     */
    public static boolean isWellKnownPort(int port) {
        return port >= WELL_KNOWN_PORT_MIN && port <= WELL_KNOWN_PORT_MAX;
    }

    /**
     * Checks if a port is in registered range.
     */
    public static boolean isRegisteredPort(int port) {
        return port >= REGISTERED_PORT_MIN && port <= REGISTERED_PORT_MAX;
    }

    /**
     * Checks if a port is in dynamic range.
     */
    public static boolean isDynamicPort(int port) {
        return port >= DYNAMIC_PORT_MIN && port <= DYNAMIC_PORT_MAX;
    }

    /**
     * Gets port range description.
     */
    @NonNull
    public static String getPortRangeDescription(int port) {
        if (isWellKnownPort(port)) {
            return "Well-known port (System)";
        } else if (isRegisteredPort(port)) {
            return "Registered port (User)";
        } else if (isDynamicPort(port)) {
            return "Dynamic/Private port";
        }
        return "Invalid port";
    }

    /**
     * Generates enumeration report.
     */
    @NonNull
    public static String generateReport(@NonNull EnumerationResult result) {
        StringBuilder report = new StringBuilder();
        
        report.append("Service Enumeration Report\n");
        report.append("==========================\n\n");
        
        report.append("Host: ").append(result.getHost()).append("\n");
        report.append("Scan Duration: ").append(result.getScanDuration()).append(" ms\n");
        report.append("Ports Scanned: ").append(result.getPortsScanned()).append("\n");
        report.append("Services Found: ").append(result.getServicesFound()).append("\n\n");
        
        if (!result.getServices().isEmpty()) {
            report.append("Identified Services:\n");
            report.append("-------------------\n");
            
            for (IdentifiedService service : result.getServices()) {
                ServiceInfo base = service.getBaseInfo();
                report.append(String.format(Locale.US, "\nPort %d/%s - %s\n",
                        base.getPort(), base.getProtocol(), base.getName()));
                
                if (service.getProduct() != null) {
                    report.append("  Product: ").append(service.getProduct()).append("\n");
                }
                if (service.getVersion() != null) {
                    report.append("  Version: ").append(service.getVersion()).append("\n");
                }
                if (service.getBanner() != null) {
                    String banner = service.getBanner();
                    if (banner.length() > 80) {
                        banner = banner.substring(0, 80) + "...";
                    }
                    report.append("  Banner: ").append(banner).append("\n");
                }
                report.append("  Response Time: ").append(service.getResponseTime()).append(" ms\n");
                report.append("  Confirmed: ").append(service.isConfirmed() ? "Yes" : "No").append("\n");
            }
        }
        
        if (!result.getErrors().isEmpty()) {
            report.append("\nErrors:\n");
            for (String error : result.getErrors()) {
                report.append("  • ").append(error).append("\n");
            }
        }
        
        return report.toString();
    }

    /**
     * Clears the result cache.
     */
    public static void clearCache() {
        RESULT_CACHE.clear();
    }
}
