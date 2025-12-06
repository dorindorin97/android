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
import java.util.regex.Pattern;

/**
 * ServiceDatabase - Database of common network services and their characteristics.
 * 
 * Provides:
 * - Service name lookup by port
 * - Default ports for common services
 * - Service categorization
 * - Security risk assessment
 * - Protocol information
 * 
 * Usage:
 * {@code
 * // Get service info
 * ServiceInfo info = ServiceDatabase.getService(22);
 * String name = info.getName(); // "SSH"
 * String risk = info.getRiskLevel(); // "Low"
 * 
 * // Get all web services ports
 * List<Integer> webPorts = ServiceDatabase.getPortsByCategory(Category.WEB);
 * }
 */
public final class ServiceDatabase {
    
    public static final String TAG = "ServiceDatabase";
    
    // Service categories
    public enum Category {
        WEB("Web Services"),
        DATABASE("Database"),
        MAIL("Email"),
        FILE_TRANSFER("File Transfer"),
        REMOTE_ACCESS("Remote Access"),
        NETWORK("Network Services"),
        SECURITY("Security"),
        MESSAGING("Messaging"),
        MEDIA("Media"),
        IOT("IoT/Embedded"),
        GAMING("Gaming"),
        OTHER("Other");
        
        private final String displayName;
        
        Category(String displayName) {
            this.displayName = displayName;
        }
        
        public String getDisplayName() {
            return displayName;
        }
    }
    
    // Risk levels
    public enum RiskLevel {
        CRITICAL("Critical", 5),
        HIGH("High", 4),
        MEDIUM("Medium", 3),
        LOW("Low", 2),
        INFO("Informational", 1);
        
        private final String name;
        private final int severity;
        
        RiskLevel(String name, int severity) {
            this.name = name;
            this.severity = severity;
        }
        
        public String getName() {
            return name;
        }
        
        public int getSeverity() {
            return severity;
        }
    }
    
    /**
     * Service information.
     */
    public static class ServiceInfo {
        public final int port;
        public final String name;
        public final String description;
        public final String protocol;
        public final Category category;
        public final RiskLevel riskLevel;
        public final boolean encrypted;
        public final String[] commonVulnerabilities;
        
        private ServiceInfo(int port, String name, String description, String protocol,
                           Category category, RiskLevel riskLevel, boolean encrypted,
                           String[] commonVulnerabilities) {
            this.port = port;
            this.name = name;
            this.description = description;
            this.protocol = protocol;
            this.category = category;
            this.riskLevel = riskLevel;
            this.encrypted = encrypted;
            this.commonVulnerabilities = commonVulnerabilities;
        }
        
        public String getName() {
            return name;
        }
        
        public RiskLevel getRiskLevel() {
            return riskLevel;
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("%d/%s (%s) - %s", port, protocol, name, description);
        }
    }
    
    // Service database
    private static final Map<Integer, ServiceInfo> services = new HashMap<>();
    private static final Map<Category, List<Integer>> categoryPorts = new HashMap<>();
    
    static {
        // Initialize category lists
        for (Category cat : Category.values()) {
            categoryPorts.put(cat, new ArrayList<>());
        }
        
        // Web Services
        addService(80, "HTTP", "Hypertext Transfer Protocol", "tcp", Category.WEB, RiskLevel.MEDIUM, false,
                new String[]{"Directory traversal", "XSS", "SQL injection"});
        addService(443, "HTTPS", "HTTP Secure", "tcp", Category.WEB, RiskLevel.LOW, true,
                new String[]{"SSL/TLS vulnerabilities", "Certificate issues"});
        addService(8080, "HTTP-Alt", "Alternative HTTP", "tcp", Category.WEB, RiskLevel.MEDIUM, false,
                new String[]{"Proxy vulnerabilities", "Unprotected admin panels"});
        addService(8443, "HTTPS-Alt", "Alternative HTTPS", "tcp", Category.WEB, RiskLevel.LOW, true,
                new String[]{"Certificate issues"});
        addService(8000, "HTTP-Alt", "Alternative HTTP port", "tcp", Category.WEB, RiskLevel.MEDIUM, false, null);
        addService(8888, "HTTP-Alt", "Alternative HTTP port", "tcp", Category.WEB, RiskLevel.MEDIUM, false, null);
        
        // Remote Access
        addService(22, "SSH", "Secure Shell", "tcp", Category.REMOTE_ACCESS, RiskLevel.LOW, true,
                new String[]{"Weak credentials", "Key vulnerabilities"});
        addService(23, "Telnet", "Telnet Protocol", "tcp", Category.REMOTE_ACCESS, RiskLevel.CRITICAL, false,
                new String[]{"Cleartext credentials", "No encryption"});
        addService(3389, "RDP", "Remote Desktop Protocol", "tcp", Category.REMOTE_ACCESS, RiskLevel.HIGH, false,
                new String[]{"BlueKeep", "Weak authentication"});
        addService(5900, "VNC", "Virtual Network Computing", "tcp", Category.REMOTE_ACCESS, RiskLevel.HIGH, false,
                new String[]{"Weak authentication", "Unencrypted by default"});
        addService(5901, "VNC-1", "VNC display 1", "tcp", Category.REMOTE_ACCESS, RiskLevel.HIGH, false, null);
        addService(5902, "VNC-2", "VNC display 2", "tcp", Category.REMOTE_ACCESS, RiskLevel.HIGH, false, null);
        
        // Database
        addService(3306, "MySQL", "MySQL Database", "tcp", Category.DATABASE, RiskLevel.HIGH, false,
                new String[]{"Default credentials", "SQL injection"});
        addService(5432, "PostgreSQL", "PostgreSQL Database", "tcp", Category.DATABASE, RiskLevel.HIGH, false,
                new String[]{"Default credentials", "SQL injection"});
        addService(1433, "MSSQL", "Microsoft SQL Server", "tcp", Category.DATABASE, RiskLevel.HIGH, false,
                new String[]{"SA account", "xp_cmdshell"});
        addService(1521, "Oracle", "Oracle Database", "tcp", Category.DATABASE, RiskLevel.HIGH, false,
                new String[]{"Default credentials", "TNS listener"});
        addService(27017, "MongoDB", "MongoDB Database", "tcp", Category.DATABASE, RiskLevel.CRITICAL, false,
                new String[]{"No authentication default", "Exposed to internet"});
        addService(6379, "Redis", "Redis Key-Value Store", "tcp", Category.DATABASE, RiskLevel.CRITICAL, false,
                new String[]{"No authentication default", "Remote code execution"});
        addService(9200, "Elasticsearch", "Elasticsearch", "tcp", Category.DATABASE, RiskLevel.HIGH, false,
                new String[]{"No authentication", "Script injection"});
        addService(5984, "CouchDB", "Apache CouchDB", "tcp", Category.DATABASE, RiskLevel.HIGH, false, null);
        addService(11211, "Memcached", "Memcached", "tcp", Category.DATABASE, RiskLevel.MEDIUM, false,
                new String[]{"Amplification attacks"});
        
        // File Transfer
        addService(21, "FTP", "File Transfer Protocol", "tcp", Category.FILE_TRANSFER, RiskLevel.HIGH, false,
                new String[]{"Anonymous access", "Cleartext credentials"});
        addService(22, "SFTP", "SSH File Transfer", "tcp", Category.FILE_TRANSFER, RiskLevel.LOW, true, null);
        addService(69, "TFTP", "Trivial File Transfer", "udp", Category.FILE_TRANSFER, RiskLevel.HIGH, false,
                new String[]{"No authentication"});
        addService(139, "NetBIOS", "NetBIOS Session", "tcp", Category.FILE_TRANSFER, RiskLevel.HIGH, false,
                new String[]{"Null sessions", "Information disclosure"});
        addService(445, "SMB", "Server Message Block", "tcp", Category.FILE_TRANSFER, RiskLevel.CRITICAL, false,
                new String[]{"EternalBlue", "Null sessions", "SMBGhost"});
        addService(2049, "NFS", "Network File System", "tcp", Category.FILE_TRANSFER, RiskLevel.HIGH, false,
                new String[]{"Misconfigured exports"});
        
        // Email
        addService(25, "SMTP", "Simple Mail Transfer", "tcp", Category.MAIL, RiskLevel.MEDIUM, false,
                new String[]{"Open relay", "User enumeration"});
        addService(110, "POP3", "Post Office Protocol", "tcp", Category.MAIL, RiskLevel.MEDIUM, false,
                new String[]{"Cleartext credentials"});
        addService(143, "IMAP", "Internet Message Access", "tcp", Category.MAIL, RiskLevel.MEDIUM, false,
                new String[]{"Cleartext credentials"});
        addService(465, "SMTPS", "SMTP Secure", "tcp", Category.MAIL, RiskLevel.LOW, true, null);
        addService(587, "Submission", "Mail Submission", "tcp", Category.MAIL, RiskLevel.LOW, false, null);
        addService(993, "IMAPS", "IMAP Secure", "tcp", Category.MAIL, RiskLevel.LOW, true, null);
        addService(995, "POP3S", "POP3 Secure", "tcp", Category.MAIL, RiskLevel.LOW, true, null);
        
        // Network Services
        addService(53, "DNS", "Domain Name System", "udp", Category.NETWORK, RiskLevel.MEDIUM, false,
                new String[]{"Zone transfer", "Cache poisoning"});
        addService(67, "DHCP", "Dynamic Host Config", "udp", Category.NETWORK, RiskLevel.MEDIUM, false,
                new String[]{"Rogue DHCP"});
        addService(68, "DHCP", "DHCP Client", "udp", Category.NETWORK, RiskLevel.LOW, false, null);
        addService(123, "NTP", "Network Time Protocol", "udp", Category.NETWORK, RiskLevel.LOW, false,
                new String[]{"Amplification attacks"});
        addService(161, "SNMP", "Simple Network Management", "udp", Category.NETWORK, RiskLevel.HIGH, false,
                new String[]{"Default community strings", "Information disclosure"});
        addService(162, "SNMP-Trap", "SNMP Trap", "udp", Category.NETWORK, RiskLevel.MEDIUM, false, null);
        addService(389, "LDAP", "Lightweight Directory Access", "tcp", Category.NETWORK, RiskLevel.HIGH, false,
                new String[]{"Anonymous bind", "LDAP injection"});
        addService(636, "LDAPS", "LDAP Secure", "tcp", Category.NETWORK, RiskLevel.MEDIUM, true, null);
        addService(1900, "SSDP", "Simple Service Discovery", "udp", Category.NETWORK, RiskLevel.MEDIUM, false,
                new String[]{"UPnP vulnerabilities"});
        
        // Security
        addService(88, "Kerberos", "Kerberos Authentication", "tcp", Category.SECURITY, RiskLevel.MEDIUM, false,
                new String[]{"Kerberoasting", "AS-REP roasting"});
        addService(464, "Kpasswd", "Kerberos Password Change", "tcp", Category.SECURITY, RiskLevel.MEDIUM, false, null);
        addService(749, "Kerberos-Admin", "Kerberos Admin", "tcp", Category.SECURITY, RiskLevel.MEDIUM, false, null);
        
        // Messaging
        addService(5222, "XMPP", "XMPP Client", "tcp", Category.MESSAGING, RiskLevel.LOW, false, null);
        addService(5269, "XMPP-Server", "XMPP Server", "tcp", Category.MESSAGING, RiskLevel.LOW, false, null);
        addService(1883, "MQTT", "Message Queue Telemetry", "tcp", Category.MESSAGING, RiskLevel.MEDIUM, false,
                new String[]{"No authentication default"});
        addService(8883, "MQTT-TLS", "MQTT over TLS", "tcp", Category.MESSAGING, RiskLevel.LOW, true, null);
        addService(5672, "AMQP", "Advanced Message Queuing", "tcp", Category.MESSAGING, RiskLevel.MEDIUM, false, null);
        
        // Media
        addService(554, "RTSP", "Real Time Streaming", "tcp", Category.MEDIA, RiskLevel.MEDIUM, false,
                new String[]{"Unauth access", "Default credentials"});
        addService(1935, "RTMP", "Real Time Messaging", "tcp", Category.MEDIA, RiskLevel.LOW, false, null);
        
        // Printer
        addService(515, "LPD", "Line Printer Daemon", "tcp", Category.OTHER, RiskLevel.MEDIUM, false, null);
        addService(631, "IPP", "Internet Printing Protocol", "tcp", Category.OTHER, RiskLevel.MEDIUM, false,
                new String[]{"PRET vulnerabilities"});
        addService(9100, "JetDirect", "HP JetDirect", "tcp", Category.OTHER, RiskLevel.MEDIUM, false,
                new String[]{"PJL/PostScript attacks"});
        
        // Other common ports
        addService(111, "RPC", "Remote Procedure Call", "tcp", Category.NETWORK, RiskLevel.HIGH, false,
                new String[]{"NFS enumeration"});
        addService(135, "MSRPC", "Microsoft RPC", "tcp", Category.NETWORK, RiskLevel.HIGH, false,
                new String[]{"DCOM vulnerabilities"});
        addService(1723, "PPTP", "Point-to-Point Tunneling", "tcp", Category.REMOTE_ACCESS, RiskLevel.HIGH, false,
                new String[]{"Weak encryption"});
        addService(5060, "SIP", "Session Initiation Protocol", "udp", Category.MESSAGING, RiskLevel.MEDIUM, false,
                new String[]{"VoIP attacks"});
        
        // IoT
        addService(502, "Modbus", "Modbus Protocol", "tcp", Category.IOT, RiskLevel.CRITICAL, false,
                new String[]{"No authentication"});
        addService(1911, "Niagara", "Tridium Niagara Fox", "tcp", Category.IOT, RiskLevel.HIGH, false, null);
        addService(47808, "BACnet", "Building Automation", "udp", Category.IOT, RiskLevel.HIGH, false, null);
    }
    
    private static void addService(int port, String name, String description, String protocol,
                                   Category category, RiskLevel riskLevel, boolean encrypted,
                                   String[] vulnerabilities) {
        ServiceInfo info = new ServiceInfo(port, name, description, protocol, category, 
                riskLevel, encrypted, vulnerabilities);
        services.put(port, info);
        categoryPorts.get(category).add(port);
    }
    
    private ServiceDatabase() {}
    
    /**
     * Get service information by port.
     * 
     * @param port port number
     * @return service info or null if unknown
     */
    @Nullable
    public static ServiceInfo getService(int port) {
        return services.get(port);
    }
    
    /**
     * Get service name by port.
     * 
     * @param port port number
     * @return service name or "Unknown"
     */
    @NonNull
    public static String getServiceName(int port) {
        ServiceInfo info = services.get(port);
        return info != null ? info.name : "Unknown";
    }
    
    /**
     * Get all ports for a category.
     * 
     * @param category service category
     * @return list of port numbers
     */
    @NonNull
    public static List<Integer> getPortsByCategory(@NonNull Category category) {
        List<Integer> ports = categoryPorts.get(category);
        return ports != null ? new ArrayList<>(ports) : Collections.emptyList();
    }
    
    /**
     * Get all high-risk ports.
     * 
     * @return list of high-risk port numbers
     */
    @NonNull
    public static List<Integer> getHighRiskPorts() {
        List<Integer> highRisk = new ArrayList<>();
        for (ServiceInfo info : services.values()) {
            if (info.riskLevel.severity >= RiskLevel.HIGH.severity) {
                highRisk.add(info.port);
            }
        }
        return highRisk;
    }
    
    /**
     * Get all critical-risk ports.
     * 
     * @return list of critical-risk port numbers
     */
    @NonNull
    public static List<Integer> getCriticalRiskPorts() {
        List<Integer> critical = new ArrayList<>();
        for (ServiceInfo info : services.values()) {
            if (info.riskLevel == RiskLevel.CRITICAL) {
                critical.add(info.port);
            }
        }
        return critical;
    }
    
    /**
     * Check if a port has a known service.
     * 
     * @param port port number
     * @return true if service is known
     */
    public static boolean isKnownPort(int port) {
        return services.containsKey(port);
    }
    
    /**
     * Get risk assessment for open ports.
     * 
     * @param openPorts list of open port numbers
     * @return map of risk level to ports
     */
    @NonNull
    public static Map<RiskLevel, List<Integer>> assessRisk(@NonNull List<Integer> openPorts) {
        Map<RiskLevel, List<Integer>> assessment = new HashMap<>();
        for (RiskLevel level : RiskLevel.values()) {
            assessment.put(level, new ArrayList<>());
        }
        
        for (int port : openPorts) {
            ServiceInfo info = services.get(port);
            RiskLevel risk = info != null ? info.riskLevel : RiskLevel.INFO;
            assessment.get(risk).add(port);
        }
        
        return assessment;
    }
    
    /**
     * Get highest risk level from open ports.
     * 
     * @param openPorts list of open port numbers
     * @return highest risk level found
     */
    @NonNull
    public static RiskLevel getHighestRisk(@NonNull List<Integer> openPorts) {
        RiskLevel highest = RiskLevel.INFO;
        
        for (int port : openPorts) {
            ServiceInfo info = services.get(port);
            if (info != null && info.riskLevel.severity > highest.severity) {
                highest = info.riskLevel;
            }
        }
        
        return highest;
    }
    
    /**
     * Get all services.
     * 
     * @return unmodifiable map of all services
     */
    @NonNull
    public static Map<Integer, ServiceInfo> getAllServices() {
        return Collections.unmodifiableMap(services);
    }
    
    /**
     * Get common vulnerabilities for a port.
     * 
     * @param port port number
     * @return array of vulnerability descriptions or empty array
     */
    @NonNull
    public static String[] getVulnerabilities(int port) {
        ServiceInfo info = services.get(port);
        if (info != null && info.commonVulnerabilities != null) {
            return info.commonVulnerabilities;
        }
        return new String[0];
    }
    
    /**
     * Search services by name.
     * 
     * @param query search query (case-insensitive)
     * @return list of matching services
     */
    @NonNull
    public static List<ServiceInfo> searchByName(@NonNull String query) {
        List<ServiceInfo> results = new ArrayList<>();
        String lowerQuery = query.toLowerCase();
        
        for (ServiceInfo info : services.values()) {
            if (info.name.toLowerCase().contains(lowerQuery) ||
                info.description.toLowerCase().contains(lowerQuery)) {
                results.add(info);
            }
        }
        
        return results;
    }
}
