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

import android.content.Context;
import android.os.Build;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * SecurityAuditHelper - Comprehensive security auditing utilities.
 * 
 * Provides:
 * - Network security checks
 * - Host vulnerability scanning
 * - Configuration auditing
 * - Security score calculation
 * 
 * Usage:
 * {@code
 * // Run network audit
 * AuditReport report = SecurityAuditHelper.auditNetwork("192.168.1.0/24");
 * 
 * // Check host security
 * HostAudit hostAudit = SecurityAuditHelper.auditHost("192.168.1.1");
 * 
 * // Get security score
 * int score = report.getSecurityScore();
 * }
 */
public final class SecurityAuditHelper {
    
    private static final String TAG = "SecurityAuditHelper";
    
    /**
     * Severity levels for findings.
     */
    public enum Severity {
        CRITICAL(4),
        HIGH(3),
        MEDIUM(2),
        LOW(1),
        INFO(0);
        
        public final int level;
        
        Severity(int level) {
            this.level = level;
        }
    }
    
    /**
     * Finding categories.
     */
    public enum Category {
        NETWORK,
        AUTHENTICATION,
        ENCRYPTION,
        SERVICE,
        CONFIGURATION,
        ACCESS_CONTROL,
        OUTDATED_SOFTWARE,
        MISCONFIGURATION
    }
    
    /**
     * Single security finding.
     */
    public static class Finding {
        public String id;
        public String title;
        public String description;
        public Severity severity;
        public Category category;
        public String host;
        public int port;
        public String remediation;
        public String cvssScore;
        public List<String> references;
        public long timestamp;
        
        public Finding(@NonNull String title, @NonNull Severity severity) {
            this.title = title;
            this.severity = severity;
            this.references = new ArrayList<>();
            this.timestamp = java.lang.System.currentTimeMillis();
            this.id = generateFindingId();
        }
        
        private String generateFindingId() {
            return "SA-" + java.lang.System.currentTimeMillis() % 100000;
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("[%s] %s: %s", severity.name(), category != null ? category.name() : "GENERAL", title);
        }
    }
    
    /**
     * Host audit result.
     */
    public static class HostAudit {
        public String host;
        public List<Integer> openPorts;
        public List<String> runningServices;
        public List<Finding> findings;
        public int securityScore;
        public long auditTime;
        public Map<String, Object> metadata;
        
        public HostAudit(@NonNull String host) {
            this.host = host;
            this.openPorts = new ArrayList<>();
            this.runningServices = new ArrayList<>();
            this.findings = new ArrayList<>();
            this.metadata = new HashMap<>();
            this.auditTime = java.lang.System.currentTimeMillis();
        }
        
        public void addFinding(@NonNull Finding finding) {
            finding.host = this.host;
            findings.add(finding);
        }
        
        public int getCriticalCount() {
            return (int) findings.stream().filter(f -> f.severity == Severity.CRITICAL).count();
        }
        
        public int getHighCount() {
            return (int) findings.stream().filter(f -> f.severity == Severity.HIGH).count();
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("HostAudit{host='%s', findings=%d, score=%d}", 
                    host, findings.size(), securityScore);
        }
    }
    
    /**
     * Full audit report.
     */
    public static class AuditReport {
        public String name;
        public String target;
        public long startTime;
        public long endTime;
        public List<HostAudit> hostAudits;
        public List<Finding> networkFindings;
        public int overallScore;
        public Map<Severity, Integer> findingsBySeverity;
        public Map<Category, Integer> findingsByCategory;
        
        public AuditReport(@NonNull String name, @NonNull String target) {
            this.name = name;
            this.target = target;
            this.startTime = java.lang.System.currentTimeMillis();
            this.hostAudits = new ArrayList<>();
            this.networkFindings = new ArrayList<>();
            this.findingsBySeverity = new HashMap<>();
            this.findingsByCategory = new HashMap<>();
        }
        
        public void complete() {
            this.endTime = java.lang.System.currentTimeMillis();
            calculateStatistics();
        }
        
        private void calculateStatistics() {
            for (Severity s : Severity.values()) {
                findingsBySeverity.put(s, 0);
            }
            for (Category c : Category.values()) {
                findingsByCategory.put(c, 0);
            }
            
            // Count host findings
            for (HostAudit audit : hostAudits) {
                for (Finding f : audit.findings) {
                    findingsBySeverity.merge(f.severity, 1, Integer::sum);
                    if (f.category != null) {
                        findingsByCategory.merge(f.category, 1, Integer::sum);
                    }
                }
            }
            
            // Count network findings
            for (Finding f : networkFindings) {
                findingsBySeverity.merge(f.severity, 1, Integer::sum);
                if (f.category != null) {
                    findingsByCategory.merge(f.category, 1, Integer::sum);
                }
            }
            
            // Calculate score
            overallScore = calculateSecurityScore();
        }
        
        private int calculateSecurityScore() {
            // Start with 100, deduct points based on findings
            int score = 100;
            
            score -= findingsBySeverity.getOrDefault(Severity.CRITICAL, 0) * 20;
            score -= findingsBySeverity.getOrDefault(Severity.HIGH, 0) * 10;
            score -= findingsBySeverity.getOrDefault(Severity.MEDIUM, 0) * 5;
            score -= findingsBySeverity.getOrDefault(Severity.LOW, 0) * 2;
            
            return Math.max(0, Math.min(100, score));
        }
        
        public int getTotalFindings() {
            int total = networkFindings.size();
            for (HostAudit audit : hostAudits) {
                total += audit.findings.size();
            }
            return total;
        }
        
        public long getDurationMs() {
            return endTime - startTime;
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("AuditReport{name='%s', hosts=%d, findings=%d, score=%d}",
                    name, hostAudits.size(), getTotalFindings(), overallScore);
        }
    }
    
    private SecurityAuditHelper() {}
    
    /**
     * Perform host security audit.
     */
    @NonNull
    public static HostAudit auditHost(@NonNull String host) {
        return auditHost(host, null);
    }
    
    /**
     * Audit host with specific ports.
     */
    @NonNull
    public static HostAudit auditHost(@NonNull String host, @Nullable int[] ports) {
        HostAudit audit = new HostAudit(host);
        
        // Determine ports to scan
        int[] portsToScan = ports != null ? ports : PortHelper.getCommonPorts();
        
        // Scan ports
        for (int port : portsToScan) {
            if (PortHelper.isPortOpen(host, port, 1000)) {
                audit.openPorts.add(port);
                audit.runningServices.add(PortHelper.getServiceName(port));
                
                // Check for security issues per service
                checkServiceSecurity(audit, port);
            }
        }
        
        // Check for insecure services
        checkInsecureServices(audit);
        
        // Calculate security score
        audit.securityScore = calculateHostScore(audit);
        
        return audit;
    }
    
    /**
     * Check security of a specific service.
     */
    private static void checkServiceSecurity(@NonNull HostAudit audit, int port) {
        switch (port) {
            case 21: // FTP
                Finding ftpFinding = new Finding("FTP Service Detected", Severity.MEDIUM);
                ftpFinding.category = Category.SERVICE;
                ftpFinding.port = port;
                ftpFinding.description = "FTP transmits credentials in plain text.";
                ftpFinding.remediation = "Consider using SFTP or FTPS instead.";
                audit.addFinding(ftpFinding);
                break;
                
            case 23: // Telnet
                Finding telnetFinding = new Finding("Telnet Service Detected", Severity.HIGH);
                telnetFinding.category = Category.SERVICE;
                telnetFinding.port = port;
                telnetFinding.description = "Telnet transmits all data including credentials in plain text.";
                telnetFinding.remediation = "Replace Telnet with SSH for secure remote access.";
                audit.addFinding(telnetFinding);
                break;
                
            case 80: // HTTP
                Finding httpFinding = new Finding("Unencrypted HTTP Service", Severity.LOW);
                httpFinding.category = Category.ENCRYPTION;
                httpFinding.port = port;
                httpFinding.description = "HTTP traffic is unencrypted and can be intercepted.";
                httpFinding.remediation = "Consider implementing HTTPS with TLS.";
                audit.addFinding(httpFinding);
                break;
                
            case 110: // POP3
                Finding pop3Finding = new Finding("Unencrypted POP3 Service", Severity.MEDIUM);
                pop3Finding.category = Category.ENCRYPTION;
                pop3Finding.port = port;
                pop3Finding.description = "POP3 transmits email credentials in plain text.";
                pop3Finding.remediation = "Use POP3S (port 995) for encrypted email retrieval.";
                audit.addFinding(pop3Finding);
                break;
                
            case 143: // IMAP
                Finding imapFinding = new Finding("Unencrypted IMAP Service", Severity.MEDIUM);
                imapFinding.category = Category.ENCRYPTION;
                imapFinding.port = port;
                imapFinding.description = "IMAP transmits email credentials in plain text.";
                imapFinding.remediation = "Use IMAPS (port 993) for encrypted email access.";
                audit.addFinding(imapFinding);
                break;
                
            case 161: // SNMP
                Finding snmpFinding = new Finding("SNMP Service Detected", Severity.MEDIUM);
                snmpFinding.category = Category.CONFIGURATION;
                snmpFinding.port = port;
                snmpFinding.description = "SNMP can expose sensitive network information if misconfigured.";
                snmpFinding.remediation = "Use SNMPv3 with authentication and encryption. Change default community strings.";
                audit.addFinding(snmpFinding);
                break;
                
            case 445: // SMB
                Finding smbFinding = new Finding("SMB Service Detected", Severity.MEDIUM);
                smbFinding.category = Category.SERVICE;
                smbFinding.port = port;
                smbFinding.description = "SMB has been associated with various vulnerabilities (e.g., EternalBlue).";
                smbFinding.remediation = "Ensure SMBv1 is disabled and system is patched.";
                audit.addFinding(smbFinding);
                break;
                
            case 1433: // MSSQL
            case 3306: // MySQL
            case 5432: // PostgreSQL
            case 27017: // MongoDB
                Finding dbFinding = new Finding("Database Port Exposed", Severity.HIGH);
                dbFinding.category = Category.ACCESS_CONTROL;
                dbFinding.port = port;
                dbFinding.description = "Database service is accessible from the network.";
                dbFinding.remediation = "Restrict database access to application servers only. Use firewall rules.";
                audit.addFinding(dbFinding);
                break;
                
            case 3389: // RDP
                Finding rdpFinding = new Finding("RDP Service Exposed", Severity.HIGH);
                rdpFinding.category = Category.ACCESS_CONTROL;
                rdpFinding.port = port;
                rdpFinding.description = "Remote Desktop Protocol is accessible from the network.";
                rdpFinding.remediation = "Use VPN for RDP access. Enable Network Level Authentication.";
                audit.addFinding(rdpFinding);
                break;
                
            case 5900: // VNC
            case 5901:
                Finding vncFinding = new Finding("VNC Service Detected", Severity.HIGH);
                vncFinding.category = Category.ACCESS_CONTROL;
                vncFinding.port = port;
                vncFinding.description = "VNC often uses weak authentication and unencrypted connections.";
                vncFinding.remediation = "Use SSH tunneling for VNC. Implement strong authentication.";
                audit.addFinding(vncFinding);
                break;
        }
    }
    
    /**
     * Check for insecure service combinations.
     */
    private static void checkInsecureServices(@NonNull HostAudit audit) {
        List<Integer> openPorts = audit.openPorts;
        
        // Check if secure alternatives are missing
        if (openPorts.contains(80) && !openPorts.contains(443)) {
            Finding finding = new Finding("HTTPS Not Configured", Severity.MEDIUM);
            finding.category = Category.ENCRYPTION;
            finding.description = "HTTP is available but HTTPS is not configured.";
            finding.remediation = "Configure HTTPS with a valid TLS certificate.";
            audit.addFinding(finding);
        }
        
        // Check for multiple admin interfaces
        List<Integer> adminPorts = new ArrayList<>();
        int[] knownAdminPorts = {22, 23, 2082, 2083, 2086, 2087, 3389, 5900, 8080, 9090};
        for (int port : knownAdminPorts) {
            if (openPorts.contains(port)) {
                adminPorts.add(port);
            }
        }
        
        if (adminPorts.size() > 3) {
            Finding finding = new Finding("Multiple Admin Interfaces Exposed", Severity.MEDIUM);
            finding.category = Category.ACCESS_CONTROL;
            finding.description = "Multiple administrative interfaces are accessible: " + adminPorts;
            finding.remediation = "Consolidate admin access through a single secure interface.";
            audit.addFinding(finding);
        }
        
        // Too many open ports
        if (openPorts.size() > 20) {
            Finding finding = new Finding("Excessive Open Ports", Severity.LOW);
            finding.category = Category.CONFIGURATION;
            finding.description = openPorts.size() + " ports are open on this host.";
            finding.remediation = "Review and close unnecessary ports. Apply principle of least privilege.";
            audit.addFinding(finding);
        }
    }
    
    /**
     * Calculate host security score.
     */
    private static int calculateHostScore(@NonNull HostAudit audit) {
        int score = 100;
        
        for (Finding f : audit.findings) {
            switch (f.severity) {
                case CRITICAL:
                    score -= 25;
                    break;
                case HIGH:
                    score -= 15;
                    break;
                case MEDIUM:
                    score -= 8;
                    break;
                case LOW:
                    score -= 3;
                    break;
                case INFO:
                    score -= 1;
                    break;
            }
        }
        
        return Math.max(0, Math.min(100, score));
    }
    
    /**
     * Create a comprehensive audit report.
     */
    @NonNull
    public static AuditReport createReport(@NonNull String name, @NonNull String target) {
        return new AuditReport(name, target);
    }
    
    /**
     * Get severity color for UI.
     */
    public static int getSeverityColor(@NonNull Severity severity) {
        switch (severity) {
            case CRITICAL:
                return 0xFFD32F2F; // Red
            case HIGH:
                return 0xFFF57C00; // Orange
            case MEDIUM:
                return 0xFFFFA000; // Amber
            case LOW:
                return 0xFF1976D2; // Blue
            case INFO:
                return 0xFF757575; // Grey
            default:
                return 0xFF000000; // Black
        }
    }
    
    /**
     * Get security score rating.
     */
    @NonNull
    public static String getScoreRating(int score) {
        if (score >= 90) return "Excellent";
        if (score >= 75) return "Good";
        if (score >= 60) return "Fair";
        if (score >= 40) return "Poor";
        return "Critical";
    }
    
    /**
     * Get security score color.
     */
    public static int getScoreColor(int score) {
        if (score >= 90) return 0xFF4CAF50; // Green
        if (score >= 75) return 0xFF8BC34A; // Light Green
        if (score >= 60) return 0xFFFFC107; // Yellow
        if (score >= 40) return 0xFFFF9800; // Orange
        return 0xFFF44336; // Red
    }
}
