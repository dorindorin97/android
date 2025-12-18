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
 * SecurityAssessmentHelper - Comprehensive security assessment utilities.
 *
 * Provides:
 * - Security risk scoring
 * - Vulnerability categorization
 * - Security posture assessment
 * - Compliance checking
 * - Risk prioritization
 *
 * Usage:
 * {@code
 * // Assess target security
 * SecurityAssessment assessment = SecurityAssessmentHelper.assessTarget(target);
 *
 * // Get risk score
 * int riskScore = assessment.getRiskScore();
 *
 * // Get recommendations
 * List<String> recommendations = assessment.getRecommendations();
 * }
 */
public final class SecurityAssessmentHelper {

    private static final String TAG = "SecurityAssessmentHelper";

    // Risk score weights
    private static final int WEIGHT_OPEN_PORTS = 10;
    private static final int WEIGHT_VULNERABLE_SERVICE = 25;
    private static final int WEIGHT_OUTDATED_SOFTWARE = 15;
    private static final int WEIGHT_WEAK_CONFIG = 20;
    private static final int WEIGHT_MISSING_ENCRYPTION = 30;

    // Common high-risk ports
    private static final int[] HIGH_RISK_PORTS = {
        21,    // FTP
        22,    // SSH
        23,    // Telnet
        25,    // SMTP
        53,    // DNS
        110,   // POP3
        135,   // MS-RPC
        139,   // NetBIOS
        143,   // IMAP
        445,   // SMB
        1433,  // MSSQL
        1521,  // Oracle
        3306,  // MySQL
        3389,  // RDP
        5432,  // PostgreSQL
        5900,  // VNC
        6379,  // Redis
        8080,  // HTTP Proxy
        27017  // MongoDB
    };

    /**
     * Security assessment result.
     */
    public static class SecurityAssessment {
        private final String targetId;
        private final long timestamp;
        private int riskScore;
        private RiskLevel riskLevel;
        private final List<SecurityFinding> findings;
        private final List<String> recommendations;
        private final Map<String, Object> metadata;

        public SecurityAssessment(@NonNull String targetId) {
            this.targetId = targetId;
            this.timestamp = System.currentTimeMillis();
            this.findings = new ArrayList<>();
            this.recommendations = new ArrayList<>();
            this.metadata = new HashMap<>();
            this.riskScore = 0;
            this.riskLevel = RiskLevel.LOW;
        }

        public String getTargetId() { return targetId; }
        public long getTimestamp() { return timestamp; }
        public int getRiskScore() { return riskScore; }
        public RiskLevel getRiskLevel() { return riskLevel; }
        public List<SecurityFinding> getFindings() { return Collections.unmodifiableList(findings); }
        public List<String> getRecommendations() { return Collections.unmodifiableList(recommendations); }
        public Map<String, Object> getMetadata() { return Collections.unmodifiableMap(metadata); }

        public void addFinding(@NonNull SecurityFinding finding) {
            findings.add(finding);
            riskScore += finding.getSeverity().getScore();
            updateRiskLevel();
        }

        public void addRecommendation(@NonNull String recommendation) {
            recommendations.add(recommendation);
        }

        public void setMetadata(@NonNull String key, @Nullable Object value) {
            metadata.put(key, value);
        }

        private void updateRiskLevel() {
            if (riskScore >= 80) {
                riskLevel = RiskLevel.CRITICAL;
            } else if (riskScore >= 60) {
                riskLevel = RiskLevel.HIGH;
            } else if (riskScore >= 40) {
                riskLevel = RiskLevel.MEDIUM;
            } else if (riskScore >= 20) {
                riskLevel = RiskLevel.LOW;
            } else {
                riskLevel = RiskLevel.INFO;
            }
        }

        @NonNull
        @Override
        public String toString() {
            return String.format("SecurityAssessment{target='%s', score=%d, level=%s, findings=%d}",
                    targetId, riskScore, riskLevel, findings.size());
        }
    }

    /**
     * Security finding detail.
     */
    public static class SecurityFinding {
        private final String id;
        private final String title;
        private final String description;
        private final Severity severity;
        private final Category category;
        private final String remediation;
        private final Map<String, String> evidence;

        public SecurityFinding(
                @NonNull String id,
                @NonNull String title,
                @NonNull String description,
                @NonNull Severity severity,
                @NonNull Category category,
                @Nullable String remediation) {
            this.id = id;
            this.title = title;
            this.description = description;
            this.severity = severity;
            this.category = category;
            this.remediation = remediation;
            this.evidence = new HashMap<>();
        }

        public String getId() { return id; }
        public String getTitle() { return title; }
        public String getDescription() { return description; }
        public Severity getSeverity() { return severity; }
        public Category getCategory() { return category; }
        public String getRemediation() { return remediation; }
        public Map<String, String> getEvidence() { return evidence; }

        public void addEvidence(@NonNull String key, @NonNull String value) {
            evidence.put(key, value);
        }

        @NonNull
        @Override
        public String toString() {
            return String.format("[%s] %s - %s", severity, id, title);
        }
    }

    /**
     * Severity levels.
     */
    public enum Severity {
        CRITICAL(40),
        HIGH(25),
        MEDIUM(15),
        LOW(5),
        INFO(0);

        private final int score;

        Severity(int score) {
            this.score = score;
        }

        public int getScore() { return score; }
    }

    /**
     * Risk level classification.
     */
    public enum RiskLevel {
        CRITICAL,
        HIGH,
        MEDIUM,
        LOW,
        INFO
    }

    /**
     * Finding categories.
     */
    public enum Category {
        NETWORK_EXPOSURE,
        VULNERABLE_SERVICE,
        CONFIGURATION_ISSUE,
        AUTHENTICATION_WEAKNESS,
        ENCRYPTION_ISSUE,
        ACCESS_CONTROL,
        INFORMATION_DISCLOSURE,
        OTHER
    }

    private SecurityAssessmentHelper() {}

    /**
     * Assess open ports for security risks.
     */
    @NonNull
    public static SecurityAssessment assessOpenPorts(@NonNull String targetId, @NonNull List<Integer> openPorts) {
        SecurityAssessment assessment = new SecurityAssessment(targetId);
        assessment.setMetadata("openPortCount", openPorts.size());

        for (int port : openPorts) {
            if (isHighRiskPort(port)) {
                SecurityFinding finding = new SecurityFinding(
                        "HIGH_RISK_PORT_" + port,
                        "High-Risk Port Open: " + port,
                        getPortDescription(port) + " port is open and may be vulnerable to attacks.",
                        Severity.MEDIUM,
                        Category.NETWORK_EXPOSURE,
                        "Consider closing this port or implementing strict access controls."
                );
                finding.addEvidence("port", String.valueOf(port));
                finding.addEvidence("service", getServiceName(port));
                assessment.addFinding(finding);
            }
        }

        // Check for excessive open ports
        if (openPorts.size() > 10) {
            assessment.addFinding(new SecurityFinding(
                    "EXCESSIVE_OPEN_PORTS",
                    "Excessive Open Ports Detected",
                    openPorts.size() + " open ports found. Large attack surface.",
                    Severity.LOW,
                    Category.NETWORK_EXPOSURE,
                    "Review and close unnecessary ports."
            ));
        }

        // Add recommendations
        if (!assessment.getFindings().isEmpty()) {
            assessment.addRecommendation("Review all open ports and close unnecessary services");
            assessment.addRecommendation("Implement firewall rules to restrict access");
            assessment.addRecommendation("Use network segmentation to limit exposure");
        }

        return assessment;
    }

    /**
     * Assess service security.
     */
    @NonNull
    public static SecurityAssessment assessService(@NonNull String targetId, @NonNull String serviceName, @Nullable String version) {
        SecurityAssessment assessment = new SecurityAssessment(targetId);

        // Check for known vulnerable services
        if (isVulnerableService(serviceName, version)) {
            assessment.addFinding(new SecurityFinding(
                    "VULNERABLE_SERVICE",
                    "Potentially Vulnerable Service",
                    "Service " + serviceName + (version != null ? " v" + version : "") + " may have known vulnerabilities.",
                    Severity.HIGH,
                    Category.VULNERABLE_SERVICE,
                    "Update to the latest version or apply security patches."
            ));
        }

        // Check for unencrypted services
        if (isUnencryptedService(serviceName)) {
            assessment.addFinding(new SecurityFinding(
                    "UNENCRYPTED_SERVICE",
                    "Unencrypted Service",
                    serviceName + " transmits data in cleartext.",
                    Severity.MEDIUM,
                    Category.ENCRYPTION_ISSUE,
                    "Use encrypted alternative (e.g., FTPS/SFTP instead of FTP, HTTPS instead of HTTP)."
            ));
        }

        return assessment;
    }

    /**
     * Calculate overall risk score.
     */
    public static int calculateRiskScore(@NonNull List<SecurityFinding> findings) {
        int score = 0;
        for (SecurityFinding finding : findings) {
            score += finding.getSeverity().getScore();
        }
        return Math.min(score, 100);
    }

    /**
     * Get risk level from score.
     */
    @NonNull
    public static RiskLevel getRiskLevel(int score) {
        if (score >= 80) return RiskLevel.CRITICAL;
        if (score >= 60) return RiskLevel.HIGH;
        if (score >= 40) return RiskLevel.MEDIUM;
        if (score >= 20) return RiskLevel.LOW;
        return RiskLevel.INFO;
    }

    /**
     * Check if port is high-risk.
     */
    public static boolean isHighRiskPort(int port) {
        for (int highRiskPort : HIGH_RISK_PORTS) {
            if (port == highRiskPort) return true;
        }
        return false;
    }

    /**
     * Get port description.
     */
    @NonNull
    public static String getPortDescription(int port) {
        switch (port) {
            case 21: return "FTP (File Transfer Protocol)";
            case 22: return "SSH (Secure Shell)";
            case 23: return "Telnet";
            case 25: return "SMTP (Simple Mail Transfer Protocol)";
            case 53: return "DNS (Domain Name System)";
            case 80: return "HTTP";
            case 110: return "POP3 (Post Office Protocol)";
            case 135: return "MS-RPC";
            case 139: return "NetBIOS Session Service";
            case 143: return "IMAP";
            case 443: return "HTTPS";
            case 445: return "SMB (Server Message Block)";
            case 1433: return "Microsoft SQL Server";
            case 1521: return "Oracle Database";
            case 3306: return "MySQL";
            case 3389: return "Remote Desktop Protocol";
            case 5432: return "PostgreSQL";
            case 5900: return "VNC";
            case 6379: return "Redis";
            case 8080: return "HTTP Proxy/Alternate";
            case 27017: return "MongoDB";
            default: return "Unknown Service";
        }
    }

    /**
     * Get service name for port.
     */
    @NonNull
    public static String getServiceName(int port) {
        switch (port) {
            case 21: return "ftp";
            case 22: return "ssh";
            case 23: return "telnet";
            case 25: return "smtp";
            case 53: return "dns";
            case 80: return "http";
            case 110: return "pop3";
            case 135: return "msrpc";
            case 139: return "netbios";
            case 143: return "imap";
            case 443: return "https";
            case 445: return "smb";
            case 1433: return "mssql";
            case 1521: return "oracle";
            case 3306: return "mysql";
            case 3389: return "rdp";
            case 5432: return "postgresql";
            case 5900: return "vnc";
            case 6379: return "redis";
            case 8080: return "http-proxy";
            case 27017: return "mongodb";
            default: return "unknown";
        }
    }

    /**
     * Check if service is potentially vulnerable.
     */
    public static boolean isVulnerableService(@NonNull String serviceName, @Nullable String version) {
        String service = serviceName.toLowerCase();

        // Known historically vulnerable services
        if (service.contains("telnet") ||
            service.contains("ftp") ||
            service.contains("rsh") ||
            service.contains("rlogin")) {
            return true;
        }

        // Check for old versions (simplified check)
        if (version != null && !version.isEmpty()) {
            try {
                String[] parts = version.split("\\.");
                int major = Integer.parseInt(parts[0]);

                // Example checks for old versions
                if (service.contains("ssh") && major < 2) return true;
                if (service.contains("apache") && major < 2) return true;
                if (service.contains("nginx") && major < 1) return true;
                if (service.contains("openssl") && major < 1) return true;
            } catch (Exception e) {
                // Ignore parsing errors
            }
        }

        return false;
    }

    /**
     * Check if service uses unencrypted communication.
     */
    public static boolean isUnencryptedService(@NonNull String serviceName) {
        String service = serviceName.toLowerCase();
        return service.contains("telnet") ||
               service.contains("ftp") && !service.contains("ftps") && !service.contains("sftp") ||
               service.equals("http") ||
               service.contains("pop3") && !service.contains("pop3s") ||
               service.contains("imap") && !service.contains("imaps") ||
               service.contains("smtp") && !service.contains("smtps");
    }

    /**
     * Generate security report summary.
     */
    @NonNull
    public static String generateSummary(@NonNull SecurityAssessment assessment) {
        StringBuilder sb = new StringBuilder();

        sb.append("=== Security Assessment Report ===\n");
        sb.append("Target: ").append(assessment.getTargetId()).append("\n");
        sb.append("Timestamp: ").append(new java.util.Date(assessment.getTimestamp())).append("\n");
        sb.append("Risk Score: ").append(assessment.getRiskScore()).append("/100\n");
        sb.append("Risk Level: ").append(assessment.getRiskLevel()).append("\n\n");

        sb.append("--- Findings (").append(assessment.getFindings().size()).append(") ---\n");
        for (SecurityFinding finding : assessment.getFindings()) {
            sb.append("  [").append(finding.getSeverity()).append("] ");
            sb.append(finding.getTitle()).append("\n");
            sb.append("    ").append(finding.getDescription()).append("\n");
            if (finding.getRemediation() != null) {
                sb.append("    Fix: ").append(finding.getRemediation()).append("\n");
            }
        }

        sb.append("\n--- Recommendations ---\n");
        for (String rec : assessment.getRecommendations()) {
            sb.append("  • ").append(rec).append("\n");
        }

        return sb.toString();
    }

    /**
     * Merge multiple assessments.
     */
    @NonNull
    public static SecurityAssessment mergeAssessments(@NonNull String targetId, @NonNull List<SecurityAssessment> assessments) {
        SecurityAssessment merged = new SecurityAssessment(targetId);

        for (SecurityAssessment assessment : assessments) {
            for (SecurityFinding finding : assessment.getFindings()) {
                merged.addFinding(finding);
            }
            for (String rec : assessment.getRecommendations()) {
                if (!merged.getRecommendations().contains(rec)) {
                    merged.addRecommendation(rec);
                }
            }
            for (Map.Entry<String, Object> entry : assessment.getMetadata().entrySet()) {
                merged.setMetadata(entry.getKey(), entry.getValue());
            }
        }

        return merged;
    }

    /**
     * Quick port scan for security assessment.
     */
    @NonNull
    public static List<Integer> quickScan(@NonNull String host, int timeoutMs) {
        List<Integer> openPorts = Collections.synchronizedList(new ArrayList<>());
        ExecutorService executor = Executors.newFixedThreadPool(20);
        List<Future<?>> futures = new ArrayList<>();

        for (int port : HIGH_RISK_PORTS) {
            futures.add(executor.submit(() -> {
                try (Socket socket = new Socket()) {
                    socket.connect(new InetSocketAddress(host, port), timeoutMs);
                    openPorts.add(port);
                } catch (Exception e) {
                    // Port closed or filtered
                }
            }));
        }

        // Wait for completion
        for (Future<?> future : futures) {
            try {
                future.get(timeoutMs * 2L, TimeUnit.MILLISECONDS);
            } catch (Exception e) {
                // Timeout or error
            }
        }

        executor.shutdown();
        Collections.sort(openPorts);
        return openPorts;
    }

    /**
     * Get security grade (A-F) from risk score.
     */
    @NonNull
    public static String getSecurityGrade(int riskScore) {
        if (riskScore <= 10) return "A+";
        if (riskScore <= 20) return "A";
        if (riskScore <= 30) return "B+";
        if (riskScore <= 40) return "B";
        if (riskScore <= 50) return "C+";
        if (riskScore <= 60) return "C";
        if (riskScore <= 70) return "D";
        return "F";
    }

    /**
     * Create finding for common security issues.
     */
    @NonNull
    public static SecurityFinding createFinding(
            @NonNull String id,
            @NonNull String title,
            @NonNull String description,
            @NonNull Severity severity,
            @NonNull Category category) {
        return new SecurityFinding(id, title, description, severity, category, null);
    }
}
