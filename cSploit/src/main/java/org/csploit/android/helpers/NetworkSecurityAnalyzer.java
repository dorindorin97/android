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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * NetworkSecurityAnalyzer - Comprehensive network security assessment.
 *
 * Provides:
 * - Host security posture assessment
 * - Service vulnerability analysis
 * - Network configuration analysis
 * - Risk scoring
 * - Security recommendations
 *
 * Usage:
 * {@code
 * // Analyze single host
 * SecurityAssessment assessment = NetworkSecurityAnalyzer.analyzeHost("192.168.1.1");
 *
 * // Get security recommendations
 * List<Recommendation> recs = NetworkSecurityAnalyzer.getRecommendations(assessment);
 *
 * // Network-wide analysis
 * NetworkSecurityReport report = NetworkSecurityAnalyzer.analyzeNetwork("192.168.1.0/24");
 * }
 */
public final class NetworkSecurityAnalyzer {

    private static final String TAG = "NetworkSecurityAnalyzer";
    private static final int DEFAULT_TIMEOUT = 3000;

    /**
     * Risk severity levels.
     */
    public enum RiskLevel {
        CRITICAL(100, "Critical"),
        HIGH(75, "High"),
        MEDIUM(50, "Medium"),
        LOW(25, "Low"),
        INFO(0, "Informational");

        public final int score;
        public final String label;

        RiskLevel(int score, String label) {
            this.score = score;
            this.label = label;
        }
    }

    /**
     * Security finding.
     */
    public static class SecurityFinding {
        public RiskLevel riskLevel;
        public String category;
        public String title;
        public String description;
        public String remediation;
        public String affectedService;
        public int port;

        public SecurityFinding(RiskLevel risk, String category, String title) {
            this.riskLevel = risk;
            this.category = category;
            this.title = title;
        }

        @NonNull
        @Override
        public String toString() {
            return String.format("[%s] %s: %s", riskLevel.label, category, title);
        }
    }

    /**
     * Host security assessment result.
     */
    public static class SecurityAssessment {
        public String hostAddress;
        public String hostname;
        public List<ServiceInfo> services = new ArrayList<>();
        public List<SecurityFinding> findings = new ArrayList<>();
        public int riskScore; // 0-100
        public String riskRating;
        public int openPortCount;
        public int criticalFindings;
        public int highFindings;
        public int mediumFindings;
        public int lowFindings;
        public long assessmentTimeMs;

        @NonNull
        @Override
        public String toString() {
            return String.format("Assessment{host='%s', score=%d, rating='%s', findings=%d}",
                    hostAddress, riskScore, riskRating, findings.size());
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
        public boolean isEncrypted;
        public boolean hasKnownVulns;
        public List<String> vulnerabilities = new ArrayList<>();

        @NonNull
        @Override
        public String toString() {
            return String.format("%d/%s - %s %s", port, protocol, serviceName, version);
        }
    }

    /**
     * Security recommendation.
     */
    public static class Recommendation {
        public RiskLevel priority;
        public String title;
        public String description;
        public String steps;

        public Recommendation(RiskLevel priority, String title, String description) {
            this.priority = priority;
            this.title = title;
            this.description = description;
        }

        @NonNull
        @Override
        public String toString() {
            return String.format("[%s] %s", priority.label, title);
        }
    }

    /**
     * Network-wide security report.
     */
    public static class NetworkSecurityReport {
        public String networkCidr;
        public int totalHosts;
        public int aliveHosts;
        public Map<String, SecurityAssessment> hostAssessments = new HashMap<>();
        public List<SecurityFinding> aggregatedFindings = new ArrayList<>();
        public int overallRiskScore;
        public String overallRiskRating;
        public long scanTimeMs;

        @NonNull
        @Override
        public String toString() {
            return String.format("NetworkReport{network='%s', hosts=%d, score=%d}",
                    networkCidr, aliveHosts, overallRiskScore);
        }
    }

    // Well-known dangerous/risky ports
    private static final Map<Integer, String> RISKY_PORTS = new HashMap<>();

    static {
        RISKY_PORTS.put(23, "Telnet (unencrypted)");
        RISKY_PORTS.put(21, "FTP (unencrypted control)");
        RISKY_PORTS.put(25, "SMTP (potentially open relay)");
        RISKY_PORTS.put(69, "TFTP (no auth)");
        RISKY_PORTS.put(111, "RPCBind (information leak)");
        RISKY_PORTS.put(135, "MSRPC (Windows attacks)");
        RISKY_PORTS.put(139, "NetBIOS (legacy SMB)");
        RISKY_PORTS.put(445, "SMB (ransomware target)");
        RISKY_PORTS.put(512, "rexec (legacy)");
        RISKY_PORTS.put(513, "rlogin (legacy)");
        RISKY_PORTS.put(514, "rsh (legacy)");
        RISKY_PORTS.put(1433, "MSSQL (database exposure)");
        RISKY_PORTS.put(1521, "Oracle (database exposure)");
        RISKY_PORTS.put(3306, "MySQL (database exposure)");
        RISKY_PORTS.put(3389, "RDP (brute force target)");
        RISKY_PORTS.put(5432, "PostgreSQL (database exposure)");
        RISKY_PORTS.put(5900, "VNC (screen sharing)");
        RISKY_PORTS.put(6379, "Redis (default no auth)");
        RISKY_PORTS.put(27017, "MongoDB (default no auth)");
    }

    private NetworkSecurityAnalyzer() {}

    /**
     * Analyze security posture of a single host.
     */
    @NonNull
    public static SecurityAssessment analyzeHost(@NonNull String host) {
        return analyzeHost(host, getCommonPorts());
    }

    /**
     * Analyze host with custom port list.
     */
    @NonNull
    public static SecurityAssessment analyzeHost(@NonNull String host, @NonNull int[] ports) {
        SecurityAssessment assessment = new SecurityAssessment();
        assessment.hostAddress = host;
        long startTime = System.currentTimeMillis();

        // Try to resolve hostname
        try {
            InetAddress addr = InetAddress.getByName(host);
            String hostname = addr.getHostName();
            if (!hostname.equals(host)) {
                assessment.hostname = hostname;
            }
        } catch (Exception e) {
            Log.d(TAG, "Failed to resolve hostname for " + host, e);
        }

        // Scan ports and gather service information
        for (int port : ports) {
            ServiceInfo service = probeService(host, port);
            if (service != null) {
                assessment.services.add(service);
                assessment.openPortCount++;

                // Generate findings based on service
                generateServiceFindings(service, assessment.findings);
            }
        }

        // Analyze overall host security
        analyzeHostSecurity(assessment);

        // Calculate risk score
        calculateRiskScore(assessment);

        assessment.assessmentTimeMs = System.currentTimeMillis() - startTime;
        return assessment;
    }

    /**
     * Probe a single service.
     */
    @Nullable
    private static ServiceInfo probeService(@NonNull String host, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), DEFAULT_TIMEOUT);
            socket.setSoTimeout(DEFAULT_TIMEOUT);

            ServiceInfo info = new ServiceInfo();
            info.port = port;
            info.protocol = "tcp";

            // Get banner
            String banner = BannerGrabber.grabBanner(host, port);
            if (banner != null) {
                info.banner = banner;

                // Detect service from banner
                BannerGrabber.ServiceInfo serviceInfo = BannerGrabber.detectService(host, port);
                info.serviceName = serviceInfo.serviceName;
                info.version = serviceInfo.version;
            } else {
                info.serviceName = guessServiceByPort(port);
            }

            // Check if encrypted
            info.isEncrypted = isEncryptedPort(port);

            // Check for known vulnerabilities
            if (info.serviceName != null && info.version != null) {
                List<ServiceVersionHelper.VulnerabilityRange> vulns =
                        ServiceVersionHelper.checkKnownVulnerabilities(info.serviceName, info.version);
                info.hasKnownVulns = !vulns.isEmpty();
                for (ServiceVersionHelper.VulnerabilityRange v : vulns) {
                    info.vulnerabilities.add(v.cveId + ": " + v.description);
                }
            }

            return info;

        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Generate security findings for a service.
     */
    private static void generateServiceFindings(@NonNull ServiceInfo service,
                                                  @NonNull List<SecurityFinding> findings) {
        // Check for risky ports
        if (RISKY_PORTS.containsKey(service.port)) {
            SecurityFinding finding = new SecurityFinding(
                    RiskLevel.MEDIUM,
                    "Risky Service",
                    "Potentially risky service exposed: " + RISKY_PORTS.get(service.port)
            );
            finding.port = service.port;
            finding.affectedService = service.serviceName;
            finding.description = "Port " + service.port + " is commonly targeted by attackers";
            finding.remediation = "Consider disabling or restricting access to this service";
            findings.add(finding);
        }

        // Check for unencrypted services
        if (!service.isEncrypted && isCredentialService(service.port)) {
            SecurityFinding finding = new SecurityFinding(
                    RiskLevel.HIGH,
                    "Unencrypted Authentication",
                    "Credentials may be transmitted in plaintext"
            );
            finding.port = service.port;
            finding.affectedService = service.serviceName;
            finding.description = "Service on port " + service.port + " does not use encryption";
            finding.remediation = "Use encrypted alternatives (SSH instead of Telnet, SFTP instead of FTP)";
            findings.add(finding);
        }

        // Check for known vulnerabilities
        if (service.hasKnownVulns) {
            for (String vuln : service.vulnerabilities) {
                SecurityFinding finding = new SecurityFinding(
                        RiskLevel.CRITICAL,
                        "Known Vulnerability",
                        vuln
                );
                finding.port = service.port;
                finding.affectedService = service.serviceName;
                finding.remediation = "Update " + service.serviceName + " to the latest version";
                findings.add(finding);
            }
        }

        // Check for version disclosure
        if (service.version != null && !service.version.isEmpty()) {
            SecurityFinding finding = new SecurityFinding(
                    RiskLevel.LOW,
                    "Version Disclosure",
                    "Service reveals version: " + service.serviceName + " " + service.version
            );
            finding.port = service.port;
            finding.affectedService = service.serviceName;
            finding.description = "Version information can help attackers identify vulnerabilities";
            finding.remediation = "Configure service to hide version information in banners";
            findings.add(finding);
        }
    }

    /**
     * Analyze overall host security.
     */
    private static void analyzeHostSecurity(@NonNull SecurityAssessment assessment) {
        // Check for too many open ports
        if (assessment.openPortCount > 10) {
            SecurityFinding finding = new SecurityFinding(
                    RiskLevel.MEDIUM,
                    "Large Attack Surface",
                    "Host has " + assessment.openPortCount + " open ports"
            );
            finding.description = "Many open ports increase the attack surface";
            finding.remediation = "Close unnecessary services and ports";
            assessment.findings.add(finding);
        }

        // Check for database exposure
        Set<Integer> dbPorts = new HashSet<>();
        dbPorts.add(1433);
        dbPorts.add(1521);
        dbPorts.add(3306);
        dbPorts.add(5432);
        dbPorts.add(27017);
        dbPorts.add(6379);

        for (ServiceInfo service : assessment.services) {
            if (dbPorts.contains(service.port)) {
                SecurityFinding finding = new SecurityFinding(
                        RiskLevel.HIGH,
                        "Database Exposure",
                        "Database service exposed: " + service.serviceName
                );
                finding.port = service.port;
                finding.description = "Direct database access should not be exposed to the network";
                finding.remediation = "Use firewall rules to restrict database access";
                assessment.findings.add(finding);
            }
        }
    }

    /**
     * Calculate risk score for assessment.
     */
    private static void calculateRiskScore(@NonNull SecurityAssessment assessment) {
        int totalScore = 0;

        for (SecurityFinding finding : assessment.findings) {
            totalScore += finding.riskLevel.score;

            switch (finding.riskLevel) {
                case CRITICAL:
                    assessment.criticalFindings++;
                    break;
                case HIGH:
                    assessment.highFindings++;
                    break;
                case MEDIUM:
                    assessment.mediumFindings++;
                    break;
                case LOW:
                    assessment.lowFindings++;
                    break;
            }
        }

        // Normalize to 0-100
        int maxPossibleScore = assessment.findings.size() * 100;
        if (maxPossibleScore > 0) {
            assessment.riskScore = Math.min(100, (totalScore * 100) / maxPossibleScore);
        }

        // Determine rating
        if (assessment.criticalFindings > 0 || assessment.riskScore >= 75) {
            assessment.riskRating = "Critical";
        } else if (assessment.highFindings > 0 || assessment.riskScore >= 50) {
            assessment.riskRating = "High";
        } else if (assessment.mediumFindings > 0 || assessment.riskScore >= 25) {
            assessment.riskRating = "Medium";
        } else if (assessment.lowFindings > 0) {
            assessment.riskRating = "Low";
        } else {
            assessment.riskRating = "Minimal";
        }
    }

    /**
     * Generate recommendations based on assessment.
     */
    @NonNull
    public static List<Recommendation> getRecommendations(@NonNull SecurityAssessment assessment) {
        List<Recommendation> recommendations = new ArrayList<>();

        // Prioritize by critical findings
        if (assessment.criticalFindings > 0) {
            recommendations.add(new Recommendation(
                    RiskLevel.CRITICAL,
                    "Address Critical Vulnerabilities Immediately",
                    "There are " + assessment.criticalFindings + " critical vulnerabilities that require immediate attention"
            ));
        }

        // Check for unpatched services
        for (ServiceInfo service : assessment.services) {
            if (service.hasKnownVulns) {
                Recommendation rec = new Recommendation(
                        RiskLevel.CRITICAL,
                        "Update " + service.serviceName,
                        "Service has known vulnerabilities that should be patched"
                );
                rec.steps = "1. Check current version\n2. Review changelog\n3. Plan update window\n4. Apply update\n5. Verify functionality";
                recommendations.add(rec);
            }
        }

        // General recommendations
        if (assessment.openPortCount > 5) {
            recommendations.add(new Recommendation(
                    RiskLevel.MEDIUM,
                    "Reduce Attack Surface",
                    "Consider closing unnecessary ports and services"
            ));
        }

        return recommendations;
    }

    /**
     * Check if port typically uses encrypted transport.
     */
    private static boolean isEncryptedPort(int port) {
        switch (port) {
            case 22:   // SSH
            case 443:  // HTTPS
            case 465:  // SMTPS
            case 587:  // SMTP with STARTTLS
            case 636:  // LDAPS
            case 853:  // DNS over TLS
            case 989:  // FTPS data
            case 990:  // FTPS control
            case 993:  // IMAPS
            case 995:  // POP3S
            case 8443: // HTTPS alt
                return true;
            default:
                return false;
        }
    }

    /**
     * Check if port handles credentials.
     */
    private static boolean isCredentialService(int port) {
        switch (port) {
            case 21:   // FTP
            case 23:   // Telnet
            case 25:   // SMTP
            case 110:  // POP3
            case 143:  // IMAP
            case 513:  // rlogin
            case 514:  // rsh
            case 3389: // RDP
            case 5900: // VNC
                return true;
            default:
                return false;
        }
    }

    /**
     * Guess service name by port.
     */
    @NonNull
    private static String guessServiceByPort(int port) {
        switch (port) {
            case 21: return "FTP";
            case 22: return "SSH";
            case 23: return "Telnet";
            case 25: return "SMTP";
            case 53: return "DNS";
            case 80: return "HTTP";
            case 110: return "POP3";
            case 143: return "IMAP";
            case 443: return "HTTPS";
            case 445: return "SMB";
            case 3306: return "MySQL";
            case 3389: return "RDP";
            case 5432: return "PostgreSQL";
            case 8080: return "HTTP-Proxy";
            default: return "unknown";
        }
    }

    /**
     * Get common ports for scanning.
     */
    @NonNull
    public static int[] getCommonPorts() {
        return new int[]{
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900,
                6379, 8080, 8443, 27017
        };
    }
}
