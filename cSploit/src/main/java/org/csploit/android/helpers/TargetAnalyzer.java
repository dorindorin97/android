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

import org.csploit.android.core.System;
import org.csploit.android.net.Target;
import org.csploit.android.net.Target.Exploit;
import org.csploit.android.net.Target.Port;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * TargetAnalyzer - Comprehensive target analysis utilities
 *
 * Provides:
 * - Port analysis and categorization
 * - Service detection patterns
 * - Vulnerability prioritization
 * - Target comparison and grouping
 * - Risk assessment
 * - Statistical analysis
 *
 * Usage:
 * {@code
 * TargetAnalyzer analyzer = new TargetAnalyzer();
 * RiskLevel risk = analyzer.assessRisk(target);
 * List<Port> webPorts = analyzer.filterPorts(target, PortCategory.WEB);
 * AnalysisSummary summary = analyzer.analyzeAll(targets);
 * }
 */
public final class TargetAnalyzer {

    private static final String TAG = "TargetAnalyzer";

    // Common port categories
    public enum PortCategory {
        WEB,           // HTTP, HTTPS
        REMOTE_ACCESS, // SSH, Telnet, RDP
        DATABASE,      // MySQL, PostgreSQL, MongoDB
        FILE_SHARING,  // FTP, SMB, NFS
        MAIL,          // SMTP, POP3, IMAP
        DNS,           // DNS
        NETWORK,       // SNMP, NetBIOS
        SECURITY,      // Known vulnerable services
        OTHER
    }

    // Risk levels for targets
    public enum RiskLevel {
        CRITICAL(4),
        HIGH(3),
        MEDIUM(2),
        LOW(1),
        INFO(0);

        public final int severity;

        RiskLevel(int severity) {
            this.severity = severity;
        }
    }

    // Port category mappings
    private static final Map<Integer, PortCategory> PORT_CATEGORIES = new HashMap<>();
    private static final Set<Integer> HIGH_RISK_PORTS = new HashSet<>();
    private static final Set<Integer> CRITICAL_PORTS = new HashSet<>();

    static {
        // Web ports
        PORT_CATEGORIES.put(80, PortCategory.WEB);
        PORT_CATEGORIES.put(443, PortCategory.WEB);
        PORT_CATEGORIES.put(8080, PortCategory.WEB);
        PORT_CATEGORIES.put(8443, PortCategory.WEB);
        PORT_CATEGORIES.put(8000, PortCategory.WEB);
        PORT_CATEGORIES.put(3000, PortCategory.WEB);

        // Remote access ports
        PORT_CATEGORIES.put(22, PortCategory.REMOTE_ACCESS);
        PORT_CATEGORIES.put(23, PortCategory.REMOTE_ACCESS);
        PORT_CATEGORIES.put(3389, PortCategory.REMOTE_ACCESS);
        PORT_CATEGORIES.put(5900, PortCategory.REMOTE_ACCESS);

        // Database ports
        PORT_CATEGORIES.put(3306, PortCategory.DATABASE);
        PORT_CATEGORIES.put(5432, PortCategory.DATABASE);
        PORT_CATEGORIES.put(1433, PortCategory.DATABASE);
        PORT_CATEGORIES.put(1521, PortCategory.DATABASE);
        PORT_CATEGORIES.put(27017, PortCategory.DATABASE);
        PORT_CATEGORIES.put(6379, PortCategory.DATABASE);

        // File sharing ports
        PORT_CATEGORIES.put(21, PortCategory.FILE_SHARING);
        PORT_CATEGORIES.put(445, PortCategory.FILE_SHARING);
        PORT_CATEGORIES.put(139, PortCategory.FILE_SHARING);
        PORT_CATEGORIES.put(2049, PortCategory.FILE_SHARING);

        // Mail ports
        PORT_CATEGORIES.put(25, PortCategory.MAIL);
        PORT_CATEGORIES.put(110, PortCategory.MAIL);
        PORT_CATEGORIES.put(143, PortCategory.MAIL);
        PORT_CATEGORIES.put(465, PortCategory.MAIL);
        PORT_CATEGORIES.put(587, PortCategory.MAIL);
        PORT_CATEGORIES.put(993, PortCategory.MAIL);
        PORT_CATEGORIES.put(995, PortCategory.MAIL);

        // DNS
        PORT_CATEGORIES.put(53, PortCategory.DNS);

        // Network services
        PORT_CATEGORIES.put(161, PortCategory.NETWORK);
        PORT_CATEGORIES.put(162, PortCategory.NETWORK);
        PORT_CATEGORIES.put(137, PortCategory.NETWORK);
        PORT_CATEGORIES.put(138, PortCategory.NETWORK);

        // High risk ports (often misconfigured)
        HIGH_RISK_PORTS.add(23);    // Telnet
        HIGH_RISK_PORTS.add(21);    // FTP
        HIGH_RISK_PORTS.add(445);   // SMB
        HIGH_RISK_PORTS.add(139);   // NetBIOS
        HIGH_RISK_PORTS.add(3389);  // RDP
        HIGH_RISK_PORTS.add(1433);  // MSSQL
        HIGH_RISK_PORTS.add(3306);  // MySQL
        HIGH_RISK_PORTS.add(27017); // MongoDB

        // Critical ports (immediate attention needed)
        CRITICAL_PORTS.add(23);     // Telnet (unencrypted)
        CRITICAL_PORTS.add(21);     // FTP (unencrypted)
        CRITICAL_PORTS.add(512);    // rexec
        CRITICAL_PORTS.add(513);    // rlogin
        CRITICAL_PORTS.add(514);    // rsh
    }

    public TargetAnalyzer() {}

    // ==================== Port Analysis ====================

    /**
     * Get the category of a port.
     *
     * @param port the port number
     * @return the port category
     */
    @NonNull
    public PortCategory getPortCategory(int port) {
        return PORT_CATEGORIES.getOrDefault(port, PortCategory.OTHER);
    }

    /**
     * Filter target's ports by category.
     *
     * @param target the target to analyze
     * @param category the port category to filter by
     * @return list of ports matching the category
     */
    @NonNull
    public List<Port> filterPorts(@NonNull Target target, @NonNull PortCategory category) {
        List<Port> result = new ArrayList<>();
        for (Port port : target.getOpenPorts()) {
            if (getPortCategory(port.getNumber()) == category) {
                result.add(port);
            }
        }
        return result;
    }

    /**
     * Get all web-related ports (HTTP, HTTPS).
     *
     * @param target the target
     * @return list of web ports
     */
    @NonNull
    public List<Port> getWebPorts(@NonNull Target target) {
        return filterPorts(target, PortCategory.WEB);
    }

    /**
     * Get all database ports.
     *
     * @param target the target
     * @return list of database ports
     */
    @NonNull
    public List<Port> getDatabasePorts(@NonNull Target target) {
        return filterPorts(target, PortCategory.DATABASE);
    }

    /**
     * Get all remote access ports.
     *
     * @param target the target
     * @return list of remote access ports
     */
    @NonNull
    public List<Port> getRemoteAccessPorts(@NonNull Target target) {
        return filterPorts(target, PortCategory.REMOTE_ACCESS);
    }

    /**
     * Check if target has web services.
     *
     * @param target the target
     * @return true if target has web services
     */
    public boolean hasWebServices(@NonNull Target target) {
        return !getWebPorts(target).isEmpty();
    }

    /**
     * Check if target has database services exposed.
     *
     * @param target the target
     * @return true if target has database services
     */
    public boolean hasDatabaseServices(@NonNull Target target) {
        return !getDatabasePorts(target).isEmpty();
    }

    // ==================== Risk Assessment ====================

    /**
     * Assess the risk level of a target.
     *
     * @param target the target to assess
     * @return the risk level
     */
    @NonNull
    public RiskLevel assessRisk(@NonNull Target target) {
        if (target.getType() == Target.Type.NETWORK) {
            return RiskLevel.INFO;
        }

        // Check for known vulnerabilities
        if (target.hasExploits()) {
            int exploitCount = target.getExploits().size();
            if (exploitCount >= 5) {
                return RiskLevel.CRITICAL;
            } else if (exploitCount >= 2) {
                return RiskLevel.HIGH;
            }
        }

        // Check for critical ports
        for (Port port : target.getOpenPorts()) {
            if (CRITICAL_PORTS.contains(port.getNumber())) {
                return RiskLevel.HIGH;
            }
        }

        // Check for high risk ports
        int highRiskCount = 0;
        for (Port port : target.getOpenPorts()) {
            if (HIGH_RISK_PORTS.contains(port.getNumber())) {
                highRiskCount++;
            }
        }

        if (highRiskCount >= 3) {
            return RiskLevel.HIGH;
        } else if (highRiskCount >= 1) {
            return RiskLevel.MEDIUM;
        }

        // Check total open ports
        if (target.getOpenPorts().size() > 10) {
            return RiskLevel.MEDIUM;
        } else if (target.hasOpenPorts()) {
            return RiskLevel.LOW;
        }

        return RiskLevel.INFO;
    }

    /**
     * Get a human-readable risk description.
     *
     * @param target the target
     * @return risk description
     */
    @NonNull
    public String getRiskDescription(@NonNull Target target) {
        RiskLevel risk = assessRisk(target);
        StringBuilder description = new StringBuilder();

        description.append("Risk Level: ").append(risk.name()).append("\n");

        switch (risk) {
            case CRITICAL:
                description.append("Multiple known vulnerabilities detected. Immediate action required.");
                break;
            case HIGH:
                description.append("Critical services exposed or known vulnerabilities present.");
                break;
            case MEDIUM:
                description.append("Potentially risky services detected. Review recommended.");
                break;
            case LOW:
                description.append("Open ports detected but no major issues identified.");
                break;
            case INFO:
                description.append("No significant risk indicators detected.");
                break;
        }

        return description.toString();
    }

    // ==================== Statistical Analysis ====================

    /**
     * Analysis summary for multiple targets.
     */
    public static class AnalysisSummary {
        public int totalTargets;
        public int criticalRiskCount;
        public int highRiskCount;
        public int mediumRiskCount;
        public int lowRiskCount;
        public int totalOpenPorts;
        public int totalExploits;
        public Map<PortCategory, Integer> portCategoryCounts;
        public List<Target> criticalTargets;
        public List<Target> highRiskTargets;

        public AnalysisSummary() {
            portCategoryCounts = new HashMap<>();
            criticalTargets = new ArrayList<>();
            highRiskTargets = new ArrayList<>();
        }

        @Override
        public String toString() {
            return String.format(
                "Analysis Summary:\n" +
                "  Total Targets: %d\n" +
                "  Critical Risk: %d\n" +
                "  High Risk: %d\n" +
                "  Medium Risk: %d\n" +
                "  Low Risk: %d\n" +
                "  Total Open Ports: %d\n" +
                "  Total Exploits: %d",
                totalTargets, criticalRiskCount, highRiskCount,
                mediumRiskCount, lowRiskCount, totalOpenPorts, totalExploits
            );
        }
    }

    /**
     * Analyze all targets and generate summary.
     *
     * @param targets collection of targets to analyze
     * @return analysis summary
     */
    @NonNull
    public AnalysisSummary analyzeAll(@NonNull List<Target> targets) {
        AnalysisSummary summary = new AnalysisSummary();
        summary.totalTargets = targets.size();

        for (Target target : targets) {
            // Assess risk
            RiskLevel risk = assessRisk(target);
            switch (risk) {
                case CRITICAL:
                    summary.criticalRiskCount++;
                    summary.criticalTargets.add(target);
                    break;
                case HIGH:
                    summary.highRiskCount++;
                    summary.highRiskTargets.add(target);
                    break;
                case MEDIUM:
                    summary.mediumRiskCount++;
                    break;
                case LOW:
                    summary.lowRiskCount++;
                    break;
            }

            // Count ports by category
            for (Port port : target.getOpenPorts()) {
                summary.totalOpenPorts++;
                PortCategory category = getPortCategory(port.getNumber());
                summary.portCategoryCounts.merge(category, 1, Integer::sum);
            }

            // Count exploits
            summary.totalExploits += target.getExploits().size();
        }

        return summary;
    }

    // ==================== Target Comparison ====================

    /**
     * Sort targets by risk level (highest first).
     *
     * @param targets list of targets
     * @return sorted list
     */
    @NonNull
    public List<Target> sortByRisk(@NonNull List<Target> targets) {
        List<Target> sorted = new ArrayList<>(targets);
        Collections.sort(sorted, (t1, t2) -> {
            int risk1 = assessRisk(t1).severity;
            int risk2 = assessRisk(t2).severity;
            return Integer.compare(risk2, risk1); // Descending
        });
        return sorted;
    }

    /**
     * Sort targets by number of open ports (most first).
     *
     * @param targets list of targets
     * @return sorted list
     */
    @NonNull
    public List<Target> sortByPortCount(@NonNull List<Target> targets) {
        List<Target> sorted = new ArrayList<>(targets);
        Collections.sort(sorted, (t1, t2) -> {
            int count1 = t1.getOpenPorts().size();
            int count2 = t2.getOpenPorts().size();
            return Integer.compare(count2, count1); // Descending
        });
        return sorted;
    }

    /**
     * Group targets by risk level.
     *
     * @param targets list of targets
     * @return map of risk level to targets
     */
    @NonNull
    public Map<RiskLevel, List<Target>> groupByRisk(@NonNull List<Target> targets) {
        Map<RiskLevel, List<Target>> grouped = new HashMap<>();
        for (RiskLevel level : RiskLevel.values()) {
            grouped.put(level, new ArrayList<>());
        }

        for (Target target : targets) {
            RiskLevel risk = assessRisk(target);
            grouped.get(risk).add(target);
        }

        return grouped;
    }

    /**
     * Find targets with a specific port open.
     *
     * @param targets list of targets
     * @param port port number to search for
     * @return targets with the port open
     */
    @NonNull
    public List<Target> findTargetsWithPort(@NonNull List<Target> targets, int port) {
        List<Target> result = new ArrayList<>();
        for (Target target : targets) {
            if (target.hasOpenPort(port)) {
                result.add(target);
            }
        }
        return result;
    }

    /**
     * Find targets with exploits.
     *
     * @param targets list of targets
     * @return targets with known exploits
     */
    @NonNull
    public List<Target> findTargetsWithExploits(@NonNull List<Target> targets) {
        List<Target> result = new ArrayList<>();
        for (Target target : targets) {
            if (target.hasExploits()) {
                result.add(target);
            }
        }
        return result;
    }

    // ==================== Service Detection ====================

    /**
     * Get likely service name for a port.
     *
     * @param port the port number
     * @return likely service name
     */
    @NonNull
    public String guessServiceName(int port) {
        String protocol = System.getProtocolByPort(port);
        if (protocol != null) {
            return protocol;
        }

        // Fallback to common known ports
        switch (port) {
            case 80: return "http";
            case 443: return "https";
            case 22: return "ssh";
            case 21: return "ftp";
            case 23: return "telnet";
            case 25: return "smtp";
            case 53: return "dns";
            case 110: return "pop3";
            case 143: return "imap";
            case 445: return "smb";
            case 3306: return "mysql";
            case 5432: return "postgresql";
            case 27017: return "mongodb";
            case 6379: return "redis";
            case 8080: return "http-proxy";
            default: return "unknown";
        }
    }

    /**
     * Check if port is commonly associated with unencrypted protocols.
     *
     * @param port the port number
     * @return true if typically unencrypted
     */
    public boolean isUnencryptedPort(int port) {
        switch (port) {
            case 21:   // FTP
            case 23:   // Telnet
            case 25:   // SMTP (without TLS)
            case 80:   // HTTP
            case 110:  // POP3
            case 143:  // IMAP
            case 161:  // SNMP
            case 512:  // rexec
            case 513:  // rlogin
            case 514:  // rsh
                return true;
            default:
                return false;
        }
    }
}
