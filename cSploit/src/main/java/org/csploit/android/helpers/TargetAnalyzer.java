package org.csploit.android.helpers;

/**
 * Utility class for analyzing network targets, categorizing ports,
 * and assessing risk levels.
 */
public class TargetAnalyzer {

    public enum PortCategory {
        WEB, REMOTE_ACCESS, DATABASE, FILE_SHARING, MAIL, DNS, NETWORK, OTHER
    }

    public enum RiskLevel {
        INFO(0), LOW(1), MEDIUM(2), HIGH(3), CRITICAL(4);

        public final int severity;

        RiskLevel(int severity) {
            this.severity = severity;
        }
    }

    public static class AnalysisSummary {
        public int totalTargets;
        public int criticalRiskCount;
        public int highRiskCount;
        public int mediumRiskCount;
        public int lowRiskCount;
        public int totalOpenPorts;
        public int totalExploits;

        @Override
        public String toString() {
            return String.format(
                    "Total Targets: %d, Critical Risk: %d, High Risk: %d, " +
                    "Medium Risk: %d, Low Risk: %d, Total Open Ports: %d, Total Exploits: %d",
                    totalTargets, criticalRiskCount, highRiskCount,
                    mediumRiskCount, lowRiskCount, totalOpenPorts, totalExploits);
        }
    }

    public PortCategory getPortCategory(int port) {
        switch (port) {
            case 80: case 443: case 8080: case 8443:
                return PortCategory.WEB;
            case 22: case 23: case 3389: case 5900:
                return PortCategory.REMOTE_ACCESS;
            case 3306: case 5432: case 27017: case 6379: case 1433: case 1521:
                return PortCategory.DATABASE;
            case 21: case 445: case 139: case 2049:
                return PortCategory.FILE_SHARING;
            case 25: case 110: case 143: case 465: case 587: case 993: case 995:
                return PortCategory.MAIL;
            case 53:
                return PortCategory.DNS;
            case 161: case 162:
                return PortCategory.NETWORK;
            default:
                return PortCategory.OTHER;
        }
    }

    public String guessServiceName(int port) {
        switch (port) {
            case 21:    return "ftp";
            case 22:    return "ssh";
            case 23:    return "telnet";
            case 25:    return "smtp";
            case 53:    return "dns";
            case 80:    return "http";
            case 110:   return "pop3";
            case 143:   return "imap";
            case 443:   return "https";
            case 445:   return "smb";
            case 3306:  return "mysql";
            case 5432:  return "postgresql";
            case 6379:  return "redis";
            case 27017: return "mongodb";
            default:    return "unknown";
        }
    }

    public boolean isUnencryptedPort(int port) {
        switch (port) {
            case 21:  // FTP
            case 23:  // Telnet
            case 80:  // HTTP
            case 110: // POP3
            case 143: // IMAP
                return true;
            default:
                return false;
        }
    }
}
