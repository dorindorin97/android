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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * PortScanOptimizer - Optimized port scanning configurations
 *
 * Provides:
 * - Pre-defined port lists for common scan types
 * - Port prioritization based on usage frequency
 * - Service-specific port ranges
 * - Scan profile management
 * - Adaptive scan strategies
 */
public final class PortScanOptimizer {

    private static final String TAG = "PortScanOptimizer";
    private static volatile PortScanOptimizer instance;

    /**
     * Scan intensity levels
     */
    public enum ScanIntensity {
        QUICK(100, "Quick Scan", "Scan top 100 most common ports"),
        STANDARD(1000, "Standard Scan", "Scan top 1000 ports"),
        THOROUGH(5000, "Thorough Scan", "Scan common and extended ports"),
        FULL(65535, "Full Scan", "Scan all 65535 TCP ports");

        private final int portCount;
        private final String name;
        private final String description;

        ScanIntensity(int portCount, String name, String description) {
            this.portCount = portCount;
            this.name = name;
            this.description = description;
        }

        public int getPortCount() { return portCount; }
        public String getName() { return name; }
        public String getDescription() { return description; }
    }

    /**
     * Service categories for targeted scanning
     */
    public enum ServiceCategory {
        WEB("Web Services"),
        DATABASE("Database Services"),
        MAIL("Mail Services"),
        FILE_SHARING("File Sharing"),
        REMOTE_ACCESS("Remote Access"),
        NETWORK("Network Services"),
        SECURITY("Security Services"),
        VOIP("VoIP/Telephony"),
        IOT("IoT Devices"),
        ALL("All Categories");

        private final String name;

        ServiceCategory(String name) {
            this.name = name;
        }

        public String getName() { return name; }
    }

    // Top 100 most common ports (ordered by frequency)
    private static final int[] TOP_100_PORTS = {
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
        143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
        137, 138, 161, 162, 389, 636, 1433, 1434, 1521, 2049,
        2121, 2222, 3128, 3268, 3269, 3690, 5000, 5001, 5432, 5631,
        5632, 5800, 5801, 5802, 5803, 5901, 5902, 5903, 6000, 6001,
        6002, 6003, 6004, 6005, 6006, 6007, 6008, 6009, 6010, 6011,
        6667, 8000, 8008, 8081, 8443, 8888, 9000, 9090, 9100, 9200,
        9443, 10000, 10443, 11211, 27017, 27018, 27019, 28017, 50000, 50001,
        1080, 1194, 1883, 4444, 5060, 5061, 5222, 5223, 5269, 5270,
        6379, 6660, 6661, 6662, 6663, 6664, 6665, 6666, 6669, 8883
    };

    // Web service ports
    private static final int[] WEB_PORTS = {
        80, 443, 8080, 8443, 8000, 8008, 8081, 8888, 9000, 9090,
        9443, 10000, 10443, 3000, 4000, 5000, 5001, 8001, 8002, 8003
    };

    // Database ports
    private static final int[] DATABASE_PORTS = {
        1433, 1434, 1521, 3306, 5432, 6379, 9200, 27017, 27018, 27019,
        28017, 11211, 5984, 7474, 8529, 9042, 9160, 26257, 28015, 50000
    };

    // Mail service ports
    private static final int[] MAIL_PORTS = {
        25, 110, 143, 465, 587, 993, 995, 2525, 1025, 106
    };

    // File sharing ports
    private static final int[] FILE_SHARING_PORTS = {
        21, 22, 139, 445, 873, 2049, 2121, 69, 115, 989,
        990, 1194, 548, 631, 9100, 515, 111
    };

    // Remote access ports
    private static final int[] REMOTE_ACCESS_PORTS = {
        22, 23, 3389, 5900, 5901, 5902, 5903, 5800, 5801, 5802,
        5803, 1194, 1723, 4899, 5631, 5632, 3283, 5938, 8291, 10050
    };

    // Network service ports
    private static final int[] NETWORK_PORTS = {
        53, 67, 68, 69, 123, 161, 162, 389, 636, 1812,
        1813, 1645, 1646, 500, 4500, 514, 1514, 5514
    };

    // IoT common ports
    private static final int[] IOT_PORTS = {
        80, 443, 1883, 8883, 5683, 5684, 8080, 8443, 1900, 5353,
        554, 8554, 49152, 49153, 49154, 7547, 2323, 37777, 34567, 9527
    };

    // Port to service name mapping
    private static final Map<Integer, String> PORT_SERVICE_MAP = new HashMap<>();

    static {
        PORT_SERVICE_MAP.put(21, "FTP");
        PORT_SERVICE_MAP.put(22, "SSH");
        PORT_SERVICE_MAP.put(23, "Telnet");
        PORT_SERVICE_MAP.put(25, "SMTP");
        PORT_SERVICE_MAP.put(53, "DNS");
        PORT_SERVICE_MAP.put(80, "HTTP");
        PORT_SERVICE_MAP.put(110, "POP3");
        PORT_SERVICE_MAP.put(111, "RPC");
        PORT_SERVICE_MAP.put(135, "MSRPC");
        PORT_SERVICE_MAP.put(139, "NetBIOS");
        PORT_SERVICE_MAP.put(143, "IMAP");
        PORT_SERVICE_MAP.put(443, "HTTPS");
        PORT_SERVICE_MAP.put(445, "SMB");
        PORT_SERVICE_MAP.put(993, "IMAPS");
        PORT_SERVICE_MAP.put(995, "POP3S");
        PORT_SERVICE_MAP.put(1433, "MSSQL");
        PORT_SERVICE_MAP.put(1521, "Oracle");
        PORT_SERVICE_MAP.put(3306, "MySQL");
        PORT_SERVICE_MAP.put(3389, "RDP");
        PORT_SERVICE_MAP.put(5432, "PostgreSQL");
        PORT_SERVICE_MAP.put(5900, "VNC");
        PORT_SERVICE_MAP.put(6379, "Redis");
        PORT_SERVICE_MAP.put(8080, "HTTP-Proxy");
        PORT_SERVICE_MAP.put(8443, "HTTPS-Alt");
        PORT_SERVICE_MAP.put(9200, "Elasticsearch");
        PORT_SERVICE_MAP.put(27017, "MongoDB");
    }

    private PortScanOptimizer() {
        Log.d(TAG, "PortScanOptimizer initialized");
    }

    public static PortScanOptimizer getInstance() {
        if (instance == null) {
            synchronized (PortScanOptimizer.class) {
                if (instance == null) {
                    instance = new PortScanOptimizer();
                }
            }
        }
        return instance;
    }

    /**
     * Get port list for scan intensity
     */
    @NonNull
    public int[] getPortsForIntensity(ScanIntensity intensity) {
        switch (intensity) {
            case QUICK:
                return TOP_100_PORTS;
            case STANDARD:
                return getTopNPorts(1000);
            case THOROUGH:
                return getTopNPorts(5000);
            case FULL:
                return getAllPorts();
            default:
                return TOP_100_PORTS;
        }
    }

    /**
     * Get ports for a specific service category
     */
    @NonNull
    public int[] getPortsForCategory(ServiceCategory category) {
        switch (category) {
            case WEB:
                return WEB_PORTS.clone();
            case DATABASE:
                return DATABASE_PORTS.clone();
            case MAIL:
                return MAIL_PORTS.clone();
            case FILE_SHARING:
                return FILE_SHARING_PORTS.clone();
            case REMOTE_ACCESS:
                return REMOTE_ACCESS_PORTS.clone();
            case NETWORK:
                return NETWORK_PORTS.clone();
            case IOT:
                return IOT_PORTS.clone();
            case ALL:
            default:
                return TOP_100_PORTS.clone();
        }
    }

    /**
     * Get ports for multiple categories combined
     */
    @NonNull
    public int[] getPortsForCategories(ServiceCategory... categories) {
        List<Integer> allPorts = new ArrayList<>();

        for (ServiceCategory category : categories) {
            int[] categoryPorts = getPortsForCategory(category);
            for (int port : categoryPorts) {
                if (!allPorts.contains(port)) {
                    allPorts.add(port);
                }
            }
        }

        Collections.sort(allPorts);
        int[] result = new int[allPorts.size()];
        for (int i = 0; i < allPorts.size(); i++) {
            result[i] = allPorts.get(i);
        }
        return result;
    }

    /**
     * Get service name for a port
     */
    @NonNull
    public String getServiceName(int port) {
        String service = PORT_SERVICE_MAP.get(port);
        return service != null ? service : "Unknown";
    }

    /**
     * Check if port is commonly associated with a vulnerable service
     */
    public boolean isHighRiskPort(int port) {
        // Ports commonly associated with security risks
        int[] highRiskPorts = {21, 23, 25, 110, 143, 139, 445, 512, 513, 514, 1433, 3389};
        for (int riskPort : highRiskPorts) {
            if (port == riskPort) {
                return true;
            }
        }
        return false;
    }

    /**
     * Get top N ports based on usage frequency
     */
    @NonNull
    private int[] getTopNPorts(int n) {
        // Extended port list for larger scans
        List<Integer> ports = new ArrayList<>();

        // Start with top 100
        for (int port : TOP_100_PORTS) {
            ports.add(port);
        }

        // Add more common ports
        for (int port = 1; port <= Math.min(n, 1024); port++) {
            if (!ports.contains(port)) {
                ports.add(port);
            }
        }

        // Add high ports commonly used
        int[] highPorts = {1080, 1194, 1433, 1434, 1521, 1723, 1883, 2049, 2121, 2222,
                          3000, 3128, 3268, 3269, 3306, 3389, 3690, 4000, 4443, 4444,
                          5000, 5001, 5060, 5222, 5432, 5631, 5632, 5800, 5900, 5984,
                          6000, 6379, 6660, 6667, 7000, 7001, 7474, 8000, 8001, 8008,
                          8080, 8081, 8443, 8529, 8883, 8888, 9000, 9042, 9090, 9100,
                          9160, 9200, 9443, 10000, 10443, 11211, 27017, 28017, 50000};

        for (int port : highPorts) {
            if (!ports.contains(port) && ports.size() < n) {
                ports.add(port);
            }
        }

        // Fill remaining with sequential ports if needed
        for (int port = 1025; ports.size() < n && port <= 65535; port++) {
            if (!ports.contains(port)) {
                ports.add(port);
            }
        }

        Collections.sort(ports);
        int[] result = new int[Math.min(ports.size(), n)];
        for (int i = 0; i < result.length; i++) {
            result[i] = ports.get(i);
        }
        return result;
    }

    /**
     * Get all 65535 ports
     */
    @NonNull
    private int[] getAllPorts() {
        int[] allPorts = new int[65535];
        for (int i = 0; i < 65535; i++) {
            allPorts[i] = i + 1;
        }
        return allPorts;
    }

    /**
     * Convert port array to nmap format string
     */
    @NonNull
    public String toNmapFormat(int[] ports) {
        if (ports == null || ports.length == 0) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        Arrays.sort(ports);

        int rangeStart = ports[0];
        int rangeEnd = ports[0];

        for (int i = 1; i < ports.length; i++) {
            if (ports[i] == rangeEnd + 1) {
                rangeEnd = ports[i];
            } else {
                if (sb.length() > 0) {
                    sb.append(",");
                }
                if (rangeStart == rangeEnd) {
                    sb.append(rangeStart);
                } else {
                    sb.append(rangeStart).append("-").append(rangeEnd);
                }
                rangeStart = ports[i];
                rangeEnd = ports[i];
            }
        }

        // Add last range
        if (sb.length() > 0) {
            sb.append(",");
        }
        if (rangeStart == rangeEnd) {
            sb.append(rangeStart);
        } else {
            sb.append(rangeStart).append("-").append(rangeEnd);
        }

        return sb.toString();
    }

    /**
     * Get estimated scan time in seconds based on port count
     */
    public int getEstimatedScanTime(int portCount, int targetCount) {
        // Rough estimate: 0.1 seconds per port per target with parallelization
        double timePerPort = 0.05;
        int parallelFactor = Math.min(10, targetCount);
        return (int) Math.ceil((portCount * targetCount * timePerPort) / parallelFactor);
    }

    /**
     * ScanProfile - Custom scan configuration
     */
    public static class ScanProfile {
        private final String name;
        private final int[] ports;
        private final boolean includeUdp;
        private final int timeout;
        private final int retries;

        private ScanProfile(Builder builder) {
            this.name = builder.name;
            this.ports = builder.ports;
            this.includeUdp = builder.includeUdp;
            this.timeout = builder.timeout;
            this.retries = builder.retries;
        }

        public String getName() { return name; }
        public int[] getPorts() { return ports.clone(); }
        public boolean isIncludeUdp() { return includeUdp; }
        public int getTimeout() { return timeout; }
        public int getRetries() { return retries; }

        public static class Builder {
            private String name = "Custom";
            private int[] ports = TOP_100_PORTS;
            private boolean includeUdp = false;
            private int timeout = 1000;
            private int retries = 2;

            public Builder name(String val) { name = val; return this; }
            public Builder ports(int[] val) { ports = val; return this; }
            public Builder includeUdp(boolean val) { includeUdp = val; return this; }
            public Builder timeout(int val) { timeout = val; return this; }
            public Builder retries(int val) { retries = val; return this; }

            public ScanProfile build() {
                return new ScanProfile(this);
            }
        }
    }

    /**
     * Create a quick web scan profile
     */
    @NonNull
    public ScanProfile createWebScanProfile() {
        return new ScanProfile.Builder()
                .name("Web Services Scan")
                .ports(WEB_PORTS)
                .timeout(2000)
                .retries(1)
                .build();
    }

    /**
     * Create a database scan profile
     */
    @NonNull
    public ScanProfile createDatabaseScanProfile() {
        return new ScanProfile.Builder()
                .name("Database Services Scan")
                .ports(DATABASE_PORTS)
                .timeout(3000)
                .retries(2)
                .build();
    }

    /**
     * Create a full service scan profile
     */
    @NonNull
    public ScanProfile createFullScanProfile() {
        return new ScanProfile.Builder()
                .name("Full Service Scan")
                .ports(getTopNPorts(1000))
                .includeUdp(true)
                .timeout(5000)
                .retries(3)
                .build();
    }
}
