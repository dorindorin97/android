/*
 * This file is part of the cSploit.
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

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Enhanced device discovery helper for network scanning.
 *
 * Provides:
 * - Rapid device discovery using multiple techniques
 * - Device type identification based on ports and behavior
 * - Operating system fingerprinting hints
 * - Service detection
 * - Concurrent scanning with progress callbacks
 */
public final class DeviceDiscoveryHelper {

    private static final String TAG = "DeviceDiscoveryHelper";

    // Common service ports for device identification
    private static final int[] DISCOVERY_PORTS = {
        22,    // SSH
        23,    // Telnet
        80,    // HTTP
        443,   // HTTPS
        445,   // SMB
        3389,  // RDP
        5900,  // VNC
        8080,  // HTTP Alt
        8443,  // HTTPS Alt
        62078, // iOS
        5555,  // Android ADB
        9100   // Printer
    };

    // Quick discovery ports (faster scan)
    private static final int[] QUICK_PORTS = {80, 443, 22, 445};

    // Device type enumeration
    public enum DeviceType {
        UNKNOWN("Unknown Device"),
        ROUTER("Router/Gateway"),
        COMPUTER("Computer"),
        SERVER("Server"),
        MOBILE("Mobile Device"),
        PRINTER("Printer"),
        IOT("IoT Device"),
        CAMERA("IP Camera"),
        MEDIA_PLAYER("Media Player"),
        SMART_TV("Smart TV"),
        NAS("NAS Storage"),
        GAME_CONSOLE("Game Console");

        public final String displayName;

        DeviceType(String displayName) {
            this.displayName = displayName;
        }
    }

    // Discovered device information
    public static class DiscoveredDevice {
        public final String ipAddress;
        public final String macAddress;
        public final String hostname;
        public final DeviceType deviceType;
        public final String vendor;
        public final List<Integer> openPorts;
        public final Map<String, String> services;
        public final String osHint;
        public final long responseTimeMs;
        public final long discoveryTimestamp;

        private DiscoveredDevice(Builder builder) {
            this.ipAddress = builder.ipAddress;
            this.macAddress = builder.macAddress;
            this.hostname = builder.hostname;
            this.deviceType = builder.deviceType;
            this.vendor = builder.vendor;
            this.openPorts = new ArrayList<>(builder.openPorts);
            this.services = new HashMap<>(builder.services);
            this.osHint = builder.osHint;
            this.responseTimeMs = builder.responseTimeMs;
            this.discoveryTimestamp = System.currentTimeMillis();
        }

        public String getSummary() {
            StringBuilder sb = new StringBuilder();
            sb.append(ipAddress);
            if (hostname != null && !hostname.isEmpty()) {
                sb.append(" (").append(hostname).append(")");
            }
            sb.append("\n");
            sb.append("Type: ").append(deviceType.displayName);
            if (vendor != null && !vendor.isEmpty()) {
                sb.append(" | Vendor: ").append(vendor);
            }
            if (osHint != null && !osHint.isEmpty()) {
                sb.append("\nOS: ").append(osHint);
            }
            if (!openPorts.isEmpty()) {
                sb.append("\nPorts: ").append(openPorts);
            }
            return sb.toString();
        }

        public static class Builder {
            private String ipAddress;
            private String macAddress;
            private String hostname;
            private DeviceType deviceType = DeviceType.UNKNOWN;
            private String vendor;
            private List<Integer> openPorts = new ArrayList<>();
            private Map<String, String> services = new HashMap<>();
            private String osHint;
            private long responseTimeMs;

            public Builder(String ipAddress) {
                this.ipAddress = ipAddress;
            }

            public Builder macAddress(String mac) {
                this.macAddress = mac;
                return this;
            }

            public Builder hostname(String hostname) {
                this.hostname = hostname;
                return this;
            }

            public Builder deviceType(DeviceType type) {
                this.deviceType = type;
                return this;
            }

            public Builder vendor(String vendor) {
                this.vendor = vendor;
                return this;
            }

            public Builder addPort(int port) {
                this.openPorts.add(port);
                return this;
            }

            public Builder addService(int port, String service) {
                this.services.put(String.valueOf(port), service);
                return this;
            }

            public Builder osHint(String os) {
                this.osHint = os;
                return this;
            }

            public Builder responseTime(long ms) {
                this.responseTimeMs = ms;
                return this;
            }

            public DiscoveredDevice build() {
                return new DiscoveredDevice(this);
            }
        }
    }

    // Discovery progress callback
    public interface DiscoveryCallback {
        void onDeviceFound(DiscoveredDevice device);
        void onProgress(int scanned, int total);
        void onComplete(List<DiscoveredDevice> devices);
        void onError(String error);
    }

    // Scan options
    public static class ScanOptions {
        public final int threadCount;
        public final int timeoutMs;
        public final boolean quickScan;
        public final boolean resolveHostnames;
        public final boolean detectServices;

        private ScanOptions(Builder builder) {
            this.threadCount = builder.threadCount;
            this.timeoutMs = builder.timeoutMs;
            this.quickScan = builder.quickScan;
            this.resolveHostnames = builder.resolveHostnames;
            this.detectServices = builder.detectServices;
        }

        public static class Builder {
            private int threadCount = 50;
            private int timeoutMs = 1000;
            private boolean quickScan = false;
            private boolean resolveHostnames = true;
            private boolean detectServices = true;

            public Builder threadCount(int count) {
                this.threadCount = Math.max(1, Math.min(count, 256));
                return this;
            }

            public Builder timeout(int ms) {
                this.timeoutMs = ms;
                return this;
            }

            public Builder quickScan(boolean quick) {
                this.quickScan = quick;
                return this;
            }

            public Builder resolveHostnames(boolean resolve) {
                this.resolveHostnames = resolve;
                return this;
            }

            public Builder detectServices(boolean detect) {
                this.detectServices = detect;
                return this;
            }

            public ScanOptions build() {
                return new ScanOptions(this);
            }
        }

        public static Builder builder() {
            return new Builder();
        }

        public static ScanOptions defaultOptions() {
            return new Builder().build();
        }

        public static ScanOptions quickOptions() {
            return new Builder()
                .quickScan(true)
                .timeout(500)
                .threadCount(100)
                .detectServices(false)
                .build();
        }
    }

    private DeviceDiscoveryHelper() {}

    // ==================== Main Discovery Methods ====================

    /**
     * Discover devices on a subnet
     *
     * @param baseIp base IP address (e.g., "192.168.1")
     * @param startHost starting host number
     * @param endHost ending host number
     * @param callback progress callback
     * @param options scan options
     */
    public static void discoverSubnet(String baseIp, int startHost, int endHost,
                                      DiscoveryCallback callback, ScanOptions options) {
        ExecutorService executor = Executors.newFixedThreadPool(options.threadCount);
        ConcurrentHashMap<String, DiscoveredDevice> devices = new ConcurrentHashMap<>();
        AtomicInteger progress = new AtomicInteger(0);
        int totalHosts = endHost - startHost + 1;

        List<Future<?>> futures = new ArrayList<>();

        for (int i = startHost; i <= endHost; i++) {
            final String ip = baseIp + "." + i;
            futures.add(executor.submit(() -> {
                try {
                    DiscoveredDevice device = probeDevice(ip, options);
                    if (device != null) {
                        devices.put(ip, device);
                        callback.onDeviceFound(device);
                    }
                } catch (Exception e) {
                    LoggingHelper.d(TAG, "Error probing " + ip + ": " + e.getMessage());
                } finally {
                    int current = progress.incrementAndGet();
                    callback.onProgress(current, totalHosts);
                }
            }));
        }

        // Wait for all tasks to complete
        ThreadHelper.executeBackground(() -> {
            for (Future<?> future : futures) {
                try {
                    future.get(30, TimeUnit.SECONDS);
                } catch (Exception e) {
                    LoggingHelper.d(TAG, "Task failed: " + e.getMessage());
                }
            }
            executor.shutdown();
            callback.onComplete(new ArrayList<>(devices.values()));
        });
    }

    /**
     * Discover devices on a /24 subnet
     *
     * @param networkIp network IP (e.g., "192.168.1.0" or "192.168.1")
     * @param callback progress callback
     */
    public static void discoverNetwork(String networkIp, DiscoveryCallback callback) {
        String baseIp = networkIp;
        if (networkIp.endsWith(".0")) {
            baseIp = networkIp.substring(0, networkIp.length() - 2);
        } else if (networkIp.split("\\.").length == 4) {
            baseIp = networkIp.substring(0, networkIp.lastIndexOf('.'));
        }
        discoverSubnet(baseIp, 1, 254, callback, ScanOptions.defaultOptions());
    }

    /**
     * Quick scan for devices on a network
     *
     * @param networkIp network IP
     * @param callback progress callback
     */
    public static void quickDiscover(String networkIp, DiscoveryCallback callback) {
        String baseIp = networkIp;
        if (networkIp.endsWith(".0")) {
            baseIp = networkIp.substring(0, networkIp.length() - 2);
        } else if (networkIp.split("\\.").length == 4) {
            baseIp = networkIp.substring(0, networkIp.lastIndexOf('.'));
        }
        discoverSubnet(baseIp, 1, 254, callback, ScanOptions.quickOptions());
    }

    // ==================== Device Probing ====================

    /**
     * Probe a single device for information
     *
     * @param ip target IP address
     * @param options scan options
     * @return DiscoveredDevice or null if not reachable
     */
    public static DiscoveredDevice probeDevice(String ip, ScanOptions options) {
        // First, check if host is reachable
        long startTime = System.currentTimeMillis();
        boolean reachable = isHostReachable(ip, options.timeoutMs);

        if (!reachable) {
            return null;
        }

        long responseTime = System.currentTimeMillis() - startTime;
        DiscoveredDevice.Builder builder = new DiscoveredDevice.Builder(ip)
            .responseTime(responseTime);

        // Get MAC address from ARP cache
        String mac = getMacFromArpCache(ip);
        if (mac != null) {
            builder.macAddress(mac);
            // Try to determine vendor from MAC
            String vendor = lookupVendor(mac);
            if (vendor != null) {
                builder.vendor(vendor);
            }
        }

        // Resolve hostname
        if (options.resolveHostnames) {
            String hostname = resolveHostname(ip);
            if (hostname != null && !hostname.equals(ip)) {
                builder.hostname(hostname);
            }
        }

        // Scan ports for service detection
        int[] portsToScan = options.quickScan ? QUICK_PORTS : DISCOVERY_PORTS;
        List<Integer> openPorts = new ArrayList<>();

        for (int port : portsToScan) {
            if (isPortOpen(ip, port, options.timeoutMs)) {
                openPorts.add(port);
                builder.addPort(port);

                if (options.detectServices) {
                    String service = identifyService(port);
                    if (service != null) {
                        builder.addService(port, service);
                    }
                }
            }
        }

        // Determine device type based on open ports and vendor
        DeviceType deviceType = identifyDeviceType(openPorts, mac);
        builder.deviceType(deviceType);

        // Try to determine OS
        String osHint = guessOperatingSystem(openPorts, mac);
        if (osHint != null) {
            builder.osHint(osHint);
        }

        return builder.build();
    }

    /**
     * Quick probe a single device
     */
    public static DiscoveredDevice probeDevice(String ip) {
        return probeDevice(ip, ScanOptions.defaultOptions());
    }

    // ==================== Host Detection ====================

    /**
     * Check if a host is reachable
     */
    public static boolean isHostReachable(String ip, int timeoutMs) {
        // Try ICMP first
        try {
            InetAddress address = InetAddress.getByName(ip);
            if (address.isReachable(timeoutMs)) {
                return true;
            }
        } catch (IOException e) {
            // Fall through to TCP check
        }

        // Fallback: try common ports
        return isPortOpen(ip, 80, timeoutMs) ||
               isPortOpen(ip, 443, timeoutMs) ||
               isPortOpen(ip, 22, timeoutMs) ||
               isPortOpen(ip, 445, timeoutMs);
    }

    /**
     * Check if a port is open
     */
    public static boolean isPortOpen(String ip, int port, int timeoutMs) {
        Socket socket = null;
        try {
            socket = new Socket();
            socket.connect(new InetSocketAddress(ip, port), timeoutMs);
            return true;
        } catch (IOException e) {
            return false;
        } finally {
            CloseableHelper.close(socket);
        }
    }

    // ==================== Device Identification ====================

    /**
     * Identify device type based on open ports and MAC address
     */
    public static DeviceType identifyDeviceType(List<Integer> openPorts, String mac) {
        if (openPorts == null || openPorts.isEmpty()) {
            return DeviceType.UNKNOWN;
        }

        // Check for specific device signatures

        // Printers
        if (openPorts.contains(9100) || openPorts.contains(631)) {
            return DeviceType.PRINTER;
        }

        // IP Cameras
        if (openPorts.contains(554) || openPorts.contains(8554)) {
            return DeviceType.CAMERA;
        }

        // Routers typically have port 80/443 and telnet
        if ((openPorts.contains(80) || openPorts.contains(443)) && openPorts.contains(23)) {
            return DeviceType.ROUTER;
        }

        // iOS devices
        if (openPorts.contains(62078)) {
            return DeviceType.MOBILE;
        }

        // Android devices with ADB
        if (openPorts.contains(5555)) {
            return DeviceType.MOBILE;
        }

        // VNC - typically workstations
        if (openPorts.contains(5900)) {
            return DeviceType.COMPUTER;
        }

        // RDP - Windows machines
        if (openPorts.contains(3389)) {
            return DeviceType.COMPUTER;
        }

        // SMB - could be server or NAS
        if (openPorts.contains(445)) {
            if (openPorts.contains(80) && openPorts.contains(443)) {
                return DeviceType.NAS;
            }
            return DeviceType.COMPUTER;
        }

        // SSH only - likely server
        if (openPorts.contains(22) && openPorts.size() <= 2) {
            return DeviceType.SERVER;
        }

        // Multiple web ports - likely server
        if (openPorts.contains(80) && openPorts.contains(443) &&
            (openPorts.contains(8080) || openPorts.contains(8443))) {
            return DeviceType.SERVER;
        }

        // Default based on vendor if available
        if (mac != null) {
            String vendor = lookupVendor(mac);
            if (vendor != null) {
                String v = vendor.toLowerCase();
                if (v.contains("apple") || v.contains("samsung") || v.contains("xiaomi")) {
                    return DeviceType.MOBILE;
                }
                if (v.contains("cisco") || v.contains("netgear") || v.contains("tp-link") ||
                    v.contains("asus") || v.contains("linksys") || v.contains("d-link")) {
                    return DeviceType.ROUTER;
                }
                if (v.contains("hp") || v.contains("canon") || v.contains("epson") ||
                    v.contains("brother") || v.contains("lexmark")) {
                    return DeviceType.PRINTER;
                }
                if (v.contains("sony") || v.contains("microsoft") || v.contains("nintendo")) {
                    return DeviceType.GAME_CONSOLE;
                }
                if (v.contains("amazon") || v.contains("roku") || v.contains("google")) {
                    return DeviceType.MEDIA_PLAYER;
                }
                if (v.contains("lg") || v.contains("vizio") || v.contains("tcl")) {
                    return DeviceType.SMART_TV;
                }
                if (v.contains("synology") || v.contains("qnap") || v.contains("western digital")) {
                    return DeviceType.NAS;
                }
            }
        }

        // Has web server - probably a computer
        if (openPorts.contains(80) || openPorts.contains(443)) {
            return DeviceType.COMPUTER;
        }

        return DeviceType.UNKNOWN;
    }

    /**
     * Guess operating system based on open ports
     */
    public static String guessOperatingSystem(List<Integer> openPorts, String mac) {
        if (openPorts == null) return null;

        // RDP strongly indicates Windows
        if (openPorts.contains(3389)) {
            return "Windows";
        }

        // SMB without RDP could be Linux Samba or NAS
        if (openPorts.contains(445) && !openPorts.contains(3389)) {
            String vendor = mac != null ? lookupVendor(mac) : null;
            if (vendor != null && vendor.toLowerCase().contains("apple")) {
                return "macOS";
            }
            return "Linux/Unix (or NAS)";
        }

        // iOS device
        if (openPorts.contains(62078)) {
            return "iOS";
        }

        // Android ADB
        if (openPorts.contains(5555)) {
            return "Android";
        }

        // SSH without RDP often indicates Linux/Unix
        if (openPorts.contains(22) && !openPorts.contains(3389)) {
            String vendor = mac != null ? lookupVendor(mac) : null;
            if (vendor != null && vendor.toLowerCase().contains("apple")) {
                return "macOS";
            }
            return "Linux/Unix";
        }

        return null;
    }

    // ==================== Helper Methods ====================

    /**
     * Get MAC address from system ARP cache
     */
    public static String getMacFromArpCache(String ip) {
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader("/proc/net/arp"));
            String line;

            while ((line = reader.readLine()) != null) {
                String[] parts = line.split("\\s+");
                if (parts.length >= 4 && parts[0].equals(ip)) {
                    String mac = parts[3];
                    if (!mac.equals("00:00:00:00:00:00")) {
                        return mac.toUpperCase(Locale.US);
                    }
                }
            }
        } catch (IOException e) {
            LoggingHelper.d(TAG, "Failed to read ARP cache: " + e.getMessage());
        } finally {
            CloseableHelper.close(reader);
        }
        return null;
    }

    /**
     * Resolve IP to hostname
     */
    public static String resolveHostname(String ip) {
        try {
            InetAddress addr = InetAddress.getByName(ip);
            String hostname = addr.getCanonicalHostName();
            return hostname.equals(ip) ? null : hostname;
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * Lookup vendor from MAC address
     */
    public static String lookupVendor(String mac) {
        if (mac == null || mac.length() < 8) return null;
        // Use the System's vendor lookup
        try {
            byte[] macBytes = NetworkHelper.macToBytes(mac);
            if (macBytes != null) {
                return org.csploit.android.core.System.getMacVendor(macBytes);
            }
        } catch (Exception e) {
            LoggingHelper.d(TAG, "Failed to lookup vendor: " + e.getMessage());
        }
        return null;
    }

    /**
     * Identify service by port number
     */
    public static String identifyService(int port) {
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
            case 554: return "RTSP";
            case 631: return "IPP/CUPS";
            case 993: return "IMAPS";
            case 995: return "POP3S";
            case 1433: return "MSSQL";
            case 3306: return "MySQL";
            case 3389: return "RDP";
            case 5432: return "PostgreSQL";
            case 5555: return "ADB";
            case 5900: return "VNC";
            case 6379: return "Redis";
            case 8080: return "HTTP-Alt";
            case 8443: return "HTTPS-Alt";
            case 9100: return "JetDirect";
            case 27017: return "MongoDB";
            case 62078: return "Apple-iDevice";
            default: return null;
        }
    }

    // ==================== ARP Scan ====================

    /**
     * Get all devices from ARP cache (very fast, but only shows recently communicated devices)
     *
     * @return list of discovered devices from ARP cache
     */
    public static List<DiscoveredDevice> getArpCacheDevices() {
        List<DiscoveredDevice> devices = new ArrayList<>();
        BufferedReader reader = null;

        try {
            reader = new BufferedReader(new FileReader("/proc/net/arp"));
            String line;
            boolean firstLine = true;

            while ((line = reader.readLine()) != null) {
                if (firstLine) {
                    firstLine = false;
                    continue; // Skip header
                }

                String[] parts = line.split("\\s+");
                if (parts.length >= 4) {
                    String ip = parts[0];
                    String mac = parts[3].toUpperCase(Locale.US);

                    if (!mac.equals("00:00:00:00:00:00") && NetworkHelper.isValidIPv4(ip)) {
                        DiscoveredDevice.Builder builder = new DiscoveredDevice.Builder(ip)
                            .macAddress(mac);

                        String vendor = lookupVendor(mac);
                        if (vendor != null) {
                            builder.vendor(vendor);
                        }

                        devices.add(builder.build());
                    }
                }
            }
        } catch (IOException e) {
            LoggingHelper.e(TAG, "Failed to read ARP cache", e);
        } finally {
            CloseableHelper.close(reader);
        }

        return devices;
    }
}
