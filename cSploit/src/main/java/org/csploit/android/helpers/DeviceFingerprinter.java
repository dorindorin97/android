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

import android.os.Handler;
import org.csploit.android.helpers.LoggingHelper;
import android.os.Looper;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * DeviceFingerprinter - OS and device fingerprinting utilities.
 * 
 * Provides methods for:
 * - OS detection via TTL analysis
 * - HTTP server fingerprinting
 * - Service banner grabbing
 * - MAC address OUI vendor lookup
 * - Device type inference
 * 
 * Usage:
 * {@code
 * // Get OS guess from TTL
 * String os = DeviceFingerprinter.guessOsFromTtl(ttlValue);
 * 
 * // Fingerprint via HTTP
 * DeviceFingerprinter.fingerprintHttp("192.168.1.1", result -> {
 *     Log.d(TAG, "Server: " + result.serverHeader);
 * });
 * }
 */
public final class DeviceFingerprinter {
    
    public static final String TAG = "DeviceFingerprinter";
    
    private static final int BANNER_TIMEOUT_MS = 3000;
    private static final int HTTP_TIMEOUT_MS = 5000;
    
    private static final ExecutorService executor = Executors.newCachedThreadPool();
    private static final Handler mainHandler = new Handler(Looper.getMainLooper());
    
    // Common TTL values and their typical OS
    private static final int TTL_LINUX = 64;
    private static final int TTL_WINDOWS = 128;
    private static final int TTL_CISCO = 255;
    private static final int TTL_SOLARIS = 255;
    
    private DeviceFingerprinter() {}
    
    /**
     * Fingerprint result containing gathered information.
     */
    public static class FingerprintResult {
        public final String host;
        public String osGuess;
        public String serverHeader;
        public String deviceType;
        public String vendor;
        public Map<Integer, String> banners;
        public Map<String, String> httpHeaders;
        
        public FingerprintResult(String host) {
            this.host = host;
            this.banners = new HashMap<>();
            this.httpHeaders = new HashMap<>();
        }
        
        @NonNull
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("Fingerprint for ").append(host).append(":\n");
            if (osGuess != null) sb.append("  OS: ").append(osGuess).append("\n");
            if (deviceType != null) sb.append("  Type: ").append(deviceType).append("\n");
            if (vendor != null) sb.append("  Vendor: ").append(vendor).append("\n");
            if (serverHeader != null) sb.append("  Server: ").append(serverHeader).append("\n");
            return sb.toString();
        }
    }
    
    /**
     * Callback for fingerprint operations.
     */
    public interface FingerprintCallback {
        void onComplete(FingerprintResult result);
    }
    
    /**
     * Guess OS from TTL value.
     * 
     * @param ttl Time To Live value
     * @return guessed OS or "Unknown"
     */
    @NonNull
    public static String guessOsFromTtl(int ttl) {
        if (ttl <= 0) return "Unknown";
        
        // Normalize TTL to initial value
        int normalizedTtl;
        if (ttl <= 64) {
            normalizedTtl = 64;
        } else if (ttl <= 128) {
            normalizedTtl = 128;
        } else {
            normalizedTtl = 255;
        }
        
        switch (normalizedTtl) {
            case 64:
                return "Linux/Unix/macOS";
            case 128:
                return "Windows";
            case 255:
                return "Cisco/Solaris/Network Device";
            default:
                return "Unknown";
        }
    }
    
    /**
     * Get device type from open ports.
     * 
     * @param openPorts array of open port numbers
     * @return inferred device type
     */
    @NonNull
    public static String inferDeviceType(@Nullable int[] openPorts) {
        if (openPorts == null || openPorts.length == 0) {
            return "Unknown";
        }
        
        boolean hasWeb = false;
        boolean hasSSH = false;
        boolean hasSMB = false;
        boolean hasRDP = false;
        boolean hasPrinter = false;
        boolean hasRouter = false;
        
        for (int port : openPorts) {
            switch (port) {
                case 80:
                case 443:
                case 8080:
                    hasWeb = true;
                    break;
                case 22:
                    hasSSH = true;
                    break;
                case 445:
                case 139:
                    hasSMB = true;
                    break;
                case 3389:
                    hasRDP = true;
                    break;
                case 515:
                case 631:
                case 9100:
                    hasPrinter = true;
                    break;
                case 23:
                case 161:
                case 162:
                    hasRouter = true;
                    break;
            }
        }
        
        if (hasPrinter) return "Printer";
        if (hasRDP && hasSMB) return "Windows Workstation";
        if (hasRDP) return "Windows Server/Desktop";
        if (hasSMB && !hasSSH) return "Windows Device";
        if (hasRouter && !hasSMB) return "Router/Network Device";
        if (hasSSH && hasWeb) return "Linux Server";
        if (hasSSH) return "Unix/Linux Device";
        if (hasWeb) return "Web Server";
        
        return "Unknown Device";
    }
    
    /**
     * Get vendor from MAC address OUI.
     * 
     * @param macAddress MAC address string
     * @return vendor name or "Unknown"
     */
    @NonNull
    public static String getVendorFromMac(@Nullable String macAddress) {
        if (macAddress == null || macAddress.length() < 8) {
            return "Unknown";
        }
        
        // Normalize and extract OUI (first 3 octets)
        String normalized = macAddress.toUpperCase()
                .replace(":", "")
                .replace("-", "")
                .replace(".", "");
        
        if (normalized.length() < 6) {
            return "Unknown";
        }
        
        String oui = normalized.substring(0, 6);
        
        // Common OUI mappings (add more as needed)
        Map<String, String> ouiMap = getOuiMap();
        String vendor = ouiMap.get(oui);
        
        return vendor != null ? vendor : "Unknown (" + formatOui(oui) + ")";
    }
    
    /**
     * Get common OUI to vendor mappings.
     */
    @NonNull
    private static Map<String, String> getOuiMap() {
        Map<String, String> map = new HashMap<>();
        
        // Apple
        map.put("00CD2B", "Apple");
        map.put("3C0754", "Apple");
        map.put("A4D1D2", "Apple");
        map.put("F0DCE2", "Apple");
        map.put("70CD60", "Apple");
        
        // Samsung
        map.put("A89FBA", "Samsung");
        map.put("5C3C27", "Samsung");
        map.put("84252E", "Samsung");
        map.put("F47B5E", "Samsung");
        
        // Google
        map.put("F4F5D8", "Google");
        map.put("94EB2C", "Google");
        map.put("54ACFB", "Google");
        
        // Microsoft
        map.put("00155D", "Microsoft");
        map.put("0050F2", "Microsoft");
        map.put("28187F", "Microsoft");
        
        // Intel
        map.put("001E64", "Intel");
        map.put("3497F6", "Intel");
        map.put("6CA100", "Intel");
        
        // Cisco
        map.put("00000C", "Cisco");
        map.put("001642", "Cisco");
        map.put("0023EA", "Cisco");
        
        // TP-Link
        map.put("30B49E", "TP-Link");
        map.put("5C628B", "TP-Link");
        map.put("640980", "TP-Link");
        
        // Netgear
        map.put("004A77", "Netgear");
        map.put("008EF2", "Netgear");
        map.put("C43DC7", "Netgear");
        
        // Asus
        map.put("001A92", "Asus");
        map.put("0800F7", "Asus");
        map.put("50465D", "Asus");
        
        // Dell
        map.put("001E4F", "Dell");
        map.put("00215D", "Dell");
        map.put("848F69", "Dell");
        
        // HP
        map.put("001635", "HP");
        map.put("00215A", "HP");
        map.put("3C4A92", "HP");
        
        // VMware
        map.put("000C29", "VMware");
        map.put("005056", "VMware");
        map.put("000569", "VMware");
        
        // Amazon
        map.put("40B4CD", "Amazon");
        map.put("FC65DE", "Amazon");
        map.put("747E2D", "Amazon");
        
        // Raspberry Pi
        map.put("B827EB", "Raspberry Pi");
        map.put("DC3A2A", "Raspberry Pi");
        map.put("E45F01", "Raspberry Pi");
        
        return map;
    }
    
    /**
     * Format OUI for display.
     */
    @NonNull
    private static String formatOui(@NonNull String oui) {
        if (oui.length() != 6) return oui;
        return oui.substring(0, 2) + ":" + oui.substring(2, 4) + ":" + oui.substring(4, 6);
    }
    
    /**
     * Grab banner from a TCP service.
     * 
     * @param host hostname or IP
     * @param port port number
     * @param timeoutMs timeout in milliseconds
     * @return banner string or null
     */
    @Nullable
    public static String grabBanner(@NonNull String host, int port, int timeoutMs) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            socket.setSoTimeout(timeoutMs);
            
            // Send minimal probe for some services
            if (port == 80 || port == 8080) {
                socket.getOutputStream().write("HEAD / HTTP/1.0\r\n\r\n".getBytes());
            } else if (port == 21) {
                // FTP sends banner automatically
            } else if (port == 22) {
                // SSH sends banner automatically
            } else if (port == 25) {
                // SMTP sends banner automatically
            }
            
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream()));
            
            StringBuilder banner = new StringBuilder();
            String line;
            int lines = 0;
            while ((line = reader.readLine()) != null && lines < 5) {
                banner.append(line).append("\n");
                lines++;
            }
            
            return banner.toString().trim();
            
        } catch (IOException e) {
            LoggingHelper.d(TAG, "Banner grab failed for " + host + ":" + port + ": " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Fingerprint an HTTP server.
     * 
     * @param host hostname or IP
     * @param port port number (80 or 443)
     * @return fingerprint result
     */
    @NonNull
    public static FingerprintResult fingerprintHttp(@NonNull String host, int port) {
        FingerprintResult result = new FingerprintResult(host);
        
        String protocol = (port == 443) ? "https" : "http";
        String urlStr = protocol + "://" + host + ":" + port + "/";
        
        try {
            URL url = new URL(urlStr);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(HTTP_TIMEOUT_MS);
            conn.setReadTimeout(HTTP_TIMEOUT_MS);
            conn.setRequestMethod("HEAD");
            conn.setInstanceFollowRedirects(false);
            
            conn.connect();
            
            // Collect headers
            Map<String, java.util.List<String>> headers = conn.getHeaderFields();
            for (Map.Entry<String, java.util.List<String>> entry : headers.entrySet()) {
                if (entry.getKey() != null && !entry.getValue().isEmpty()) {
                    result.httpHeaders.put(entry.getKey(), entry.getValue().get(0));
                }
            }
            
            // Extract server header
            result.serverHeader = conn.getHeaderField("Server");
            
            // Try to guess OS from server header
            if (result.serverHeader != null) {
                result.osGuess = guessOsFromServerHeader(result.serverHeader);
            }
            
            // Get X-Powered-By for framework detection
            String poweredBy = conn.getHeaderField("X-Powered-By");
            if (poweredBy != null) {
                result.httpHeaders.put("X-Powered-By", poweredBy);
            }
            
            conn.disconnect();
            
        } catch (IOException e) {
            LoggingHelper.d(TAG, "HTTP fingerprint failed: " + e.getMessage());
        }
        
        return result;
    }
    
    /**
     * Fingerprint HTTP server asynchronously.
     * 
     * @param host hostname or IP
     * @param callback result callback
     */
    public static void fingerprintHttpAsync(@NonNull String host, @NonNull FingerprintCallback callback) {
        executor.execute(() -> {
            FingerprintResult result = fingerprintHttp(host, 80);
            mainHandler.post(() -> callback.onComplete(result));
        });
    }
    
    /**
     * Guess OS from HTTP server header.
     * 
     * @param serverHeader Server header value
     * @return OS guess or null
     */
    @Nullable
    public static String guessOsFromServerHeader(@Nullable String serverHeader) {
        if (serverHeader == null) return null;
        
        String lower = serverHeader.toLowerCase();
        
        if (lower.contains("iis")) {
            return "Windows (IIS)";
        } else if (lower.contains("ubuntu") || lower.contains("debian")) {
            return "Linux (Debian/Ubuntu)";
        } else if (lower.contains("centos") || lower.contains("red hat") || lower.contains("rhel")) {
            return "Linux (RHEL/CentOS)";
        } else if (lower.contains("fedora")) {
            return "Linux (Fedora)";
        } else if (lower.contains("freebsd")) {
            return "FreeBSD";
        } else if (lower.contains("unix") || lower.contains("linux")) {
            return "Unix/Linux";
        } else if (lower.contains("darwin") || lower.contains("macos")) {
            return "macOS";
        } else if (lower.contains("win")) {
            return "Windows";
        }
        
        return null;
    }
    
    /**
     * Parse SSH banner for OS/version info.
     * 
     * @param banner SSH banner string
     * @return parsed info map
     */
    @NonNull
    public static Map<String, String> parseSshBanner(@Nullable String banner) {
        Map<String, String> info = new HashMap<>();
        
        if (banner == null || banner.isEmpty()) {
            return info;
        }
        
        // SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
        Pattern sshPattern = Pattern.compile("SSH-([\\d.]+)-(.+)");
        Matcher matcher = sshPattern.matcher(banner.trim());
        
        if (matcher.find()) {
            info.put("protocol", matcher.group(1));
            String impl = matcher.group(2);
            info.put("implementation", impl);
            
            // Try to extract OS
            String lower = impl.toLowerCase();
            if (lower.contains("ubuntu")) {
                info.put("os", "Ubuntu Linux");
            } else if (lower.contains("debian")) {
                info.put("os", "Debian Linux");
            } else if (lower.contains("freebsd")) {
                info.put("os", "FreeBSD");
            } else if (lower.contains("openbsd")) {
                info.put("os", "OpenBSD");
            }
        }
        
        return info;
    }
    
    /**
     * Comprehensive fingerprint of a host.
     * 
     * @param host hostname or IP
     * @param macAddress MAC address (optional)
     * @param openPorts open ports (optional)
     * @param callback result callback
     */
    public static void comprehensiveFingerprint(@NonNull String host, 
                                                @Nullable String macAddress,
                                                @Nullable int[] openPorts,
                                                @NonNull FingerprintCallback callback) {
        executor.execute(() -> {
            FingerprintResult result = new FingerprintResult(host);
            
            // Get vendor from MAC
            if (macAddress != null) {
                result.vendor = getVendorFromMac(macAddress);
            }
            
            // Infer device type from ports
            if (openPorts != null) {
                result.deviceType = inferDeviceType(openPorts);
            }
            
            // Try HTTP fingerprinting if web ports are open
            if (openPorts != null) {
                for (int port : openPorts) {
                    if (port == 80 || port == 8080) {
                        FingerprintResult httpResult = fingerprintHttp(host, port);
                        result.serverHeader = httpResult.serverHeader;
                        result.httpHeaders.putAll(httpResult.httpHeaders);
                        if (httpResult.osGuess != null) {
                            result.osGuess = httpResult.osGuess;
                        }
                        break;
                    }
                }
            }
            
            // Try SSH banner if port 22 is open
            if (openPorts != null) {
                for (int port : openPorts) {
                    if (port == 22) {
                        String banner = grabBanner(host, 22, BANNER_TIMEOUT_MS);
                        if (banner != null) {
                            result.banners.put(22, banner);
                            Map<String, String> sshInfo = parseSshBanner(banner);
                            if (sshInfo.containsKey("os") && result.osGuess == null) {
                                result.osGuess = sshInfo.get("os");
                            }
                        }
                        break;
                    }
                }
            }
            
            mainHandler.post(() -> callback.onComplete(result));
        });
    }
    
    /**
     * Shutdown the executor service.
     */
    public static void shutdown() {
        executor.shutdownNow();
    }
}
