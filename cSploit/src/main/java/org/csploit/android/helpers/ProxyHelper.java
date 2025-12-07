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

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ProxyHelper - Network proxy configuration and management.
 * 
 * Provides:
 * - System proxy detection
 * - Proxy authentication
 * - SOCKS and HTTP proxy support
 * - Proxy chain configuration
 * - Connectivity testing through proxies
 * 
 * Usage:
 * {@code
 * // Get system proxy
 * Proxy proxy = ProxyHelper.getSystemProxy();
 * 
 * // Create HTTP proxy
 * Proxy httpProxy = ProxyHelper.createHttpProxy("proxy.example.com", 8080);
 * 
 * // Test proxy
 * boolean works = ProxyHelper.testProxy(proxy, "http://example.com");
 * }
 */
public final class ProxyHelper {
    
    private static final String TAG = "ProxyHelper";
    private static final int DEFAULT_TIMEOUT = 10000; // 10 seconds
    
    // Proxy cache
    private static final Map<String, ProxyInfo> proxyCache = new ConcurrentHashMap<>();
    
    /**
     * Extended proxy information.
     */
    public static class ProxyInfo {
        public Proxy.Type type;
        public String host;
        public int port;
        public String username;
        public String password;
        public boolean requiresAuth;
        public long lastTestedTime;
        public boolean lastTestResult;
        public long latencyMs;
        
        public ProxyInfo(Proxy.Type type, String host, int port) {
            this.type = type;
            this.host = host;
            this.port = port;
        }
        
        @NonNull
        public Proxy toProxy() {
            return new Proxy(type, new InetSocketAddress(host, port));
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("%s://%s:%d", type.name().toLowerCase(), host, port);
        }
    }
    
    /**
     * Proxy test result.
     */
    public static class ProxyTestResult {
        public boolean success;
        public long latencyMs;
        public String externalIp;
        public String errorMessage;
        
        @NonNull
        @Override
        public String toString() {
            return success 
                    ? String.format("Success: latency=%dms, ip=%s", latencyMs, externalIp)
                    : String.format("Failed: %s", errorMessage);
        }
    }
    
    private ProxyHelper() {}
    
    /**
     * Get system default proxy for HTTP.
     */
    @Nullable
    public static Proxy getSystemProxy() {
        return getSystemProxy("http://www.google.com");
    }
    
    /**
     * Get system proxy for a specific URI.
     */
    @Nullable
    public static Proxy getSystemProxy(@NonNull String uriString) {
        try {
            URI uri = new URI(uriString);
            ProxySelector selector = ProxySelector.getDefault();
            if (selector == null) return null;
            
            List<Proxy> proxies = selector.select(uri);
            for (Proxy proxy : proxies) {
                if (proxy.type() != Proxy.Type.DIRECT) {
                    return proxy;
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "Failed to get system proxy", e);
        }
        return null;
    }
    
    /**
     * Get all configured system proxies.
     */
    @NonNull
    public static List<Proxy> getSystemProxies(@NonNull String uriString) {
        List<Proxy> result = new ArrayList<>();
        try {
            URI uri = new URI(uriString);
            ProxySelector selector = ProxySelector.getDefault();
            if (selector != null) {
                result.addAll(selector.select(uri));
            }
        } catch (Exception e) {
            Log.w(TAG, "Failed to get system proxies", e);
        }
        return result;
    }
    
    /**
     * Create HTTP proxy.
     */
    @NonNull
    public static Proxy createHttpProxy(@NonNull String host, int port) {
        return new Proxy(Proxy.Type.HTTP, new InetSocketAddress(host, port));
    }
    
    /**
     * Create SOCKS proxy.
     */
    @NonNull
    public static Proxy createSocksProxy(@NonNull String host, int port) {
        return new Proxy(Proxy.Type.SOCKS, new InetSocketAddress(host, port));
    }
    
    /**
     * Create ProxyInfo with authentication.
     */
    @NonNull
    public static ProxyInfo createAuthenticatedProxy(
            @NonNull Proxy.Type type,
            @NonNull String host,
            int port,
            @NonNull String username,
            @NonNull String password) {
        ProxyInfo info = new ProxyInfo(type, host, port);
        info.username = username;
        info.password = password;
        info.requiresAuth = true;
        return info;
    }
    
    /**
     * Test proxy connectivity.
     */
    @NonNull
    public static ProxyTestResult testProxy(@NonNull Proxy proxy) {
        return testProxy(proxy, "http://www.google.com", DEFAULT_TIMEOUT);
    }
    
    /**
     * Test proxy with custom URL.
     */
    @NonNull
    public static ProxyTestResult testProxy(@NonNull Proxy proxy, @NonNull String testUrl) {
        return testProxy(proxy, testUrl, DEFAULT_TIMEOUT);
    }
    
    /**
     * Test proxy with custom URL and timeout.
     */
    @NonNull
    public static ProxyTestResult testProxy(@NonNull Proxy proxy, @NonNull String testUrl, int timeoutMs) {
        ProxyTestResult result = new ProxyTestResult();
        long startTime = java.lang.System.currentTimeMillis();
        
        java.net.HttpURLConnection conn = null;
        try {
            java.net.URL url = new java.net.URL(testUrl);
            conn = (java.net.HttpURLConnection) url.openConnection(proxy);
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);
            conn.setRequestMethod("GET");
            conn.setRequestProperty("User-Agent", "Mozilla/5.0");
            
            int responseCode = conn.getResponseCode();
            result.latencyMs = java.lang.System.currentTimeMillis() - startTime;
            result.success = (responseCode >= 200 && responseCode < 400);
            
            if (!result.success) {
                result.errorMessage = "HTTP " + responseCode;
            }
            
        } catch (IOException e) {
            result.success = false;
            result.latencyMs = java.lang.System.currentTimeMillis() - startTime;
            result.errorMessage = e.getMessage();
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
        
        return result;
    }
    
    /**
     * Test proxy and get external IP.
     */
    @NonNull
    public static ProxyTestResult testProxyWithIpCheck(@NonNull Proxy proxy) {
        ProxyTestResult result = new ProxyTestResult();
        long startTime = java.lang.System.currentTimeMillis();
        
        java.net.HttpURLConnection conn = null;
        java.io.BufferedReader reader = null;
        try {
            // Use a service that returns IP
            java.net.URL url = new java.net.URL("https://api.ipify.org");
            conn = (java.net.HttpURLConnection) url.openConnection(proxy);
            conn.setConnectTimeout(DEFAULT_TIMEOUT);
            conn.setReadTimeout(DEFAULT_TIMEOUT);
            conn.setRequestMethod("GET");
            
            int responseCode = conn.getResponseCode();
            result.latencyMs = java.lang.System.currentTimeMillis() - startTime;
            
            if (responseCode == 200) {
                reader = new java.io.BufferedReader(new java.io.InputStreamReader(conn.getInputStream()));
                result.externalIp = reader.readLine();
                result.success = true;
            } else {
                result.success = false;
                result.errorMessage = "HTTP " + responseCode;
            }
            
        } catch (IOException e) {
            result.success = false;
            result.latencyMs = java.lang.System.currentTimeMillis() - startTime;
            result.errorMessage = e.getMessage();
        } finally {
            if (reader != null) {
                try { reader.close(); } catch (IOException e) { Log.d(TAG, "Failed to close reader: " + e.getMessage()); }
            }
            if (conn != null) {
                conn.disconnect();
            }
        }
        
        return result;
    }
    
    /**
     * Check if proxy requires authentication.
     */
    public static boolean requiresAuthentication(@NonNull Proxy proxy) {
        java.net.HttpURLConnection conn = null;
        try {
            java.net.URL url = new java.net.URL("http://www.google.com");
            conn = (java.net.HttpURLConnection) url.openConnection(proxy);
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.setRequestMethod("GET");
            
            int responseCode = conn.getResponseCode();
            return responseCode == 407; // Proxy Authentication Required
            
        } catch (IOException e) {
            return false;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }
    
    /**
     * Parse proxy URL string.
     * Formats: host:port, http://host:port, socks://host:port, http://user:pass@host:port
     */
    @Nullable
    public static ProxyInfo parseProxyUrl(@NonNull String proxyUrl) {
        try {
            String url = proxyUrl.trim();
            
            // Determine type
            Proxy.Type type = Proxy.Type.HTTP;
            if (url.toLowerCase().startsWith("socks://") || url.toLowerCase().startsWith("socks5://")) {
                type = Proxy.Type.SOCKS;
                url = url.substring(url.indexOf("://") + 3);
            } else if (url.toLowerCase().startsWith("http://")) {
                url = url.substring(7);
            } else if (url.toLowerCase().startsWith("https://")) {
                url = url.substring(8);
            }
            
            // Extract credentials if present
            String username = null;
            String password = null;
            int atIndex = url.indexOf('@');
            if (atIndex > 0) {
                String credentials = url.substring(0, atIndex);
                url = url.substring(atIndex + 1);
                
                int colonIndex = credentials.indexOf(':');
                if (colonIndex > 0) {
                    username = credentials.substring(0, colonIndex);
                    password = credentials.substring(colonIndex + 1);
                } else {
                    username = credentials;
                }
            }
            
            // Extract host and port
            int colonIndex = url.lastIndexOf(':');
            if (colonIndex <= 0) {
                return null; // Invalid format
            }
            
            String host = url.substring(0, colonIndex);
            int port = Integer.parseInt(url.substring(colonIndex + 1));
            
            ProxyInfo info = new ProxyInfo(type, host, port);
            if (username != null) {
                info.username = username;
                info.password = password;
                info.requiresAuth = true;
            }
            
            return info;
            
        } catch (Exception e) {
            Log.w(TAG, "Failed to parse proxy URL: " + proxyUrl, e);
            return null;
        }
    }
    
    /**
     * Get proxy address info.
     */
    @Nullable
    public static InetSocketAddress getProxyAddress(@NonNull Proxy proxy) {
        SocketAddress address = proxy.address();
        if (address instanceof InetSocketAddress) {
            return (InetSocketAddress) address;
        }
        return null;
    }
    
    /**
     * Check if proxy is available (quick check).
     */
    public static boolean isProxyAvailable(@NonNull String host, int port, int timeoutMs) {
        try (java.net.Socket socket = new java.net.Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            return true;
        } catch (IOException e) {
            return false;
        }
    }
    
    /**
     * Get cached proxy or create new.
     */
    @NonNull
    public static ProxyInfo getOrCreateProxy(@NonNull Proxy.Type type, @NonNull String host, int port) {
        String key = type.name() + ":" + host + ":" + port;
        return proxyCache.computeIfAbsent(key, k -> new ProxyInfo(type, host, port));
    }
    
    /**
     * Clear proxy cache.
     */
    public static void clearCache() {
        proxyCache.clear();
    }
    
    /**
     * Get common proxy ports.
     */
    @NonNull
    public static int[] getCommonProxyPorts() {
        return new int[]{
            80,     // HTTP
            443,    // HTTPS
            1080,   // SOCKS
            3128,   // Squid
            8080,   // HTTP Proxy
            8118,   // Privoxy
            8888,   // HTTP Proxy alt
            9050,   // Tor SOCKS
            9150    // Tor Browser SOCKS
        };
    }
    
    /**
     * Set JVM-wide proxy settings.
     */
    public static void setSystemProxy(@NonNull ProxyInfo proxy) {
        if (proxy.type == Proxy.Type.HTTP) {
            System.setProperty("http.proxyHost", proxy.host);
            System.setProperty("http.proxyPort", String.valueOf(proxy.port));
            System.setProperty("https.proxyHost", proxy.host);
            System.setProperty("https.proxyPort", String.valueOf(proxy.port));
            
            if (proxy.requiresAuth && proxy.username != null) {
                System.setProperty("http.proxyUser", proxy.username);
                System.setProperty("http.proxyPassword", proxy.password != null ? proxy.password : "");
            }
        } else if (proxy.type == Proxy.Type.SOCKS) {
            System.setProperty("socksProxyHost", proxy.host);
            System.setProperty("socksProxyPort", String.valueOf(proxy.port));
            
            if (proxy.requiresAuth && proxy.username != null) {
                System.setProperty("java.net.socks.username", proxy.username);
                System.setProperty("java.net.socks.password", proxy.password != null ? proxy.password : "");
            }
        }
    }
    
    /**
     * Clear JVM-wide proxy settings.
     */
    public static void clearSystemProxy() {
        System.clearProperty("http.proxyHost");
        System.clearProperty("http.proxyPort");
        System.clearProperty("https.proxyHost");
        System.clearProperty("https.proxyPort");
        System.clearProperty("http.proxyUser");
        System.clearProperty("http.proxyPassword");
        System.clearProperty("socksProxyHost");
        System.clearProperty("socksProxyPort");
        System.clearProperty("java.net.socks.username");
        System.clearProperty("java.net.socks.password");
    }
}
