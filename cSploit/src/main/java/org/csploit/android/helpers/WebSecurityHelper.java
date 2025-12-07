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
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * WebSecurityHelper - Web application security analysis utilities.
 *
 * Provides:
 * - HTTP security header analysis
 * - Technology detection (server, framework, CMS)
 * - Common vulnerability checks
 * - Web server fingerprinting
 * - Cookie security analysis
 *
 * Usage:
 * {@code
 * // Analyze security headers
 * SecurityHeadersResult result = WebSecurityHelper.analyzeSecurityHeaders("https://example.com");
 *
 * // Detect technologies
 * TechnologyInfo tech = WebSecurityHelper.detectTechnologies("https://example.com");
 *
 * // Check for common issues
 * List<SecurityIssue> issues = WebSecurityHelper.quickSecurityScan("https://example.com");
 * }
 */
public final class WebSecurityHelper {

    private static final String TAG = "WebSecurityHelper";
    private static final int DEFAULT_TIMEOUT = 10000;
    private static final String USER_AGENT = "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36";

    /**
     * Security header analysis result.
     */
    public static class SecurityHeadersResult {
        public boolean hasStrictTransportSecurity;
        public boolean hasContentSecurityPolicy;
        public boolean hasXFrameOptions;
        public boolean hasXContentTypeOptions;
        public boolean hasXXssProtection;
        public boolean hasReferrerPolicy;
        public boolean hasPermissionsPolicy;
        public Map<String, String> headers = new HashMap<>();
        public List<String> missingHeaders = new ArrayList<>();
        public List<String> recommendations = new ArrayList<>();
        public int securityScore; // 0-100

        @NonNull
        @Override
        public String toString() {
            return String.format("SecurityHeaders{score=%d, missing=%d}",
                    securityScore, missingHeaders.size());
        }
    }

    /**
     * Technology detection result.
     */
    public static class TechnologyInfo {
        public String webServer;
        public String webServerVersion;
        public String programmingLanguage;
        public String framework;
        public String cms;
        public String jsLibrary;
        public List<String> detectedTechnologies = new ArrayList<>();
        public Map<String, String> rawHeaders = new HashMap<>();

        @NonNull
        @Override
        public String toString() {
            return String.format("Tech{server='%s', lang='%s', cms='%s'}",
                    webServer, programmingLanguage, cms);
        }
    }

    /**
     * Security issue found during scan.
     */
    public static class SecurityIssue {
        public enum Severity { LOW, MEDIUM, HIGH, CRITICAL }

        public Severity severity;
        public String title;
        public String description;
        public String remediation;
        public String reference;

        public SecurityIssue(Severity severity, String title, String description) {
            this.severity = severity;
            this.title = title;
            this.description = description;
        }

        @NonNull
        @Override
        public String toString() {
            return String.format("[%s] %s", severity, title);
        }
    }

    /**
     * Cookie security analysis result.
     */
    public static class CookieAnalysis {
        public String name;
        public boolean isSecure;
        public boolean isHttpOnly;
        public boolean hasSameSite;
        public String sameSiteValue;
        public boolean hasExpiry;
        public List<String> issues = new ArrayList<>();

        @NonNull
        @Override
        public String toString() {
            return String.format("Cookie{name='%s', secure=%b, httpOnly=%b}",
                    name, isSecure, isHttpOnly);
        }
    }

    private WebSecurityHelper() {}

    /**
     * Analyze security headers for a URL.
     */
    @NonNull
    public static SecurityHeadersResult analyzeSecurityHeaders(@NonNull String urlString) {
        SecurityHeadersResult result = new SecurityHeadersResult();
        HttpURLConnection conn = null;

        try {
            URL url = new URL(urlString);
            conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(DEFAULT_TIMEOUT);
            conn.setReadTimeout(DEFAULT_TIMEOUT);
            conn.setRequestMethod("HEAD");
            conn.setRequestProperty("User-Agent", USER_AGENT);
            conn.connect();

            // Get all headers
            Map<String, List<String>> headerFields = conn.getHeaderFields();
            for (Map.Entry<String, List<String>> entry : headerFields.entrySet()) {
                if (entry.getKey() != null && !entry.getValue().isEmpty()) {
                    result.headers.put(entry.getKey().toLowerCase(), entry.getValue().get(0));
                }
            }

            // Check security headers
            result.hasStrictTransportSecurity = result.headers.containsKey("strict-transport-security");
            result.hasContentSecurityPolicy = result.headers.containsKey("content-security-policy");
            result.hasXFrameOptions = result.headers.containsKey("x-frame-options");
            result.hasXContentTypeOptions = result.headers.containsKey("x-content-type-options");
            result.hasXXssProtection = result.headers.containsKey("x-xss-protection");
            result.hasReferrerPolicy = result.headers.containsKey("referrer-policy");
            result.hasPermissionsPolicy = result.headers.containsKey("permissions-policy");

            // Calculate missing headers
            if (!result.hasStrictTransportSecurity && urlString.startsWith("https")) {
                result.missingHeaders.add("Strict-Transport-Security");
                result.recommendations.add("Add HSTS header to prevent protocol downgrade attacks");
            }
            if (!result.hasContentSecurityPolicy) {
                result.missingHeaders.add("Content-Security-Policy");
                result.recommendations.add("Implement CSP to prevent XSS attacks");
            }
            if (!result.hasXFrameOptions) {
                result.missingHeaders.add("X-Frame-Options");
                result.recommendations.add("Add X-Frame-Options to prevent clickjacking");
            }
            if (!result.hasXContentTypeOptions) {
                result.missingHeaders.add("X-Content-Type-Options");
                result.recommendations.add("Add nosniff header to prevent MIME type sniffing");
            }

            // Calculate security score
            int score = 0;
            if (result.hasStrictTransportSecurity) score += 20;
            if (result.hasContentSecurityPolicy) score += 25;
            if (result.hasXFrameOptions) score += 15;
            if (result.hasXContentTypeOptions) score += 10;
            if (result.hasXXssProtection) score += 10;
            if (result.hasReferrerPolicy) score += 10;
            if (result.hasPermissionsPolicy) score += 10;
            result.securityScore = score;

        } catch (Exception e) {
            Log.e(TAG, "Failed to analyze security headers for " + urlString, e);
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }

        return result;
    }

    /**
     * Detect technologies used by a website.
     */
    @NonNull
    public static TechnologyInfo detectTechnologies(@NonNull String urlString) {
        TechnologyInfo info = new TechnologyInfo();
        HttpURLConnection conn = null;
        StringBuilder content = new StringBuilder();

        try {
            URL url = new URL(urlString);
            conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(DEFAULT_TIMEOUT);
            conn.setReadTimeout(DEFAULT_TIMEOUT);
            conn.setRequestProperty("User-Agent", USER_AGENT);
            conn.connect();

            // Get headers
            Map<String, List<String>> headerFields = conn.getHeaderFields();
            for (Map.Entry<String, List<String>> entry : headerFields.entrySet()) {
                if (entry.getKey() != null && !entry.getValue().isEmpty()) {
                    info.rawHeaders.put(entry.getKey().toLowerCase(), entry.getValue().get(0));
                }
            }

            // Detect from Server header
            String server = info.rawHeaders.get("server");
            if (server != null) {
                parseServerHeader(server, info);
            }

            // Detect from X-Powered-By
            String poweredBy = info.rawHeaders.get("x-powered-by");
            if (poweredBy != null) {
                parsePoweredByHeader(poweredBy, info);
            }

            // Read content for further detection
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                String line;
                int lineCount = 0;
                while ((line = reader.readLine()) != null && lineCount < 500) {
                    content.append(line).append("\n");
                    lineCount++;
                }
            }

            // Detect from content
            String html = content.toString().toLowerCase();
            detectFromContent(html, info);

        } catch (Exception e) {
            Log.e(TAG, "Failed to detect technologies for " + urlString, e);
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }

        return info;
    }

    /**
     * Parse Server header for technology info.
     */
    private static void parseServerHeader(@NonNull String server, @NonNull TechnologyInfo info) {
        String lowerServer = server.toLowerCase();

        if (lowerServer.contains("apache")) {
            info.webServer = "Apache";
            info.detectedTechnologies.add("Apache");
            Matcher m = Pattern.compile("apache/([\\d.]+)").matcher(lowerServer);
            if (m.find()) info.webServerVersion = m.group(1);
        } else if (lowerServer.contains("nginx")) {
            info.webServer = "nginx";
            info.detectedTechnologies.add("nginx");
            Matcher m = Pattern.compile("nginx/([\\d.]+)").matcher(lowerServer);
            if (m.find()) info.webServerVersion = m.group(1);
        } else if (lowerServer.contains("iis")) {
            info.webServer = "Microsoft IIS";
            info.detectedTechnologies.add("Microsoft IIS");
            Matcher m = Pattern.compile("iis/([\\d.]+)").matcher(lowerServer);
            if (m.find()) info.webServerVersion = m.group(1);
        } else if (lowerServer.contains("cloudflare")) {
            info.detectedTechnologies.add("Cloudflare");
        } else if (lowerServer.contains("litespeed")) {
            info.webServer = "LiteSpeed";
            info.detectedTechnologies.add("LiteSpeed");
        }
    }

    /**
     * Parse X-Powered-By header.
     */
    private static void parsePoweredByHeader(@NonNull String poweredBy, @NonNull TechnologyInfo info) {
        String lower = poweredBy.toLowerCase();

        if (lower.contains("php")) {
            info.programmingLanguage = "PHP";
            info.detectedTechnologies.add("PHP");
            Matcher m = Pattern.compile("php/([\\d.]+)").matcher(lower);
            if (m.find()) {
                info.detectedTechnologies.add("PHP " + m.group(1));
            }
        } else if (lower.contains("asp.net")) {
            info.programmingLanguage = "ASP.NET";
            info.detectedTechnologies.add("ASP.NET");
        } else if (lower.contains("express")) {
            info.framework = "Express.js";
            info.programmingLanguage = "Node.js";
            info.detectedTechnologies.add("Express.js");
            info.detectedTechnologies.add("Node.js");
        } else if (lower.contains("servlet")) {
            info.programmingLanguage = "Java";
            info.detectedTechnologies.add("Java Servlet");
        }
    }

    /**
     * Detect technologies from HTML content.
     */
    private static void detectFromContent(@NonNull String html, @NonNull TechnologyInfo info) {
        // CMS Detection
        if (html.contains("wp-content") || html.contains("wp-includes")) {
            info.cms = "WordPress";
            info.detectedTechnologies.add("WordPress");
        } else if (html.contains("joomla") || html.contains("/components/com_")) {
            info.cms = "Joomla";
            info.detectedTechnologies.add("Joomla");
        } else if (html.contains("drupal") || html.contains("/sites/default/")) {
            info.cms = "Drupal";
            info.detectedTechnologies.add("Drupal");
        } else if (html.contains("magento")) {
            info.cms = "Magento";
            info.detectedTechnologies.add("Magento");
        } else if (html.contains("shopify")) {
            info.cms = "Shopify";
            info.detectedTechnologies.add("Shopify");
        }

        // JS Framework Detection
        if (html.contains("react") || html.contains("_reactrootcontainer")) {
            info.jsLibrary = "React";
            info.detectedTechnologies.add("React");
        }
        if (html.contains("angular") || html.contains("ng-")) {
            info.jsLibrary = "Angular";
            info.detectedTechnologies.add("Angular");
        }
        if (html.contains("vue") || html.contains("data-v-")) {
            info.jsLibrary = "Vue.js";
            info.detectedTechnologies.add("Vue.js");
        }
        if (html.contains("jquery")) {
            info.detectedTechnologies.add("jQuery");
        }
        if (html.contains("bootstrap")) {
            info.detectedTechnologies.add("Bootstrap");
        }

        // Other technologies
        if (html.contains("google-analytics") || html.contains("gtag(")) {
            info.detectedTechnologies.add("Google Analytics");
        }
        if (html.contains("cloudflare")) {
            info.detectedTechnologies.add("Cloudflare");
        }
        if (html.contains("recaptcha")) {
            info.detectedTechnologies.add("reCAPTCHA");
        }
    }

    /**
     * Perform a quick security scan.
     */
    @NonNull
    public static List<SecurityIssue> quickSecurityScan(@NonNull String urlString) {
        List<SecurityIssue> issues = new ArrayList<>();

        // Analyze security headers
        SecurityHeadersResult headers = analyzeSecurityHeaders(urlString);

        if (!headers.hasStrictTransportSecurity && urlString.startsWith("https")) {
            issues.add(new SecurityIssue(
                    SecurityIssue.Severity.MEDIUM,
                    "Missing HSTS Header",
                    "Strict-Transport-Security header is not set, making the site vulnerable to protocol downgrade attacks"
            ));
        }

        if (!headers.hasContentSecurityPolicy) {
            issues.add(new SecurityIssue(
                    SecurityIssue.Severity.MEDIUM,
                    "Missing Content Security Policy",
                    "No CSP header found, which increases the risk of XSS attacks"
            ));
        }

        if (!headers.hasXFrameOptions) {
            issues.add(new SecurityIssue(
                    SecurityIssue.Severity.MEDIUM,
                    "Missing X-Frame-Options",
                    "Site may be vulnerable to clickjacking attacks"
            ));
        }

        if (!headers.hasXContentTypeOptions) {
            issues.add(new SecurityIssue(
                    SecurityIssue.Severity.LOW,
                    "Missing X-Content-Type-Options",
                    "Browser MIME-sniffing could lead to security issues"
            ));
        }

        // Check for information disclosure
        String server = headers.headers.get("server");
        if (server != null && (server.contains("/") || Pattern.matches(".*\\d+\\.\\d+.*", server))) {
            issues.add(new SecurityIssue(
                    SecurityIssue.Severity.LOW,
                    "Server Version Disclosure",
                    "Server header reveals version information: " + server
            ));
        }

        String poweredBy = headers.headers.get("x-powered-by");
        if (poweredBy != null) {
            issues.add(new SecurityIssue(
                    SecurityIssue.Severity.LOW,
                    "Technology Disclosure via X-Powered-By",
                    "X-Powered-By header reveals: " + poweredBy
            ));
        }

        // Check for HTTP (not HTTPS)
        if (!urlString.startsWith("https://")) {
            issues.add(new SecurityIssue(
                    SecurityIssue.Severity.HIGH,
                    "No HTTPS",
                    "Site is accessible over unencrypted HTTP connection"
            ));
        }

        return issues;
    }

    /**
     * Analyze cookies from Set-Cookie header.
     */
    @NonNull
    public static List<CookieAnalysis> analyzeCookies(@NonNull String urlString) {
        List<CookieAnalysis> cookies = new ArrayList<>();
        HttpURLConnection conn = null;

        try {
            URL url = new URL(urlString);
            conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(DEFAULT_TIMEOUT);
            conn.setReadTimeout(DEFAULT_TIMEOUT);
            conn.setRequestProperty("User-Agent", USER_AGENT);
            conn.connect();

            Map<String, List<String>> headerFields = conn.getHeaderFields();
            List<String> setCookies = headerFields.get("Set-Cookie");

            if (setCookies != null) {
                for (String cookie : setCookies) {
                    cookies.add(analyzeSingleCookie(cookie));
                }
            }

        } catch (Exception e) {
            Log.e(TAG, "Failed to analyze cookies for " + urlString, e);
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }

        return cookies;
    }

    /**
     * Analyze a single Set-Cookie header value.
     */
    @NonNull
    private static CookieAnalysis analyzeSingleCookie(@NonNull String cookie) {
        CookieAnalysis analysis = new CookieAnalysis();
        String lower = cookie.toLowerCase();

        // Extract cookie name
        int equalsIndex = cookie.indexOf('=');
        if (equalsIndex > 0) {
            analysis.name = cookie.substring(0, equalsIndex).trim();
        }

        // Check for Secure flag
        analysis.isSecure = lower.contains("; secure") || lower.contains(";secure");
        if (!analysis.isSecure) {
            analysis.issues.add("Cookie missing Secure flag");
        }

        // Check for HttpOnly flag
        analysis.isHttpOnly = lower.contains("; httponly") || lower.contains(";httponly");
        if (!analysis.isHttpOnly) {
            analysis.issues.add("Cookie missing HttpOnly flag");
        }

        // Check for SameSite
        analysis.hasSameSite = lower.contains("samesite");
        if (analysis.hasSameSite) {
            if (lower.contains("samesite=strict")) {
                analysis.sameSiteValue = "Strict";
            } else if (lower.contains("samesite=lax")) {
                analysis.sameSiteValue = "Lax";
            } else if (lower.contains("samesite=none")) {
                analysis.sameSiteValue = "None";
            }
        } else {
            analysis.issues.add("Cookie missing SameSite attribute");
        }

        // Check for expiry
        analysis.hasExpiry = lower.contains("expires=") || lower.contains("max-age=");

        return analysis;
    }

    /**
     * Check if URL is accessible.
     */
    public static boolean isAccessible(@NonNull String urlString) {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(urlString);
            conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.setRequestMethod("HEAD");
            conn.connect();
            return conn.getResponseCode() < 400;
        } catch (Exception e) {
            return false;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    /**
     * Get HTTP response code.
     */
    public static int getResponseCode(@NonNull String urlString) {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(urlString);
            conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(DEFAULT_TIMEOUT);
            conn.setReadTimeout(DEFAULT_TIMEOUT);
            conn.setRequestMethod("HEAD");
            conn.connect();
            return conn.getResponseCode();
        } catch (Exception e) {
            return -1;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }
}
