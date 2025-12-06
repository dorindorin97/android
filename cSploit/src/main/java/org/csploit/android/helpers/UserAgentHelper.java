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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

/**
 * UserAgentHelper - User agent string management and parsing.
 * 
 * Provides:
 * - User agent database
 * - Random user agent generation
 * - User agent parsing
 * - Device/browser detection
 * 
 * Usage:
 * {@code
 * // Get random user agent
 * String ua = UserAgentHelper.getRandomUserAgent();
 * 
 * // Parse user agent
 * UserAgentInfo info = UserAgentHelper.parse(ua);
 * 
 * // Get specific browser UA
 * String chromeUa = UserAgentHelper.getChrome();
 * }
 */
public final class UserAgentHelper {
    
    private static final String TAG = "UserAgentHelper";
    private static final Random random = new Random();
    
    // User agent database
    private static final List<String> DESKTOP_USER_AGENTS = new ArrayList<>();
    private static final List<String> MOBILE_USER_AGENTS = new ArrayList<>();
    private static final List<String> BOT_USER_AGENTS = new ArrayList<>();
    
    // Cache for parsed results
    private static final Map<String, UserAgentInfo> parseCache = new ConcurrentHashMap<>();
    
    static {
        initializeDesktopUserAgents();
        initializeMobileUserAgents();
        initializeBotUserAgents();
    }
    
    /**
     * Parsed user agent information.
     */
    public static class UserAgentInfo {
        public String browser;
        public String browserVersion;
        public String os;
        public String osVersion;
        public String device;
        public String deviceType; // desktop, mobile, tablet, bot
        public String engine;
        public String engineVersion;
        public boolean isMobile;
        public boolean isTablet;
        public boolean isBot;
        public String rawUserAgent;
        
        @NonNull
        @Override
        public String toString() {
            return String.format("%s %s on %s %s (%s)",
                    browser, browserVersion, os, osVersion, deviceType);
        }
    }
    
    private UserAgentHelper() {}
    
    // ==================== User Agent Getters ====================
    
    /**
     * Get random desktop user agent.
     */
    @NonNull
    public static String getRandomDesktopUserAgent() {
        return DESKTOP_USER_AGENTS.get(random.nextInt(DESKTOP_USER_AGENTS.size()));
    }
    
    /**
     * Get random mobile user agent.
     */
    @NonNull
    public static String getRandomMobileUserAgent() {
        return MOBILE_USER_AGENTS.get(random.nextInt(MOBILE_USER_AGENTS.size()));
    }
    
    /**
     * Get random user agent (desktop or mobile).
     */
    @NonNull
    public static String getRandomUserAgent() {
        return random.nextBoolean() ? getRandomDesktopUserAgent() : getRandomMobileUserAgent();
    }
    
    /**
     * Get random bot user agent.
     */
    @NonNull
    public static String getRandomBotUserAgent() {
        return BOT_USER_AGENTS.get(random.nextInt(BOT_USER_AGENTS.size()));
    }
    
    /**
     * Get Chrome user agent.
     */
    @NonNull
    public static String getChrome() {
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    }
    
    /**
     * Get Firefox user agent.
     */
    @NonNull
    public static String getFirefox() {
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0";
    }
    
    /**
     * Get Safari user agent.
     */
    @NonNull
    public static String getSafari() {
        return "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15";
    }
    
    /**
     * Get Edge user agent.
     */
    @NonNull
    public static String getEdge() {
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0";
    }
    
    /**
     * Get iPhone user agent.
     */
    @NonNull
    public static String getIPhone() {
        return "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1";
    }
    
    /**
     * Get Android user agent.
     */
    @NonNull
    public static String getAndroid() {
        return "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36";
    }
    
    /**
     * Get Googlebot user agent.
     */
    @NonNull
    public static String getGooglebot() {
        return "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
    }
    
    /**
     * Get curl user agent.
     */
    @NonNull
    public static String getCurl() {
        return "curl/8.4.0";
    }
    
    // ==================== User Agent Parsing ====================
    
    /**
     * Parse user agent string.
     */
    @NonNull
    public static UserAgentInfo parse(@NonNull String userAgent) {
        // Check cache
        UserAgentInfo cached = parseCache.get(userAgent);
        if (cached != null) {
            return cached;
        }
        
        UserAgentInfo info = new UserAgentInfo();
        info.rawUserAgent = userAgent;
        
        String ua = userAgent.toLowerCase();
        
        // Detect bots first
        if (detectBot(info, ua)) {
            info.deviceType = "bot";
            info.isBot = true;
        }
        // Detect mobile/tablet
        else if (detectMobile(info, ua, userAgent)) {
            info.isMobile = true;
            info.deviceType = info.isTablet ? "tablet" : "mobile";
        }
        // Desktop
        else {
            info.deviceType = "desktop";
            detectDesktopBrowser(info, ua, userAgent);
            detectDesktopOS(info, ua, userAgent);
        }
        
        // Detect rendering engine
        detectEngine(info, ua, userAgent);
        
        // Cache result
        parseCache.put(userAgent, info);
        
        return info;
    }
    
    /**
     * Detect bot user agent.
     */
    private static boolean detectBot(@NonNull UserAgentInfo info, @NonNull String ua) {
        if (ua.contains("googlebot")) {
            info.browser = "Googlebot";
            return true;
        }
        if (ua.contains("bingbot")) {
            info.browser = "Bingbot";
            return true;
        }
        if (ua.contains("slurp")) {
            info.browser = "Yahoo! Slurp";
            return true;
        }
        if (ua.contains("duckduckbot")) {
            info.browser = "DuckDuckBot";
            return true;
        }
        if (ua.contains("baiduspider")) {
            info.browser = "Baiduspider";
            return true;
        }
        if (ua.contains("yandexbot")) {
            info.browser = "YandexBot";
            return true;
        }
        if (ua.contains("bot") || ua.contains("spider") || ua.contains("crawler")) {
            info.browser = "Bot";
            return true;
        }
        if (ua.contains("curl")) {
            info.browser = "curl";
            return true;
        }
        if (ua.contains("wget")) {
            info.browser = "wget";
            return true;
        }
        return false;
    }
    
    /**
     * Detect mobile/tablet user agent.
     */
    private static boolean detectMobile(@NonNull UserAgentInfo info, @NonNull String ua, @NonNull String originalUa) {
        // Tablets
        if (ua.contains("ipad")) {
            info.device = "iPad";
            info.os = "iOS";
            info.isTablet = true;
            detectMobileBrowser(info, ua, originalUa);
            return true;
        }
        if (ua.contains("android") && !ua.contains("mobile")) {
            info.device = "Android Tablet";
            info.os = "Android";
            info.isTablet = true;
            detectMobileBrowser(info, ua, originalUa);
            return true;
        }
        
        // Mobile phones
        if (ua.contains("iphone")) {
            info.device = "iPhone";
            info.os = "iOS";
            detectMobileBrowser(info, ua, originalUa);
            return true;
        }
        if (ua.contains("android") && ua.contains("mobile")) {
            info.device = "Android Phone";
            info.os = "Android";
            detectMobileBrowser(info, ua, originalUa);
            return true;
        }
        if (ua.contains("mobile") || ua.contains("phone")) {
            info.device = "Mobile Device";
            detectMobileBrowser(info, ua, originalUa);
            return true;
        }
        
        return false;
    }
    
    /**
     * Detect mobile browser.
     */
    private static void detectMobileBrowser(@NonNull UserAgentInfo info, @NonNull String ua, @NonNull String originalUa) {
        if (ua.contains("crios")) {
            info.browser = "Chrome";
            info.browserVersion = extractVersion(originalUa, "CriOS/");
        } else if (ua.contains("fxios")) {
            info.browser = "Firefox";
            info.browserVersion = extractVersion(originalUa, "FxiOS/");
        } else if (ua.contains("safari") && ua.contains("version")) {
            info.browser = "Safari";
            info.browserVersion = extractVersion(originalUa, "Version/");
        } else if (ua.contains("chrome")) {
            info.browser = "Chrome";
            info.browserVersion = extractVersion(originalUa, "Chrome/");
        } else if (ua.contains("firefox")) {
            info.browser = "Firefox";
            info.browserVersion = extractVersion(originalUa, "Firefox/");
        } else if (ua.contains("samsungbrowser")) {
            info.browser = "Samsung Browser";
            info.browserVersion = extractVersion(originalUa, "SamsungBrowser/");
        } else {
            info.browser = "Mobile Browser";
        }
    }
    
    /**
     * Detect desktop browser.
     */
    private static void detectDesktopBrowser(@NonNull UserAgentInfo info, @NonNull String ua, @NonNull String originalUa) {
        if (ua.contains("edg/") || ua.contains("edge/")) {
            info.browser = "Edge";
            info.browserVersion = extractVersion(originalUa, "Edg/", "Edge/");
        } else if (ua.contains("opr/") || ua.contains("opera")) {
            info.browser = "Opera";
            info.browserVersion = extractVersion(originalUa, "OPR/", "Opera/");
        } else if (ua.contains("vivaldi")) {
            info.browser = "Vivaldi";
            info.browserVersion = extractVersion(originalUa, "Vivaldi/");
        } else if (ua.contains("brave")) {
            info.browser = "Brave";
            info.browserVersion = extractVersion(originalUa, "Brave/");
        } else if (ua.contains("chrome") && !ua.contains("chromium")) {
            info.browser = "Chrome";
            info.browserVersion = extractVersion(originalUa, "Chrome/");
        } else if (ua.contains("chromium")) {
            info.browser = "Chromium";
            info.browserVersion = extractVersion(originalUa, "Chromium/");
        } else if (ua.contains("firefox")) {
            info.browser = "Firefox";
            info.browserVersion = extractVersion(originalUa, "Firefox/");
        } else if (ua.contains("safari") && !ua.contains("chrome")) {
            info.browser = "Safari";
            info.browserVersion = extractVersion(originalUa, "Version/");
        } else if (ua.contains("msie") || ua.contains("trident")) {
            info.browser = "Internet Explorer";
            info.browserVersion = extractVersion(originalUa, "MSIE ", "rv:");
        } else {
            info.browser = "Unknown";
        }
    }
    
    /**
     * Detect desktop OS.
     */
    private static void detectDesktopOS(@NonNull UserAgentInfo info, @NonNull String ua, @NonNull String originalUa) {
        if (ua.contains("windows nt 10")) {
            info.os = "Windows";
            info.osVersion = "10/11";
        } else if (ua.contains("windows nt 6.3")) {
            info.os = "Windows";
            info.osVersion = "8.1";
        } else if (ua.contains("windows nt 6.2")) {
            info.os = "Windows";
            info.osVersion = "8";
        } else if (ua.contains("windows nt 6.1")) {
            info.os = "Windows";
            info.osVersion = "7";
        } else if (ua.contains("windows")) {
            info.os = "Windows";
        } else if (ua.contains("mac os x")) {
            info.os = "macOS";
            info.osVersion = extractMacVersion(originalUa);
        } else if (ua.contains("linux")) {
            info.os = "Linux";
            if (ua.contains("ubuntu")) info.osVersion = "Ubuntu";
            else if (ua.contains("fedora")) info.osVersion = "Fedora";
            else if (ua.contains("debian")) info.osVersion = "Debian";
        } else if (ua.contains("cros")) {
            info.os = "Chrome OS";
        } else {
            info.os = "Unknown";
        }
    }
    
    /**
     * Detect rendering engine.
     */
    private static void detectEngine(@NonNull UserAgentInfo info, @NonNull String ua, @NonNull String originalUa) {
        if (ua.contains("webkit")) {
            info.engine = "WebKit";
            info.engineVersion = extractVersion(originalUa, "AppleWebKit/");
        } else if (ua.contains("gecko")) {
            info.engine = "Gecko";
            info.engineVersion = extractVersion(originalUa, "Gecko/", "rv:");
        } else if (ua.contains("trident")) {
            info.engine = "Trident";
            info.engineVersion = extractVersion(originalUa, "Trident/");
        } else if (ua.contains("presto")) {
            info.engine = "Presto";
            info.engineVersion = extractVersion(originalUa, "Presto/");
        }
    }
    
    /**
     * Extract version from user agent.
     */
    @Nullable
    private static String extractVersion(@NonNull String ua, @NonNull String... prefixes) {
        for (String prefix : prefixes) {
            int start = ua.indexOf(prefix);
            if (start >= 0) {
                start += prefix.length();
                int end = start;
                while (end < ua.length() && (Character.isDigit(ua.charAt(end)) || ua.charAt(end) == '.')) {
                    end++;
                }
                if (end > start) {
                    return ua.substring(start, end);
                }
            }
        }
        return null;
    }
    
    /**
     * Extract macOS version.
     */
    @Nullable
    private static String extractMacVersion(@NonNull String ua) {
        int start = ua.indexOf("Mac OS X ");
        if (start >= 0) {
            start += 9;
            int end = start;
            while (end < ua.length() && (Character.isDigit(ua.charAt(end)) || ua.charAt(end) == '_' || ua.charAt(end) == '.')) {
                end++;
            }
            if (end > start) {
                return ua.substring(start, end).replace('_', '.');
            }
        }
        return null;
    }
    
    // ==================== Initialization ====================
    
    private static void initializeDesktopUserAgents() {
        // Chrome on Windows
        DESKTOP_USER_AGENTS.add("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        DESKTOP_USER_AGENTS.add("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36");
        
        // Chrome on Mac
        DESKTOP_USER_AGENTS.add("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        
        // Firefox on Windows
        DESKTOP_USER_AGENTS.add("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0");
        DESKTOP_USER_AGENTS.add("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0");
        
        // Firefox on Mac
        DESKTOP_USER_AGENTS.add("Mozilla/5.0 (Macintosh; Intel Mac OS X 14.2; rv:121.0) Gecko/20100101 Firefox/121.0");
        
        // Safari on Mac
        DESKTOP_USER_AGENTS.add("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15");
        DESKTOP_USER_AGENTS.add("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15");
        
        // Edge on Windows
        DESKTOP_USER_AGENTS.add("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0");
        
        // Chrome on Linux
        DESKTOP_USER_AGENTS.add("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        
        // Firefox on Linux
        DESKTOP_USER_AGENTS.add("Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0");
    }
    
    private static void initializeMobileUserAgents() {
        // iPhone
        MOBILE_USER_AGENTS.add("Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1");
        MOBILE_USER_AGENTS.add("Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1");
        
        // iPad
        MOBILE_USER_AGENTS.add("Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1");
        
        // Android
        MOBILE_USER_AGENTS.add("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36");
        MOBILE_USER_AGENTS.add("Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36");
        MOBILE_USER_AGENTS.add("Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36");
        
        // Samsung Browser
        MOBILE_USER_AGENTS.add("Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36");
    }
    
    private static void initializeBotUserAgents() {
        BOT_USER_AGENTS.add("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)");
        BOT_USER_AGENTS.add("Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)");
        BOT_USER_AGENTS.add("Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)");
        BOT_USER_AGENTS.add("Mozilla/5.0 (compatible; DuckDuckBot-Https/1.1; https://duckduckgo.com/duckduckbot)");
        BOT_USER_AGENTS.add("Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)");
        BOT_USER_AGENTS.add("Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)");
        BOT_USER_AGENTS.add("curl/8.4.0");
        BOT_USER_AGENTS.add("Wget/1.21.4");
    }
    
    /**
     * Clear parse cache.
     */
    public static void clearCache() {
        parseCache.clear();
    }
    
    /**
     * Get all desktop user agents.
     */
    @NonNull
    public static List<String> getAllDesktopUserAgents() {
        return new ArrayList<>(DESKTOP_USER_AGENTS);
    }
    
    /**
     * Get all mobile user agents.
     */
    @NonNull
    public static List<String> getAllMobileUserAgents() {
        return new ArrayList<>(MOBILE_USER_AGENTS);
    }
}
