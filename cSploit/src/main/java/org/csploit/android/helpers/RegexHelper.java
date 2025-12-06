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
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * RegexHelper - Regular expression utilities and common patterns.
 * 
 * Provides:
 * - Pre-compiled common patterns
 * - Pattern matching utilities
 * - Data extraction helpers
 * - Regex testing and debugging
 * 
 * Usage:
 * {@code
 * // Check if string is valid email
 * boolean isEmail = RegexHelper.isEmail("test@example.com");
 * 
 * // Extract all IPs from text
 * List<String> ips = RegexHelper.extractAll(text, RegexHelper.IPV4_PATTERN);
 * 
 * // Match and extract groups
 * String[] groups = RegexHelper.matchGroups(text, pattern);
 * }
 */
public final class RegexHelper {
    
    private static final String TAG = "RegexHelper";
    
    // ==================== Common Patterns ====================
    
    // Network patterns
    public static final Pattern IPV4_PATTERN = Pattern.compile(
            "\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b");
    
    public static final Pattern IPV6_PATTERN = Pattern.compile(
            "(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|" +
            "(?:[0-9a-fA-F]{1,4}:){1,7}:|" +
            "(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|" +
            "(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|" +
            "(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|" +
            "(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|" +
            "(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|" +
            "[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|" +
            ":(?::[0-9a-fA-F]{1,4}){1,7}|" +
            "::(?:[fF]{4}:)?(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)");
    
    public static final Pattern MAC_ADDRESS_PATTERN = Pattern.compile(
            "(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}");
    
    public static final Pattern PORT_PATTERN = Pattern.compile(
            "\\b([0-9]{1,5})\\b");
    
    public static final Pattern CIDR_PATTERN = Pattern.compile(
            "\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/([0-9]|[1-2][0-9]|3[0-2])\\b");
    
    // URL patterns
    public static final Pattern URL_PATTERN = Pattern.compile(
            "https?://[\\w\\-._~:/?#\\[\\]@!$&'()*+,;=%]+",
            Pattern.CASE_INSENSITIVE);
    
    public static final Pattern DOMAIN_PATTERN = Pattern.compile(
            "(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}");
    
    // Email patterns
    public static final Pattern EMAIL_PATTERN = Pattern.compile(
            "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}");
    
    // Phone patterns
    public static final Pattern PHONE_PATTERN = Pattern.compile(
            "\\+?[0-9]{1,4}?[-.\\s]?\\(?[0-9]{1,3}?\\)?[-.\\s]?[0-9]{1,4}[-.\\s]?[0-9]{1,4}[-.\\s]?[0-9]{1,9}");
    
    // Hash patterns
    public static final Pattern MD5_PATTERN = Pattern.compile(
            "\\b[a-fA-F0-9]{32}\\b");
    
    public static final Pattern SHA1_PATTERN = Pattern.compile(
            "\\b[a-fA-F0-9]{40}\\b");
    
    public static final Pattern SHA256_PATTERN = Pattern.compile(
            "\\b[a-fA-F0-9]{64}\\b");
    
    // Credential patterns
    public static final Pattern BASE64_PATTERN = Pattern.compile(
            "(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?");
    
    public static final Pattern JWT_PATTERN = Pattern.compile(
            "eyJ[A-Za-z0-9-_]+\\.eyJ[A-Za-z0-9-_]+\\.[A-Za-z0-9-_.+/=]*");
    
    // File patterns
    public static final Pattern FILE_PATH_UNIX_PATTERN = Pattern.compile(
            "/(?:[^/\\0]+/)*[^/\\0]*");
    
    public static final Pattern FILE_PATH_WINDOWS_PATTERN = Pattern.compile(
            "[A-Za-z]:\\\\(?:[^\\\\/:*?\"<>|\\r\\n]+\\\\)*[^\\\\/:*?\"<>|\\r\\n]*");
    
    // Code patterns
    public static final Pattern HTML_TAG_PATTERN = Pattern.compile(
            "<[^>]+>");
    
    public static final Pattern COMMENT_SINGLE_LINE_PATTERN = Pattern.compile(
            "//.*$", Pattern.MULTILINE);
    
    public static final Pattern COMMENT_MULTI_LINE_PATTERN = Pattern.compile(
            "/\\*[\\s\\S]*?\\*/");
    
    private RegexHelper() {}
    
    // ==================== Validation Methods ====================
    
    /**
     * Check if string matches IPv4 pattern.
     */
    public static boolean isIPv4(@NonNull String input) {
        return IPV4_PATTERN.matcher(input.trim()).matches();
    }
    
    /**
     * Check if string matches IPv6 pattern.
     */
    public static boolean isIPv6(@NonNull String input) {
        return IPV6_PATTERN.matcher(input.trim()).matches();
    }
    
    /**
     * Check if string matches IP address (v4 or v6).
     */
    public static boolean isIPAddress(@NonNull String input) {
        return isIPv4(input) || isIPv6(input);
    }
    
    /**
     * Check if string matches MAC address pattern.
     */
    public static boolean isMacAddress(@NonNull String input) {
        return MAC_ADDRESS_PATTERN.matcher(input.trim()).matches();
    }
    
    /**
     * Check if string matches email pattern.
     */
    public static boolean isEmail(@NonNull String input) {
        return EMAIL_PATTERN.matcher(input.trim()).matches();
    }
    
    /**
     * Check if string matches URL pattern.
     */
    public static boolean isUrl(@NonNull String input) {
        return URL_PATTERN.matcher(input.trim()).matches();
    }
    
    /**
     * Check if string matches domain pattern.
     */
    public static boolean isDomain(@NonNull String input) {
        return DOMAIN_PATTERN.matcher(input.trim()).matches();
    }
    
    /**
     * Check if string is valid port number.
     */
    public static boolean isPort(@NonNull String input) {
        try {
            int port = Integer.parseInt(input.trim());
            return port > 0 && port <= 65535;
        } catch (NumberFormatException e) {
            return false;
        }
    }
    
    /**
     * Check if string matches MD5 hash pattern.
     */
    public static boolean isMd5(@NonNull String input) {
        return MD5_PATTERN.matcher(input.trim()).matches();
    }
    
    /**
     * Check if string matches SHA1 hash pattern.
     */
    public static boolean isSha1(@NonNull String input) {
        return SHA1_PATTERN.matcher(input.trim()).matches();
    }
    
    /**
     * Check if string matches SHA256 hash pattern.
     */
    public static boolean isSha256(@NonNull String input) {
        return SHA256_PATTERN.matcher(input.trim()).matches();
    }
    
    /**
     * Check if string matches JWT pattern.
     */
    public static boolean isJwt(@NonNull String input) {
        return JWT_PATTERN.matcher(input.trim()).matches();
    }
    
    // ==================== Extraction Methods ====================
    
    /**
     * Extract all matches of a pattern from text.
     */
    @NonNull
    public static List<String> extractAll(@NonNull String text, @NonNull Pattern pattern) {
        List<String> matches = new ArrayList<>();
        Matcher matcher = pattern.matcher(text);
        
        while (matcher.find()) {
            matches.add(matcher.group());
        }
        
        return matches;
    }
    
    /**
     * Extract all matches with groups.
     */
    @NonNull
    public static List<String[]> extractAllWithGroups(@NonNull String text, @NonNull Pattern pattern) {
        List<String[]> matches = new ArrayList<>();
        Matcher matcher = pattern.matcher(text);
        
        while (matcher.find()) {
            String[] groups = new String[matcher.groupCount() + 1];
            for (int i = 0; i <= matcher.groupCount(); i++) {
                groups[i] = matcher.group(i);
            }
            matches.add(groups);
        }
        
        return matches;
    }
    
    /**
     * Extract first match of a pattern.
     */
    @Nullable
    public static String extractFirst(@NonNull String text, @NonNull Pattern pattern) {
        Matcher matcher = pattern.matcher(text);
        if (matcher.find()) {
            return matcher.group();
        }
        return null;
    }
    
    /**
     * Extract groups from first match.
     */
    @Nullable
    public static String[] matchGroups(@NonNull String text, @NonNull Pattern pattern) {
        Matcher matcher = pattern.matcher(text);
        if (matcher.find()) {
            String[] groups = new String[matcher.groupCount() + 1];
            for (int i = 0; i <= matcher.groupCount(); i++) {
                groups[i] = matcher.group(i);
            }
            return groups;
        }
        return null;
    }
    
    /**
     * Extract all IPv4 addresses from text.
     */
    @NonNull
    public static List<String> extractIPv4Addresses(@NonNull String text) {
        return extractAll(text, IPV4_PATTERN);
    }
    
    /**
     * Extract all MAC addresses from text.
     */
    @NonNull
    public static List<String> extractMacAddresses(@NonNull String text) {
        return extractAll(text, MAC_ADDRESS_PATTERN);
    }
    
    /**
     * Extract all URLs from text.
     */
    @NonNull
    public static List<String> extractUrls(@NonNull String text) {
        return extractAll(text, URL_PATTERN);
    }
    
    /**
     * Extract all emails from text.
     */
    @NonNull
    public static List<String> extractEmails(@NonNull String text) {
        return extractAll(text, EMAIL_PATTERN);
    }
    
    /**
     * Extract all domains from text.
     */
    @NonNull
    public static List<String> extractDomains(@NonNull String text) {
        return extractAll(text, DOMAIN_PATTERN);
    }
    
    /**
     * Extract all hashes from text.
     */
    @NonNull
    public static Map<String, List<String>> extractHashes(@NonNull String text) {
        Map<String, List<String>> hashes = new HashMap<>();
        hashes.put("MD5", extractAll(text, MD5_PATTERN));
        hashes.put("SHA1", extractAll(text, SHA1_PATTERN));
        hashes.put("SHA256", extractAll(text, SHA256_PATTERN));
        return hashes;
    }
    
    // ==================== Utility Methods ====================
    
    /**
     * Replace all matches with replacement string.
     */
    @NonNull
    public static String replaceAll(@NonNull String text, @NonNull Pattern pattern, @NonNull String replacement) {
        return pattern.matcher(text).replaceAll(replacement);
    }
    
    /**
     * Replace first match with replacement string.
     */
    @NonNull
    public static String replaceFirst(@NonNull String text, @NonNull Pattern pattern, @NonNull String replacement) {
        return pattern.matcher(text).replaceFirst(replacement);
    }
    
    /**
     * Count matches in text.
     */
    public static int countMatches(@NonNull String text, @NonNull Pattern pattern) {
        Matcher matcher = pattern.matcher(text);
        int count = 0;
        while (matcher.find()) {
            count++;
        }
        return count;
    }
    
    /**
     * Split text by pattern.
     */
    @NonNull
    public static List<String> split(@NonNull String text, @NonNull Pattern pattern) {
        return Arrays.asList(pattern.split(text));
    }
    
    /**
     * Check if pattern matches anywhere in text.
     */
    public static boolean contains(@NonNull String text, @NonNull Pattern pattern) {
        return pattern.matcher(text).find();
    }
    
    /**
     * Check if pattern matches entire text.
     */
    public static boolean matches(@NonNull String text, @NonNull Pattern pattern) {
        return pattern.matcher(text).matches();
    }
    
    /**
     * Escape special regex characters.
     */
    @NonNull
    public static String escape(@NonNull String input) {
        return Pattern.quote(input);
    }
    
    /**
     * Compile pattern with flags.
     */
    @NonNull
    public static Pattern compile(@NonNull String regex, boolean caseInsensitive, boolean multiline) {
        int flags = 0;
        if (caseInsensitive) flags |= Pattern.CASE_INSENSITIVE;
        if (multiline) flags |= Pattern.MULTILINE;
        return Pattern.compile(regex, flags);
    }
    
    /**
     * Test if regex is valid.
     */
    public static boolean isValidRegex(@NonNull String regex) {
        try {
            Pattern.compile(regex);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Get match positions in text.
     */
    @NonNull
    public static List<int[]> getMatchPositions(@NonNull String text, @NonNull Pattern pattern) {
        List<int[]> positions = new ArrayList<>();
        Matcher matcher = pattern.matcher(text);
        
        while (matcher.find()) {
            positions.add(new int[]{matcher.start(), matcher.end()});
        }
        
        return positions;
    }
    
    /**
     * Strip HTML tags from text.
     */
    @NonNull
    public static String stripHtmlTags(@NonNull String html) {
        return HTML_TAG_PATTERN.matcher(html).replaceAll("");
    }
    
    /**
     * Strip comments from code.
     */
    @NonNull
    public static String stripComments(@NonNull String code) {
        String result = COMMENT_MULTI_LINE_PATTERN.matcher(code).replaceAll("");
        return COMMENT_SINGLE_LINE_PATTERN.matcher(result).replaceAll("");
    }
}
