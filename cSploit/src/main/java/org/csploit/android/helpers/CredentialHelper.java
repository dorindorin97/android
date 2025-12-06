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
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * CredentialHelper - Credential extraction and management utilities.
 * 
 * Provides:
 * - Credential pattern detection
 * - Common credential extraction
 * - Password strength analysis
 * - Credential format validation
 * 
 * Usage:
 * {@code
 * // Extract credentials from text
 * List<Credential> creds = CredentialHelper.extractCredentials(text);
 * 
 * // Check password strength
 * PasswordStrength strength = CredentialHelper.analyzePassword("password123");
 * 
 * // Detect credential type
 * CredentialType type = CredentialHelper.detectType(credential);
 * }
 */
public final class CredentialHelper {
    
    private static final String TAG = "CredentialHelper";
    
    // Pattern cache
    private static final Map<String, Pattern> patternCache = new ConcurrentHashMap<>();
    
    /**
     * Credential types.
     */
    public enum CredentialType {
        USERNAME_PASSWORD,
        API_KEY,
        JWT_TOKEN,
        BASIC_AUTH,
        BEARER_TOKEN,
        AWS_KEY,
        PRIVATE_KEY,
        SSH_KEY,
        DATABASE_CONNECTION,
        EMAIL_PASSWORD,
        UNKNOWN
    }
    
    /**
     * Password strength levels.
     */
    public enum PasswordStrength {
        VERY_WEAK(0, "Very Weak"),
        WEAK(1, "Weak"),
        FAIR(2, "Fair"),
        STRONG(3, "Strong"),
        VERY_STRONG(4, "Very Strong");
        
        public final int level;
        public final String description;
        
        PasswordStrength(int level, String description) {
            this.level = level;
            this.description = description;
        }
    }
    
    /**
     * Extracted credential.
     */
    public static class Credential {
        public CredentialType type;
        public String username;
        public String password;
        public String token;
        public String raw;
        public String source;
        public int lineNumber;
        public Map<String, String> metadata;
        
        public Credential(@NonNull CredentialType type) {
            this.type = type;
            this.metadata = new HashMap<>();
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("Credential{type=%s, username='%s'}", type, username);
        }
    }
    
    /**
     * Password analysis result.
     */
    public static class PasswordAnalysis {
        public PasswordStrength strength;
        public int score;
        public int length;
        public boolean hasUppercase;
        public boolean hasLowercase;
        public boolean hasDigits;
        public boolean hasSpecialChars;
        public boolean hasCommonPatterns;
        public List<String> warnings;
        public List<String> suggestions;
        
        public PasswordAnalysis() {
            warnings = new ArrayList<>();
            suggestions = new ArrayList<>();
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("Password{strength=%s, score=%d, length=%d}",
                    strength.description, score, length);
        }
    }
    
    private CredentialHelper() {}
    
    // ==================== Credential Extraction ====================
    
    /**
     * Extract credentials from text.
     */
    @NonNull
    public static List<Credential> extractCredentials(@NonNull String text) {
        List<Credential> credentials = new ArrayList<>();
        
        // Extract Basic Auth
        credentials.addAll(extractBasicAuth(text));
        
        // Extract Bearer tokens
        credentials.addAll(extractBearerTokens(text));
        
        // Extract API keys
        credentials.addAll(extractApiKeys(text));
        
        // Extract JWT tokens
        credentials.addAll(extractJwtTokens(text));
        
        // Extract AWS keys
        credentials.addAll(extractAwsKeys(text));
        
        // Extract database connection strings
        credentials.addAll(extractDbConnectionStrings(text));
        
        // Extract username:password patterns
        credentials.addAll(extractUsernamePassword(text));
        
        return credentials;
    }
    
    /**
     * Extract Basic Auth credentials.
     */
    @NonNull
    public static List<Credential> extractBasicAuth(@NonNull String text) {
        List<Credential> credentials = new ArrayList<>();
        
        Pattern pattern = getPattern("Basic\\s+([A-Za-z0-9+/]+=*)");
        Matcher matcher = pattern.matcher(text);
        
        while (matcher.find()) {
            try {
                String encoded = matcher.group(1);
                String decoded = new String(android.util.Base64.decode(encoded, android.util.Base64.DEFAULT));
                
                String[] parts = decoded.split(":", 2);
                if (parts.length == 2) {
                    Credential cred = new Credential(CredentialType.BASIC_AUTH);
                    cred.username = parts[0];
                    cred.password = parts[1];
                    cred.raw = matcher.group(0);
                    credentials.add(cred);
                }
            } catch (Exception e) {
                Log.d(TAG, "Failed to decode Basic Auth", e);
            }
        }
        
        return credentials;
    }
    
    /**
     * Extract Bearer tokens.
     */
    @NonNull
    public static List<Credential> extractBearerTokens(@NonNull String text) {
        List<Credential> credentials = new ArrayList<>();
        
        Pattern pattern = getPattern("Bearer\\s+([A-Za-z0-9\\-_=]+\\.?[A-Za-z0-9\\-_=]*\\.?[A-Za-z0-9\\-_=]*)");
        Matcher matcher = pattern.matcher(text);
        
        while (matcher.find()) {
            Credential cred = new Credential(CredentialType.BEARER_TOKEN);
            cred.token = matcher.group(1);
            cred.raw = matcher.group(0);
            credentials.add(cred);
        }
        
        return credentials;
    }
    
    /**
     * Extract API keys.
     */
    @NonNull
    public static List<Credential> extractApiKeys(@NonNull String text) {
        List<Credential> credentials = new ArrayList<>();
        
        // Common API key patterns
        String[] patterns = {
            "api[_-]?key[\"':\\s=]+([A-Za-z0-9\\-_]{20,})",
            "apikey[\"':\\s=]+([A-Za-z0-9\\-_]{20,})",
            "x-api-key[\"':\\s=]+([A-Za-z0-9\\-_]{20,})",
            "secret[_-]?key[\"':\\s=]+([A-Za-z0-9\\-_]{20,})",
            "access[_-]?token[\"':\\s=]+([A-Za-z0-9\\-_]{20,})"
        };
        
        for (String patternStr : patterns) {
            Pattern pattern = getPattern(patternStr);
            Matcher matcher = pattern.matcher(text.toLowerCase());
            
            int searchFrom = 0;
            while (matcher.find(searchFrom)) {
                // Get actual case-sensitive value from original text
                int start = matcher.start(1);
                int end = matcher.end(1);
                
                Credential cred = new Credential(CredentialType.API_KEY);
                cred.token = text.substring(start, end);
                cred.raw = text.substring(matcher.start(), matcher.end());
                credentials.add(cred);
                
                searchFrom = matcher.end();
            }
        }
        
        return credentials;
    }
    
    /**
     * Extract JWT tokens.
     */
    @NonNull
    public static List<Credential> extractJwtTokens(@NonNull String text) {
        List<Credential> credentials = new ArrayList<>();
        
        // JWT pattern: header.payload.signature
        Pattern pattern = getPattern("eyJ[A-Za-z0-9\\-_]+\\.eyJ[A-Za-z0-9\\-_]+\\.[A-Za-z0-9\\-_]+");
        Matcher matcher = pattern.matcher(text);
        
        while (matcher.find()) {
            Credential cred = new Credential(CredentialType.JWT_TOKEN);
            cred.token = matcher.group();
            cred.raw = matcher.group();
            
            // Try to decode JWT header and payload
            try {
                String[] parts = cred.token.split("\\.");
                if (parts.length >= 2) {
                    String header = new String(android.util.Base64.decode(parts[0], android.util.Base64.URL_SAFE));
                    String payload = new String(android.util.Base64.decode(parts[1], android.util.Base64.URL_SAFE));
                    cred.metadata.put("header", header);
                    cred.metadata.put("payload", payload);
                }
            } catch (Exception e) {
                Log.d(TAG, "Failed to decode JWT", e);
            }
            
            credentials.add(cred);
        }
        
        return credentials;
    }
    
    /**
     * Extract AWS keys.
     */
    @NonNull
    public static List<Credential> extractAwsKeys(@NonNull String text) {
        List<Credential> credentials = new ArrayList<>();
        
        // AWS Access Key ID
        Pattern accessKeyPattern = getPattern("AKIA[0-9A-Z]{16}");
        Matcher accessMatcher = accessKeyPattern.matcher(text);
        
        while (accessMatcher.find()) {
            Credential cred = new Credential(CredentialType.AWS_KEY);
            cred.username = accessMatcher.group(); // Access key ID
            cred.raw = accessMatcher.group();
            credentials.add(cred);
        }
        
        // AWS Secret Key (40 char base64)
        Pattern secretPattern = getPattern("aws[_-]?secret[_-]?access[_-]?key[\"':\\s=]+([A-Za-z0-9/+]{40})");
        Matcher secretMatcher = secretPattern.matcher(text.toLowerCase());
        
        int searchFrom = 0;
        while (secretMatcher.find(searchFrom)) {
            // Try to find matching access key credential
            if (!credentials.isEmpty()) {
                Credential lastCred = credentials.get(credentials.size() - 1);
                if (lastCred.type == CredentialType.AWS_KEY && lastCred.password == null) {
                    lastCred.password = text.substring(secretMatcher.start(1), secretMatcher.end(1));
                }
            }
            searchFrom = secretMatcher.end();
        }
        
        return credentials;
    }
    
    /**
     * Extract database connection strings.
     */
    @NonNull
    public static List<Credential> extractDbConnectionStrings(@NonNull String text) {
        List<Credential> credentials = new ArrayList<>();
        
        // MySQL, PostgreSQL, MongoDB connection strings
        String[] patterns = {
            "mysql://([^:]+):([^@]+)@([^/]+)/(.+)",
            "postgres(?:ql)?://([^:]+):([^@]+)@([^/]+)/(.+)",
            "mongodb(?:\\+srv)?://([^:]+):([^@]+)@([^/]+)/(.+)",
            "jdbc:([^:]+)://([^/]+)/([^?]+)\\?user=([^&]+)&password=([^&]+)"
        };
        
        for (String patternStr : patterns) {
            Pattern pattern = getPattern(patternStr);
            Matcher matcher = pattern.matcher(text);
            
            while (matcher.find()) {
                Credential cred = new Credential(CredentialType.DATABASE_CONNECTION);
                cred.raw = matcher.group();
                
                if (matcher.groupCount() >= 2) {
                    cred.username = matcher.group(1);
                    cred.password = matcher.group(2);
                }
                
                credentials.add(cred);
            }
        }
        
        return credentials;
    }
    
    /**
     * Extract username:password patterns.
     */
    @NonNull
    public static List<Credential> extractUsernamePassword(@NonNull String text) {
        List<Credential> credentials = new ArrayList<>();
        
        // URL-style credentials
        Pattern urlPattern = getPattern("(?:https?://)?([^:]+):([^@]+)@[\\w.-]+");
        Matcher urlMatcher = urlPattern.matcher(text);
        
        while (urlMatcher.find()) {
            Credential cred = new Credential(CredentialType.USERNAME_PASSWORD);
            cred.username = urlMatcher.group(1);
            cred.password = urlMatcher.group(2);
            cred.raw = urlMatcher.group();
            credentials.add(cred);
        }
        
        return credentials;
    }
    
    // ==================== Password Analysis ====================
    
    /**
     * Analyze password strength.
     */
    @NonNull
    public static PasswordAnalysis analyzePassword(@NonNull String password) {
        PasswordAnalysis analysis = new PasswordAnalysis();
        analysis.length = password.length();
        
        // Check character classes
        analysis.hasUppercase = password.matches(".*[A-Z].*");
        analysis.hasLowercase = password.matches(".*[a-z].*");
        analysis.hasDigits = password.matches(".*\\d.*");
        analysis.hasSpecialChars = password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?].*");
        
        // Check common patterns
        analysis.hasCommonPatterns = checkCommonPatterns(password);
        
        // Calculate score
        int score = 0;
        
        // Length scoring
        if (analysis.length >= 8) score += 1;
        if (analysis.length >= 12) score += 1;
        if (analysis.length >= 16) score += 1;
        
        // Character class scoring
        if (analysis.hasUppercase) score += 1;
        if (analysis.hasLowercase) score += 1;
        if (analysis.hasDigits) score += 1;
        if (analysis.hasSpecialChars) score += 2;
        
        // Penalties
        if (analysis.hasCommonPatterns) score -= 2;
        if (analysis.length < 8) score -= 2;
        
        // Normalize score
        score = Math.max(0, Math.min(10, score));
        analysis.score = score;
        
        // Determine strength
        if (score <= 2) {
            analysis.strength = PasswordStrength.VERY_WEAK;
        } else if (score <= 4) {
            analysis.strength = PasswordStrength.WEAK;
        } else if (score <= 6) {
            analysis.strength = PasswordStrength.FAIR;
        } else if (score <= 8) {
            analysis.strength = PasswordStrength.STRONG;
        } else {
            analysis.strength = PasswordStrength.VERY_STRONG;
        }
        
        // Generate warnings and suggestions
        generateWarningsAndSuggestions(analysis, password);
        
        return analysis;
    }
    
    /**
     * Check for common password patterns.
     */
    private static boolean checkCommonPatterns(@NonNull String password) {
        String lower = password.toLowerCase();
        
        // Common passwords
        String[] commonPasswords = {
            "password", "123456", "qwerty", "admin", "letmein",
            "welcome", "monkey", "dragon", "master", "login",
            "abc123", "111111", "1234567", "12345678", "123456789"
        };
        
        for (String common : commonPasswords) {
            if (lower.contains(common)) {
                return true;
            }
        }
        
        // Keyboard patterns
        String[] keyboardPatterns = {
            "qwerty", "asdfgh", "zxcvbn", "qazwsx", "1qaz2wsx"
        };
        
        for (String pattern : keyboardPatterns) {
            if (lower.contains(pattern)) {
                return true;
            }
        }
        
        // Sequential characters
        if (lower.matches(".*(.)(\\1){2,}.*")) { // Repeated characters
            return true;
        }
        
        return false;
    }
    
    /**
     * Generate warnings and suggestions.
     */
    private static void generateWarningsAndSuggestions(@NonNull PasswordAnalysis analysis, @NonNull String password) {
        if (analysis.length < 8) {
            analysis.warnings.add("Password is too short");
            analysis.suggestions.add("Use at least 8 characters");
        }
        
        if (!analysis.hasUppercase) {
            analysis.suggestions.add("Add uppercase letters");
        }
        
        if (!analysis.hasLowercase) {
            analysis.suggestions.add("Add lowercase letters");
        }
        
        if (!analysis.hasDigits) {
            analysis.suggestions.add("Add numbers");
        }
        
        if (!analysis.hasSpecialChars) {
            analysis.suggestions.add("Add special characters (!@#$%^&*)");
        }
        
        if (analysis.hasCommonPatterns) {
            analysis.warnings.add("Contains common password patterns");
            analysis.suggestions.add("Avoid common words and patterns");
        }
        
        if (password.matches("^[a-zA-Z]+$")) {
            analysis.warnings.add("Password contains only letters");
        }
        
        if (password.matches("^\\d+$")) {
            analysis.warnings.add("Password contains only numbers");
        }
    }
    
    // ==================== Utilities ====================
    
    /**
     * Get cached pattern.
     */
    @NonNull
    private static Pattern getPattern(@NonNull String regex) {
        return patternCache.computeIfAbsent(regex, k -> 
                Pattern.compile(k, Pattern.CASE_INSENSITIVE));
    }
    
    /**
     * Detect credential type from string.
     */
    @NonNull
    public static CredentialType detectType(@NonNull String credential) {
        String trimmed = credential.trim();
        
        if (trimmed.startsWith("Bearer ")) {
            return CredentialType.BEARER_TOKEN;
        }
        if (trimmed.startsWith("Basic ")) {
            return CredentialType.BASIC_AUTH;
        }
        if (trimmed.startsWith("eyJ") && trimmed.contains(".")) {
            return CredentialType.JWT_TOKEN;
        }
        if (trimmed.startsWith("AKIA") && trimmed.length() == 20) {
            return CredentialType.AWS_KEY;
        }
        if (trimmed.startsWith("-----BEGIN")) {
            return CredentialType.PRIVATE_KEY;
        }
        if (trimmed.contains("@") && trimmed.contains(":")) {
            return CredentialType.DATABASE_CONNECTION;
        }
        if (trimmed.contains(":") && !trimmed.contains(" ")) {
            return CredentialType.USERNAME_PASSWORD;
        }
        
        return CredentialType.UNKNOWN;
    }
    
    /**
     * Mask credential for safe display.
     */
    @NonNull
    public static String maskCredential(@NonNull String credential) {
        if (credential.length() <= 4) {
            return "****";
        }
        
        int showChars = Math.min(4, credential.length() / 4);
        String start = credential.substring(0, showChars);
        String end = credential.substring(credential.length() - showChars);
        
        return start + "****" + end;
    }
    
    /**
     * Generate random password.
     */
    @NonNull
    public static String generatePassword(int length, boolean includeSpecial) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        if (includeSpecial) {
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?";
        }
        
        java.security.SecureRandom random = new java.security.SecureRandom();
        StringBuilder password = new StringBuilder(length);
        
        for (int i = 0; i < length; i++) {
            password.append(chars.charAt(random.nextInt(chars.length())));
        }
        
        return password.toString();
    }
}
