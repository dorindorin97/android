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

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AuthTokenHelper - Authentication token management utilities.
 * 
 * Provides:
 * - Token generation (JWT-like, API keys)
 * - Token validation
 * - Token storage and caching
 * - Token expiration handling
 * - Session management
 * 
 * Usage:
 * {@code
 * // Generate token
 * String token = AuthTokenHelper.generateToken("user123", 3600);
 * 
 * // Validate token
 * TokenInfo info = AuthTokenHelper.validateToken(token);
 * 
 * // Create session
 * String sessionId = AuthTokenHelper.createSession("user123");
 * }
 */
public final class AuthTokenHelper {
    
    private static final String TAG = "AuthTokenHelper";
    
    private static final int TOKEN_LENGTH = 32;
    private static final int API_KEY_LENGTH = 40;
    @SuppressWarnings("unused") // Reserved for encrypted tokens
    private static final String TOKEN_ALGORITHM = "AES";
    private static final String HASH_ALGORITHM = "SHA-256";
    
    private static final ConcurrentHashMap<String, TokenInfo> tokenCache = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, SessionInfo> sessionCache = new ConcurrentHashMap<>();
    private static final SecureRandom secureRandom = new SecureRandom();
    
    private static final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private static byte[] secretKey = null;
    
    // Start cleanup task
    static {
        scheduler.scheduleAtFixedRate(AuthTokenHelper::cleanupExpired, 1, 1, TimeUnit.MINUTES);
    }
    
    /**
     * Token types.
     */
    public enum TokenType {
        BEARER,
        API_KEY,
        REFRESH,
        ACCESS,
        CSRF,
        SESSION
    }
    
    /**
     * Token information.
     */
    public static class TokenInfo {
        public String token;
        public String subject;          // User ID or identifier
        public TokenType type;
        public long createdAt;
        public long expiresAt;
        public Map<String, String> claims;
        public boolean isValid;
        
        public boolean isExpired() {
            return java.lang.System.currentTimeMillis() > expiresAt;
        }
        
        public long getRemainingTimeMs() {
            return expiresAt - java.lang.System.currentTimeMillis();
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("TokenInfo{subject='%s', type=%s, valid=%s, expires=%dms}",
                    subject, type, isValid, getRemainingTimeMs());
        }
    }
    
    /**
     * Session information.
     */
    public static class SessionInfo {
        public String sessionId;
        public String userId;
        public long createdAt;
        public long lastAccessedAt;
        public long expiresAt;
        public Map<String, Object> attributes;
        public String ipAddress;
        public String userAgent;
        public boolean isActive;
        
        public SessionInfo() {
            this.attributes = new HashMap<>();
        }
        
        public boolean isExpired() {
            return java.lang.System.currentTimeMillis() > expiresAt;
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("Session{id='%s', user='%s', active=%s}",
                    sessionId, userId, isActive);
        }
    }
    
    private AuthTokenHelper() {}
    
    /**
     * Initialize with secret key.
     */
    public static void initialize(@NonNull byte[] key) {
        if (key.length < 16) {
            throw new IllegalArgumentException("Secret key must be at least 16 bytes");
        }
        secretKey = key.clone();
    }
    
    /**
     * Initialize with random secret key.
     */
    public static void initialize() {
        secretKey = new byte[32];
        secureRandom.nextBytes(secretKey);
    }
    
    /**
     * Generate a random token.
     * 
     * @param subject token subject (user ID)
     * @param ttlSeconds time to live in seconds
     * @return generated token
     */
    @NonNull
    public static String generateToken(@NonNull String subject, long ttlSeconds) {
        return generateToken(subject, TokenType.BEARER, ttlSeconds, null);
    }
    
    /**
     * Generate a token with claims.
     */
    @NonNull
    public static String generateToken(@NonNull String subject, @NonNull TokenType type,
                                       long ttlSeconds, @Nullable Map<String, String> claims) {
        long now = java.lang.System.currentTimeMillis();
        
        TokenInfo info = new TokenInfo();
        info.subject = subject;
        info.type = type;
        info.createdAt = now;
        info.expiresAt = now + (ttlSeconds * 1000);
        info.claims = claims != null ? claims : new HashMap<>();
        info.isValid = true;
        
        // Generate random token
        byte[] tokenBytes = new byte[TOKEN_LENGTH];
        secureRandom.nextBytes(tokenBytes);
        String token = bytesToHex(tokenBytes);
        
        info.token = token;
        tokenCache.put(token, info);
        
        return token;
    }
    
    /**
     * Generate API key.
     */
    @NonNull
    public static String generateApiKey(@NonNull String userId) {
        byte[] keyBytes = new byte[API_KEY_LENGTH / 2];
        secureRandom.nextBytes(keyBytes);
        String apiKey = bytesToHex(keyBytes);
        
        TokenInfo info = new TokenInfo();
        info.token = apiKey;
        info.subject = userId;
        info.type = TokenType.API_KEY;
        info.createdAt = java.lang.System.currentTimeMillis();
        info.expiresAt = Long.MAX_VALUE; // API keys don't expire by default
        info.claims = new HashMap<>();
        info.isValid = true;
        
        tokenCache.put(apiKey, info);
        
        return apiKey;
    }
    
    /**
     * Generate CSRF token.
     */
    @NonNull
    public static String generateCsrfToken() {
        byte[] tokenBytes = new byte[32];
        secureRandom.nextBytes(tokenBytes);
        String token = bytesToHex(tokenBytes);
        
        TokenInfo info = new TokenInfo();
        info.token = token;
        info.type = TokenType.CSRF;
        info.createdAt = java.lang.System.currentTimeMillis();
        info.expiresAt = java.lang.System.currentTimeMillis() + (30 * 60 * 1000); // 30 min
        info.isValid = true;
        
        tokenCache.put(token, info);
        
        return token;
    }
    
    /**
     * Validate token.
     */
    @Nullable
    public static TokenInfo validateToken(@NonNull String token) {
        TokenInfo info = tokenCache.get(token);
        
        if (info == null) {
            return null;
        }
        
        if (info.isExpired()) {
            info.isValid = false;
            tokenCache.remove(token);
            return null;
        }
        
        return info;
    }
    
    /**
     * Check if token is valid.
     */
    public static boolean isValidToken(@NonNull String token) {
        return validateToken(token) != null;
    }
    
    /**
     * Revoke token.
     */
    public static boolean revokeToken(@NonNull String token) {
        TokenInfo info = tokenCache.remove(token);
        if (info != null) {
            info.isValid = false;
            return true;
        }
        return false;
    }
    
    /**
     * Refresh token.
     */
    @Nullable
    public static String refreshToken(@NonNull String oldToken, long newTtlSeconds) {
        TokenInfo oldInfo = tokenCache.remove(oldToken);
        
        if (oldInfo == null || oldInfo.isExpired()) {
            return null;
        }
        
        return generateToken(oldInfo.subject, oldInfo.type, newTtlSeconds, oldInfo.claims);
    }
    
    /**
     * Create session.
     */
    @NonNull
    public static String createSession(@NonNull String userId) {
        return createSession(userId, 30 * 60 * 1000); // 30 min default
    }
    
    /**
     * Create session with custom TTL.
     */
    @NonNull
    public static String createSession(@NonNull String userId, long ttlMs) {
        String sessionId = UUID.randomUUID().toString();
        long now = java.lang.System.currentTimeMillis();
        
        SessionInfo session = new SessionInfo();
        session.sessionId = sessionId;
        session.userId = userId;
        session.createdAt = now;
        session.lastAccessedAt = now;
        session.expiresAt = now + ttlMs;
        session.isActive = true;
        
        sessionCache.put(sessionId, session);
        
        return sessionId;
    }
    
    /**
     * Get session.
     */
    @Nullable
    public static SessionInfo getSession(@NonNull String sessionId) {
        SessionInfo session = sessionCache.get(sessionId);
        
        if (session == null || session.isExpired()) {
            sessionCache.remove(sessionId);
            return null;
        }
        
        // Update last accessed time
        session.lastAccessedAt = java.lang.System.currentTimeMillis();
        
        return session;
    }
    
    /**
     * Invalidate session.
     */
    public static boolean invalidateSession(@NonNull String sessionId) {
        SessionInfo session = sessionCache.remove(sessionId);
        if (session != null) {
            session.isActive = false;
            return true;
        }
        return false;
    }
    
    /**
     * Invalidate all sessions for user.
     */
    public static int invalidateUserSessions(@NonNull String userId) {
        int count = 0;
        List<String> toRemove = new ArrayList<>();
        
        for (SessionInfo session : sessionCache.values()) {
            if (userId.equals(session.userId)) {
                toRemove.add(session.sessionId);
            }
        }
        
        for (String sessionId : toRemove) {
            if (invalidateSession(sessionId)) {
                count++;
            }
        }
        
        return count;
    }
    
    /**
     * Get active sessions for user.
     */
    @NonNull
    public static List<SessionInfo> getUserSessions(@NonNull String userId) {
        List<SessionInfo> sessions = new ArrayList<>();
        
        for (SessionInfo session : sessionCache.values()) {
            if (userId.equals(session.userId) && session.isActive && !session.isExpired()) {
                sessions.add(session);
            }
        }
        
        return sessions;
    }
    
    /**
     * Hash password (for storage).
     */
    @Nullable
    public static String hashPassword(@NonNull String password) {
        return hashPassword(password, generateSalt());
    }
    
    /**
     * Hash password with salt.
     */
    @Nullable
    public static String hashPassword(@NonNull String password, @NonNull String salt) {
        try {
            MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
            digest.update(salt.getBytes());
            byte[] hash = digest.digest(password.getBytes());
            return salt + "$" + bytesToHex(hash);
        } catch (Exception e) {
            Log.e(TAG, "Failed to hash password", e);
            return null;
        }
    }
    
    /**
     * Verify password.
     */
    public static boolean verifyPassword(@NonNull String password, @NonNull String hashedPassword) {
        int separatorIndex = hashedPassword.indexOf('$');
        if (separatorIndex <= 0) {
            return false;
        }
        
        String salt = hashedPassword.substring(0, separatorIndex);
        String expectedHash = hashPassword(password, salt);
        
        return hashedPassword.equals(expectedHash);
    }
    
    /**
     * Generate random salt.
     */
    @NonNull
    public static String generateSalt() {
        byte[] saltBytes = new byte[16];
        secureRandom.nextBytes(saltBytes);
        return bytesToHex(saltBytes);
    }
    
    /**
     * Validate password strength.
     */
    @NonNull
    public static PasswordStrength checkPasswordStrength(@NonNull String password) {
        int score = 0;
        List<String> issues = new ArrayList<>();
        
        // Length check
        if (password.length() < 8) {
            issues.add("Password should be at least 8 characters");
        } else {
            score += password.length() >= 12 ? 2 : 1;
        }
        
        // Character variety
        if (Pattern.compile("[a-z]").matcher(password).find()) {
            score++;
        } else {
            issues.add("Add lowercase letters");
        }
        
        if (Pattern.compile("[A-Z]").matcher(password).find()) {
            score++;
        } else {
            issues.add("Add uppercase letters");
        }
        
        if (Pattern.compile("[0-9]").matcher(password).find()) {
            score++;
        } else {
            issues.add("Add numbers");
        }
        
        if (Pattern.compile("[^a-zA-Z0-9]").matcher(password).find()) {
            score++;
        } else {
            issues.add("Add special characters");
        }
        
        // Common patterns
        if (password.toLowerCase().contains("password") ||
            password.toLowerCase().contains("123456") ||
            password.toLowerCase().contains("qwerty")) {
            score = Math.max(0, score - 2);
            issues.add("Avoid common patterns");
        }
        
        PasswordStrength.Level level;
        if (score >= 6) {
            level = PasswordStrength.Level.STRONG;
        } else if (score >= 4) {
            level = PasswordStrength.Level.MEDIUM;
        } else {
            level = PasswordStrength.Level.WEAK;
        }
        
        return new PasswordStrength(level, score, issues);
    }
    
    /**
     * Password strength result.
     */
    public static class PasswordStrength {
        public enum Level { WEAK, MEDIUM, STRONG }
        
        public final Level level;
        public final int score;
        public final List<String> issues;
        
        PasswordStrength(Level level, int score, List<String> issues) {
            this.level = level;
            this.score = score;
            this.issues = issues;
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("PasswordStrength{%s, score=%d}", level, score);
        }
    }
    
    /**
     * Clean up expired tokens and sessions.
     */
    private static void cleanupExpired() {
        long now = java.lang.System.currentTimeMillis();
        
        // Cleanup tokens
        tokenCache.entrySet().removeIf(entry -> entry.getValue().expiresAt < now);
        
        // Cleanup sessions
        sessionCache.entrySet().removeIf(entry -> entry.getValue().expiresAt < now);
    }
    
    /**
     * Get token cache statistics.
     */
    @NonNull
    public static CacheStats getStats() {
        return new CacheStats(tokenCache.size(), sessionCache.size());
    }
    
    /**
     * Cache statistics.
     */
    public static class CacheStats {
        public final int tokenCount;
        public final int sessionCount;
        
        CacheStats(int tokens, int sessions) {
            this.tokenCount = tokens;
            this.sessionCount = sessions;
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("CacheStats{tokens=%d, sessions=%d}", tokenCount, sessionCount);
        }
    }
    
    /**
     * Clear all tokens and sessions.
     */
    public static void clearAll() {
        tokenCache.clear();
        sessionCache.clear();
    }
    
    /**
     * Convert bytes to hex string.
     */
    @NonNull
    private static String bytesToHex(@NonNull byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    /**
     * Shutdown scheduler.
     */
    public static void shutdown() {
        scheduler.shutdown();
        try {
            if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            scheduler.shutdownNow();
        }
    }
}
