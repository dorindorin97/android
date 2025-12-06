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
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.CRC32;

/**
 * HashHelper - Cryptographic hash and checksum utilities.
 * 
 * Provides:
 * - MD5, SHA-1, SHA-256, SHA-512 hashing
 * - CRC32 checksum
 * - Password hashing
 * - Hash verification
 * - HMAC generation
 * 
 * Usage:
 * {@code
 * // Generate MD5 hash
 * String md5 = HashHelper.md5("test");
 * 
 * // Generate SHA-256 hash
 * String sha256 = HashHelper.sha256("test");
 * 
 * // Verify hash
 * boolean valid = HashHelper.verify("test", md5, Algorithm.MD5);
 * }
 */
public final class HashHelper {
    
    private static final String TAG = "HashHelper";
    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();
    
    /**
     * Hash algorithms.
     */
    public enum Algorithm {
        MD5("MD5"),
        SHA1("SHA-1"),
        SHA256("SHA-256"),
        SHA384("SHA-384"),
        SHA512("SHA-512");
        
        private final String algorithmName;
        
        Algorithm(String name) {
            this.algorithmName = name;
        }
        
        public String getAlgorithmName() {
            return algorithmName;
        }
    }
    
    private HashHelper() {}
    
    // ==================== Basic Hash Functions ====================
    
    /**
     * Generate MD5 hash.
     */
    @Nullable
    public static String md5(@NonNull String input) {
        return hash(input, Algorithm.MD5);
    }
    
    /**
     * Generate MD5 hash of bytes.
     */
    @Nullable
    public static String md5(@NonNull byte[] input) {
        return hash(input, Algorithm.MD5);
    }
    
    /**
     * Generate SHA-1 hash.
     */
    @Nullable
    public static String sha1(@NonNull String input) {
        return hash(input, Algorithm.SHA1);
    }
    
    /**
     * Generate SHA-1 hash of bytes.
     */
    @Nullable
    public static String sha1(@NonNull byte[] input) {
        return hash(input, Algorithm.SHA1);
    }
    
    /**
     * Generate SHA-256 hash.
     */
    @Nullable
    public static String sha256(@NonNull String input) {
        return hash(input, Algorithm.SHA256);
    }
    
    /**
     * Generate SHA-256 hash of bytes.
     */
    @Nullable
    public static String sha256(@NonNull byte[] input) {
        return hash(input, Algorithm.SHA256);
    }
    
    /**
     * Generate SHA-384 hash.
     */
    @Nullable
    public static String sha384(@NonNull String input) {
        return hash(input, Algorithm.SHA384);
    }
    
    /**
     * Generate SHA-512 hash.
     */
    @Nullable
    public static String sha512(@NonNull String input) {
        return hash(input, Algorithm.SHA512);
    }
    
    /**
     * Generate hash with specified algorithm.
     */
    @Nullable
    public static String hash(@NonNull String input, @NonNull Algorithm algorithm) {
        return hash(input.getBytes(java.nio.charset.StandardCharsets.UTF_8), algorithm);
    }
    
    /**
     * Generate hash with specified algorithm.
     */
    @Nullable
    public static String hash(@NonNull byte[] input, @NonNull Algorithm algorithm) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm.getAlgorithmName());
            byte[] hashBytes = digest.digest(input);
            return bytesToHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "Algorithm not found: " + algorithm.getAlgorithmName(), e);
            return null;
        }
    }
    
    /**
     * Generate hash with raw bytes output.
     */
    @Nullable
    public static byte[] hashBytes(@NonNull byte[] input, @NonNull Algorithm algorithm) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm.getAlgorithmName());
            return digest.digest(input);
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "Algorithm not found: " + algorithm.getAlgorithmName(), e);
            return null;
        }
    }
    
    // ==================== Hash Verification ====================
    
    /**
     * Verify hash matches input.
     */
    public static boolean verify(@NonNull String input, @NonNull String hash, @NonNull Algorithm algorithm) {
        String computed = hash(input, algorithm);
        return computed != null && computed.equalsIgnoreCase(hash);
    }
    
    /**
     * Verify hash matches input (auto-detect algorithm).
     */
    public static boolean verify(@NonNull String input, @NonNull String hash) {
        Algorithm algorithm = detectAlgorithm(hash);
        if (algorithm == null) {
            return false;
        }
        return verify(input, hash, algorithm);
    }
    
    /**
     * Detect algorithm from hash length.
     */
    @Nullable
    public static Algorithm detectAlgorithm(@NonNull String hash) {
        switch (hash.length()) {
            case 32:
                return Algorithm.MD5;
            case 40:
                return Algorithm.SHA1;
            case 64:
                return Algorithm.SHA256;
            case 96:
                return Algorithm.SHA384;
            case 128:
                return Algorithm.SHA512;
            default:
                return null;
        }
    }
    
    // ==================== CRC32 ====================
    
    /**
     * Generate CRC32 checksum.
     */
    public static long crc32(@NonNull String input) {
        return crc32(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
    
    /**
     * Generate CRC32 checksum.
     */
    public static long crc32(@NonNull byte[] input) {
        CRC32 crc = new CRC32();
        crc.update(input);
        return crc.getValue();
    }
    
    /**
     * Generate CRC32 checksum as hex string.
     */
    @NonNull
    public static String crc32Hex(@NonNull String input) {
        return String.format("%08x", crc32(input));
    }
    
    // ==================== Password Hashing ====================
    
    /**
     * Hash password with salt.
     */
    @NonNull
    public static PasswordHash hashPassword(@NonNull String password) {
        return hashPassword(password, Algorithm.SHA256);
    }
    
    /**
     * Hash password with salt and specified algorithm.
     */
    @NonNull
    public static PasswordHash hashPassword(@NonNull String password, @NonNull Algorithm algorithm) {
        // Generate random salt
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        
        // Hash password with salt
        byte[] passwordBytes = password.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] saltedPassword = new byte[passwordBytes.length + salt.length];
        System.arraycopy(salt, 0, saltedPassword, 0, salt.length);
        System.arraycopy(passwordBytes, 0, saltedPassword, salt.length, passwordBytes.length);
        
        String hash = hash(saltedPassword, algorithm);
        
        return new PasswordHash(hash, bytesToHex(salt), algorithm);
    }
    
    /**
     * Verify password against hash.
     */
    public static boolean verifyPassword(@NonNull String password, @NonNull PasswordHash passwordHash) {
        byte[] salt = hexToBytes(passwordHash.salt);
        byte[] passwordBytes = password.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] saltedPassword = new byte[passwordBytes.length + salt.length];
        System.arraycopy(salt, 0, saltedPassword, 0, salt.length);
        System.arraycopy(passwordBytes, 0, saltedPassword, salt.length, passwordBytes.length);
        
        String computed = hash(saltedPassword, passwordHash.algorithm);
        return computed != null && computed.equalsIgnoreCase(passwordHash.hash);
    }
    
    /**
     * Password hash result.
     */
    public static class PasswordHash {
        public final String hash;
        public final String salt;
        public final Algorithm algorithm;
        
        public PasswordHash(@NonNull String hash, @NonNull String salt, @NonNull Algorithm algorithm) {
            this.hash = hash;
            this.salt = salt;
            this.algorithm = algorithm;
        }
        
        @NonNull
        @Override
        public String toString() {
            return algorithm.name() + ":" + salt + ":" + hash;
        }
        
        /**
         * Parse from string representation.
         */
        @Nullable
        public static PasswordHash fromString(@NonNull String str) {
            String[] parts = str.split(":");
            if (parts.length != 3) return null;
            
            try {
                Algorithm algo = Algorithm.valueOf(parts[0]);
                return new PasswordHash(parts[2], parts[1], algo);
            } catch (Exception e) {
                return null;
            }
        }
    }
    
    // ==================== HMAC ====================
    
    /**
     * Generate HMAC.
     */
    @Nullable
    public static String hmac(@NonNull String data, @NonNull String key, @NonNull Algorithm algorithm) {
        try {
            String hmacAlgorithm = "Hmac" + algorithm.getAlgorithmName().replace("-", "");
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance(hmacAlgorithm);
            javax.crypto.spec.SecretKeySpec secretKey = new javax.crypto.spec.SecretKeySpec(
                    key.getBytes(java.nio.charset.StandardCharsets.UTF_8), hmacAlgorithm);
            mac.init(secretKey);
            byte[] hmacBytes = mac.doFinal(data.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return bytesToHex(hmacBytes);
        } catch (Exception e) {
            Log.e(TAG, "HMAC generation failed", e);
            return null;
        }
    }
    
    /**
     * Generate HMAC-SHA256.
     */
    @Nullable
    public static String hmacSha256(@NonNull String data, @NonNull String key) {
        return hmac(data, key, Algorithm.SHA256);
    }
    
    /**
     * Generate HMAC-SHA512.
     */
    @Nullable
    public static String hmacSha512(@NonNull String data, @NonNull String key) {
        return hmac(data, key, Algorithm.SHA512);
    }
    
    // ==================== Utilities ====================
    
    /**
     * Convert bytes to hex string.
     */
    @NonNull
    public static String bytesToHex(@NonNull byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hexChars[i * 2] = HEX_CHARS[v >>> 4];
            hexChars[i * 2 + 1] = HEX_CHARS[v & 0x0F];
        }
        return new String(hexChars);
    }
    
    /**
     * Convert hex string to bytes.
     */
    @NonNull
    public static byte[] hexToBytes(@NonNull String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
    
    /**
     * Compute hashes with all algorithms.
     */
    @NonNull
    public static Map<Algorithm, String> hashAll(@NonNull String input) {
        Map<Algorithm, String> hashes = new HashMap<>();
        for (Algorithm algo : Algorithm.values()) {
            String hash = hash(input, algo);
            if (hash != null) {
                hashes.put(algo, hash);
            }
        }
        return hashes;
    }
    
    /**
     * Identify hash type by format.
     */
    @NonNull
    public static List<String> identifyHashType(@NonNull String hash) {
        List<String> possibleTypes = new ArrayList<>();
        
        int len = hash.length();
        boolean isHex = hash.matches("^[0-9a-fA-F]+$");
        
        if (!isHex) {
            // Could be Base64 encoded
            if (hash.matches("^[A-Za-z0-9+/]+=*$")) {
                possibleTypes.add("Base64 encoded");
            }
            return possibleTypes;
        }
        
        switch (len) {
            case 32:
                possibleTypes.add("MD5");
                possibleTypes.add("MD4");
                possibleTypes.add("MD2");
                possibleTypes.add("NTLM");
                break;
            case 40:
                possibleTypes.add("SHA-1");
                possibleTypes.add("MySQL5");
                possibleTypes.add("RIPEMD-160");
                break;
            case 56:
                possibleTypes.add("SHA-224");
                break;
            case 64:
                possibleTypes.add("SHA-256");
                possibleTypes.add("RIPEMD-256");
                possibleTypes.add("Snefru-256");
                break;
            case 96:
                possibleTypes.add("SHA-384");
                break;
            case 128:
                possibleTypes.add("SHA-512");
                possibleTypes.add("Whirlpool");
                possibleTypes.add("SHA-512/256");
                break;
            case 8:
                possibleTypes.add("CRC32");
                break;
            case 16:
                possibleTypes.add("CRC64");
                possibleTypes.add("MySQL323");
                break;
        }
        
        return possibleTypes;
    }
    
    /**
     * Generate file checksum (for file path).
     */
    @Nullable
    public static String fileHash(@NonNull String filePath, @NonNull Algorithm algorithm) {
        try {
            java.io.File file = new java.io.File(filePath);
            if (!file.exists() || !file.isFile()) {
                return null;
            }
            
            MessageDigest digest = MessageDigest.getInstance(algorithm.getAlgorithmName());
            java.io.FileInputStream fis = new java.io.FileInputStream(file);
            
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
            fis.close();
            
            return bytesToHex(digest.digest());
        } catch (Exception e) {
            Log.e(TAG, "File hash failed", e);
            return null;
        }
    }
}
