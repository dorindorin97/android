package org.csploit.android.helpers;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;
import android.util.Log;

/**
 * Helper for securely storing and retrieving sensitive credentials.
 * Uses Android's EncryptedSharedPreferences (part of androidx.security:security-crypto)
 * for encrypted storage with hardware-backed encryption when available.
 */
public class SecureCredentialsHelper {
    private static final String TAG = "SecureCredentialsHelper";
    private static final String ENCRYPTED_PREFS_NAME = "csploit_secure_prefs";

    private final SharedPreferences encryptedPreferences;

    /**
     * Initialize encrypted preferences with master key.
     * The MasterKey uses AES-256-GCM for encryption.
     *
     * @param context Application context
     */
    public SecureCredentialsHelper(Context context) {
        try {
            MasterKey masterKey = new MasterKey.Builder(context)
                    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                    .build();

            this.encryptedPreferences = EncryptedSharedPreferences.create(
                    context,
                    ENCRYPTED_PREFS_NAME,
                    masterKey,
                    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            );
        } catch (Exception e) {
            Log.e(TAG, "Failed to initialize encrypted preferences", e);
            throw new RuntimeException("Failed to initialize secure storage", e);
        }
    }

    /**
     * Store a sensitive string credential securely.
     *
     * @param key   The preference key
     * @param value The credential value to encrypt
     */
    public void storeCredential(String key, String value) {
        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("Credential key cannot be null or empty");
        }

        try {
            encryptedPreferences.edit()
                    .putString(key, value)
                    .apply();
            Log.d(TAG, "Credential stored securely: " + key);
        } catch (Exception e) {
            Log.e(TAG, "Failed to store credential: " + key, e);
            throw new RuntimeException("Failed to store credential", e);
        }
    }

    /**
     * Retrieve a sensitive string credential.
     *
     * @param key          The preference key
     * @param defaultValue Default value if key not found
     * @return The decrypted credential value
     */
    public String retrieveCredential(String key, String defaultValue) {
        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("Credential key cannot be null or empty");
        }

        try {
            return encryptedPreferences.getString(key, defaultValue);
        } catch (Exception e) {
            Log.e(TAG, "Failed to retrieve credential: " + key, e);
            throw new RuntimeException("Failed to retrieve credential", e);
        }
    }

    /**
     * Store a sensitive integer credential securely.
     *
     * @param key   The preference key
     * @param value The credential value to encrypt
     */
    public void storeCredential(String key, int value) {
        try {
            encryptedPreferences.edit()
                    .putInt(key, value)
                    .apply();
            Log.d(TAG, "Integer credential stored securely: " + key);
        } catch (Exception e) {
            Log.e(TAG, "Failed to store integer credential: " + key, e);
            throw new RuntimeException("Failed to store credential", e);
        }
    }

    /**
     * Retrieve a sensitive integer credential.
     *
     * @param key          The preference key
     * @param defaultValue Default value if key not found
     * @return The decrypted credential value
     */
    public int retrieveCredential(String key, int defaultValue) {
        try {
            return encryptedPreferences.getInt(key, defaultValue);
        } catch (Exception e) {
            Log.e(TAG, "Failed to retrieve integer credential: " + key, e);
            throw new RuntimeException("Failed to retrieve credential", e);
        }
    }

    /**
     * Store a sensitive boolean credential securely.
     *
     * @param key   The preference key
     * @param value The credential value to encrypt
     */
    public void storeCredential(String key, boolean value) {
        try {
            encryptedPreferences.edit()
                    .putBoolean(key, value)
                    .apply();
            Log.d(TAG, "Boolean credential stored securely: " + key);
        } catch (Exception e) {
            Log.e(TAG, "Failed to store boolean credential: " + key, e);
            throw new RuntimeException("Failed to store credential", e);
        }
    }

    /**
     * Retrieve a sensitive boolean credential.
     *
     * @param key          The preference key
     * @param defaultValue Default value if key not found
     * @return The decrypted credential value
     */
    public boolean retrieveCredential(String key, boolean defaultValue) {
        try {
            return encryptedPreferences.getBoolean(key, defaultValue);
        } catch (Exception e) {
            Log.e(TAG, "Failed to retrieve boolean credential: " + key, e);
            throw new RuntimeException("Failed to retrieve credential", e);
        }
    }

    /**
     * Delete a credential.
     *
     * @param key The preference key to delete
     */
    public void deleteCredential(String key) {
        try {
            encryptedPreferences.edit()
                    .remove(key)
                    .apply();
            Log.d(TAG, "Credential deleted: " + key);
        } catch (Exception e) {
            Log.e(TAG, "Failed to delete credential: " + key, e);
            throw new RuntimeException("Failed to delete credential", e);
        }
    }

    /**
     * Check if a credential exists.
     *
     * @param key The preference key
     * @return true if key exists, false otherwise
     */
    public boolean hasCredential(String key) {
        return encryptedPreferences.contains(key);
    }

    /**
     * Clear all stored credentials.
     */
    public void clearAllCredentials() {
        try {
            encryptedPreferences.edit()
                    .clear()
                    .apply();
            Log.d(TAG, "All credentials cleared");
        } catch (Exception e) {
            Log.e(TAG, "Failed to clear credentials", e);
            throw new RuntimeException("Failed to clear credentials", e);
        }
    }
}
