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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with cSploit.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.csploit.android.helpers;

import android.content.Context;
import org.csploit.android.helpers.LoggingHelper;
import android.content.SharedPreferences;
import org.csploit.android.helpers.LoggingHelper;

import androidx.annotation.NonNull;
import org.csploit.android.helpers.LoggingHelper;
import androidx.annotation.Nullable;
import org.csploit.android.helpers.LoggingHelper;
import androidx.security.crypto.EncryptedSharedPreferences;
import org.csploit.android.helpers.LoggingHelper;
import androidx.security.crypto.MasterKey;
import org.csploit.android.helpers.LoggingHelper;

import java.io.IOException;
import org.csploit.android.helpers.LoggingHelper;
import java.security.GeneralSecurityException;
import org.csploit.android.helpers.LoggingHelper;
import java.util.HashSet;
import org.csploit.android.helpers.LoggingHelper;
import java.util.Set;
import org.csploit.android.helpers.LoggingHelper;

/**
 * EncryptedStorageHelper - Secure encrypted storage for sensitive data.
 * 
 * Uses Android's EncryptedSharedPreferences for storing sensitive information
 * like credentials, API keys, and tokens securely.
 * 
 * Usage:
 * {@code
 * EncryptedStorageHelper storage = EncryptedStorageHelper.getInstance(context);
 * storage.putString("api_key", apiKey);
 * String key = storage.getString("api_key", null);
 * }
 */
public final class EncryptedStorageHelper {
    
    private static final String TAG = "EncryptedStorageHelper";
    private static final String ENCRYPTED_PREFS_NAME = "csploit_secure_prefs";
    
    private static volatile EncryptedStorageHelper instance;
    private final SharedPreferences encryptedPrefs;
    private final SharedPreferences.Editor editor;
    
    /**
     * Get singleton instance.
     * 
     * @param context Application context
     * @return EncryptedStorageHelper instance
     * @throws SecurityException if encryption initialization fails
     */
    @NonNull
    public static synchronized EncryptedStorageHelper getInstance(@NonNull Context context) {
        if (instance == null) {
            instance = new EncryptedStorageHelper(context.getApplicationContext());
        }
        return instance;
    }
    
    private EncryptedStorageHelper(@NonNull Context context) {
        try {
            MasterKey masterKey = new MasterKey.Builder(context)
                    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                    .build();
            
            encryptedPrefs = EncryptedSharedPreferences.create(
                    context,
                    ENCRYPTED_PREFS_NAME,
                    masterKey,
                    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            );
            editor = encryptedPrefs.edit();
        } catch (GeneralSecurityException | IOException e) {
            LoggingHelper.e(TAG, "Failed to initialize encrypted storage", e);
            throw new SecurityException("Cannot initialize encrypted storage", e);
        }
    }
    
    /**
     * Store a string value securely.
     * 
     * @param key The preference key
     * @param value The value to store (null to remove)
     */
    public void putString(@NonNull String key, @Nullable String value) {
        if (value == null) {
            editor.remove(key);
        } else {
            editor.putString(key, value);
        }
        editor.apply();
    }
    
    /**
     * Retrieve a string value.
     * 
     * @param key The preference key
     * @param defaultValue Default value if not found
     * @return The stored value or default
     */
    @Nullable
    public String getString(@NonNull String key, @Nullable String defaultValue) {
        return encryptedPrefs.getString(key, defaultValue);
    }
    
    /**
     * Store an integer value securely.
     * 
     * @param key The preference key
     * @param value The value to store
     */
    public void putInt(@NonNull String key, int value) {
        editor.putInt(key, value);
        editor.apply();
    }
    
    /**
     * Retrieve an integer value.
     * 
     * @param key The preference key
     * @param defaultValue Default value if not found
     * @return The stored value or default
     */
    public int getInt(@NonNull String key, int defaultValue) {
        return encryptedPrefs.getInt(key, defaultValue);
    }
    
    /**
     * Store a long value securely.
     * 
     * @param key The preference key
     * @param value The value to store
     */
    public void putLong(@NonNull String key, long value) {
        editor.putLong(key, value);
        editor.apply();
    }
    
    /**
     * Retrieve a long value.
     * 
     * @param key The preference key
     * @param defaultValue Default value if not found
     * @return The stored value or default
     */
    public long getLong(@NonNull String key, long defaultValue) {
        return encryptedPrefs.getLong(key, defaultValue);
    }
    
    /**
     * Store a boolean value securely.
     * 
     * @param key The preference key
     * @param value The value to store
     */
    public void putBoolean(@NonNull String key, boolean value) {
        editor.putBoolean(key, value);
        editor.apply();
    }
    
    /**
     * Retrieve a boolean value.
     * 
     * @param key The preference key
     * @param defaultValue Default value if not found
     * @return The stored value or default
     */
    public boolean getBoolean(@NonNull String key, boolean defaultValue) {
        return encryptedPrefs.getBoolean(key, defaultValue);
    }
    
    /**
     * Store a string set securely.
     * 
     * @param key The preference key
     * @param values The values to store
     */
    public void putStringSet(@NonNull String key, @Nullable Set<String> values) {
        if (values == null) {
            editor.remove(key);
        } else {
            editor.putStringSet(key, values);
        }
        editor.apply();
    }
    
    /**
     * Retrieve a string set.
     * 
     * @param key The preference key
     * @param defaultValues Default values if not found
     * @return The stored values or default
     */
    @Nullable
    public Set<String> getStringSet(@NonNull String key, @Nullable Set<String> defaultValues) {
        Set<String> result = encryptedPrefs.getStringSet(key, defaultValues);
        return result != null ? new HashSet<>(result) : defaultValues;
    }
    
    /**
     * Check if a key exists.
     * 
     * @param key The preference key
     * @return true if key exists
     */
    public boolean contains(@NonNull String key) {
        return encryptedPrefs.contains(key);
    }
    
    /**
     * Remove a value.
     * 
     * @param key The preference key to remove
     */
    public void remove(@NonNull String key) {
        editor.remove(key);
        editor.apply();
    }
    
    /**
     * Clear all stored values.
     */
    public void clear() {
        editor.clear();
        editor.apply();
    }
    
    // Convenience methods for common credential storage
    
    /**
     * Store credentials securely.
     * 
     * @param service Service identifier
     * @param username Username
     * @param password Password
     */
    public void storeCredentials(@NonNull String service, @NonNull String username, @NonNull String password) {
        String keyPrefix = "cred_" + service + "_";
        putString(keyPrefix + "username", username);
        putString(keyPrefix + "password", password);
        putLong(keyPrefix + "timestamp", java.lang.System.currentTimeMillis());
    }
    
    /**
     * Retrieve stored username.
     * 
     * @param service Service identifier
     * @return Username or null
     */
    @Nullable
    public String getUsername(@NonNull String service) {
        return getString("cred_" + service + "_username", null);
    }
    
    /**
     * Retrieve stored password.
     * 
     * @param service Service identifier
     * @return Password or null
     */
    @Nullable
    public String getPassword(@NonNull String service) {
        return getString("cred_" + service + "_password", null);
    }
    
    /**
     * Check if credentials exist for a service.
     * 
     * @param service Service identifier
     * @return true if credentials exist
     */
    public boolean hasCredentials(@NonNull String service) {
        return contains("cred_" + service + "_username") && contains("cred_" + service + "_password");
    }
    
    /**
     * Remove credentials for a service.
     * 
     * @param service Service identifier
     */
    public void removeCredentials(@NonNull String service) {
        String keyPrefix = "cred_" + service + "_";
        remove(keyPrefix + "username");
        remove(keyPrefix + "password");
        remove(keyPrefix + "timestamp");
    }
    
    /**
     * Store an API key securely.
     * 
     * @param service Service identifier
     * @param apiKey API key
     */
    public void storeApiKey(@NonNull String service, @NonNull String apiKey) {
        putString("apikey_" + service, apiKey);
    }
    
    /**
     * Retrieve an API key.
     * 
     * @param service Service identifier
     * @return API key or null
     */
    @Nullable
    public String getApiKey(@NonNull String service) {
        return getString("apikey_" + service, null);
    }
    
    /**
     * Store a token securely.
     * 
     * @param service Service identifier
     * @param token Token value
     * @param expiryMs Expiry time in milliseconds (0 for no expiry)
     */
    public void storeToken(@NonNull String service, @NonNull String token, long expiryMs) {
        String keyPrefix = "token_" + service + "_";
        putString(keyPrefix + "value", token);
        if (expiryMs > 0) {
            putLong(keyPrefix + "expiry", java.lang.System.currentTimeMillis() + expiryMs);
        }
    }
    
    /**
     * Retrieve a token if not expired.
     * 
     * @param service Service identifier
     * @return Token or null if not found or expired
     */
    @Nullable
    public String getToken(@NonNull String service) {
        String keyPrefix = "token_" + service + "_";
        String token = getString(keyPrefix + "value", null);
        if (token == null) {
            return null;
        }
        
        long expiry = getLong(keyPrefix + "expiry", 0);
        if (expiry > 0 && java.lang.System.currentTimeMillis() > expiry) {
            // Token expired, remove it
            remove(keyPrefix + "value");
            remove(keyPrefix + "expiry");
            return null;
        }
        
        return token;
    }
    
    /**
     * Check if a token is expired.
     * 
     * @param service Service identifier
     * @return true if token is expired or doesn't exist
     */
    public boolean isTokenExpired(@NonNull String service) {
        String keyPrefix = "token_" + service + "_";
        if (!contains(keyPrefix + "value")) {
            return true;
        }
        
        long expiry = getLong(keyPrefix + "expiry", 0);
        return expiry > 0 && java.lang.System.currentTimeMillis() > expiry;
    }
}
