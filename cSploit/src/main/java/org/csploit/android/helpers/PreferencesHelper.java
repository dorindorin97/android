package org.csploit.android.helpers;

import android.content.Context;
import org.csploit.android.helpers.LoggingHelper;
import android.content.SharedPreferences;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

/**
 * Secure shared preferences wrapper with encryption support.
 * Provides methods for secure storage of sensitive data.
 */
public final class PreferencesHelper {

    private static final String PREF_NAME = "cSploit_prefs";
    private static final String SECURE_PREF_NAME = "cSploit_secure_prefs";

    private static SharedPreferences preferences;
    private static SharedPreferences securePreferences;

    /**
     * Initialize preferences (should be called once on app startup)
     */
    public static void init(@NonNull Context context) {
        preferences = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        
        try {
            MasterKey masterKey = new MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build();

            securePreferences = EncryptedSharedPreferences.create(
                context,
                SECURE_PREF_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            );
        } catch (Exception e) {
            // Fallback to unencrypted if encryption setup fails
            securePreferences = context.getSharedPreferences(SECURE_PREF_NAME, Context.MODE_PRIVATE);
            LoggingHelper.e("PreferencesHelper", "Failed to initialize encrypted preferences", e);
        }
    }

    /**
     * Get string preference
     */
    @Nullable
    public static String getString(@NonNull String key, @Nullable String defaultValue) {
        if (preferences == null) {
            return defaultValue;
        }
        return preferences.getString(key, defaultValue);
    }

    /**
     * Get integer preference
     */
    public static int getInt(@NonNull String key, int defaultValue) {
        if (preferences == null) {
            return defaultValue;
        }
        return preferences.getInt(key, defaultValue);
    }

    /**
     * Get long preference
     */
    public static long getLong(@NonNull String key, long defaultValue) {
        if (preferences == null) {
            return defaultValue;
        }
        return preferences.getLong(key, defaultValue);
    }

    /**
     * Get boolean preference
     */
    public static boolean getBoolean(@NonNull String key, boolean defaultValue) {
        if (preferences == null) {
            return defaultValue;
        }
        return preferences.getBoolean(key, defaultValue);
    }

    /**
     * Get float preference
     */
    public static float getFloat(@NonNull String key, float defaultValue) {
        if (preferences == null) {
            return defaultValue;
        }
        return preferences.getFloat(key, defaultValue);
    }

    /**
     * Set string preference
     */
    public static void setString(@NonNull String key, @Nullable String value) {
        if (preferences != null) {
            preferences.edit().putString(key, value).apply();
        }
    }

    /**
     * Set integer preference
     */
    public static void setInt(@NonNull String key, int value) {
        if (preferences != null) {
            preferences.edit().putInt(key, value).apply();
        }
    }

    /**
     * Set long preference
     */
    public static void setLong(@NonNull String key, long value) {
        if (preferences != null) {
            preferences.edit().putLong(key, value).apply();
        }
    }

    /**
     * Set boolean preference
     */
    public static void setBoolean(@NonNull String key, boolean value) {
        if (preferences != null) {
            preferences.edit().putBoolean(key, value).apply();
        }
    }

    /**
     * Set float preference
     */
    public static void setFloat(@NonNull String key, float value) {
        if (preferences != null) {
            preferences.edit().putFloat(key, value).apply();
        }
    }

    /**
     * Get encrypted string preference
     */
    @Nullable
    public static String getSecureString(@NonNull String key, @Nullable String defaultValue) {
        if (securePreferences == null) {
            return defaultValue;
        }
        return securePreferences.getString(key, defaultValue);
    }

    /**
     * Set encrypted string preference
     */
    public static void setSecureString(@NonNull String key, @Nullable String value) {
        if (securePreferences != null) {
            securePreferences.edit().putString(key, value).apply();
        }
    }

    /**
     * Remove preference
     */
    public static void remove(@NonNull String key) {
        if (preferences != null) {
            preferences.edit().remove(key).apply();
        }
    }

    /**
     * Remove secure preference
     */
    public static void removeSecure(@NonNull String key) {
        if (securePreferences != null) {
            securePreferences.edit().remove(key).apply();
        }
    }

    /**
     * Clear all preferences
     */
    public static void clear() {
        if (preferences != null) {
            preferences.edit().clear().apply();
        }
    }

    /**
     * Clear all secure preferences
     */
    public static void clearSecure() {
        if (securePreferences != null) {
            securePreferences.edit().clear().apply();
        }
    }

    /**
     * Check if key exists
     */
    public static boolean contains(@NonNull String key) {
        return preferences != null && preferences.contains(key);
    }

    /**
     * Check if secure key exists
     */
    public static boolean containsSecure(@NonNull String key) {
        return securePreferences != null && securePreferences.contains(key);
    }

    /**
     * Get all preferences as map
     */
    @NonNull
    public static java.util.Map<String, ?> getAll() {
        if (preferences == null) {
            return new java.util.HashMap<>();
        }
        return preferences.getAll();
    }
}
