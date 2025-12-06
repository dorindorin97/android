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

import android.content.Context;
import android.content.SharedPreferences;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * SessionStateManager - Manages application session state and persistence.
 *
 * Provides:
 * - In-memory session state storage
 * - Persistent state storage via SharedPreferences
 * - Session lifecycle management
 * - State change listeners
 *
 * Usage:
 * {@code
 * SessionStateManager manager = SessionStateManager.getInstance();
 * manager.setState("currentTarget", targetId);
 * String targetId = manager.getState("currentTarget");
 * }
 */
public final class SessionStateManager {

    private static final String TAG = "SessionStateManager";
    private static final String PREFS_NAME = "SessionState";

    private static volatile SessionStateManager sInstance;

    private final Map<String, Object> mSessionState = new ConcurrentHashMap<>();
    private final Map<String, StateChangeListener> mListeners = new ConcurrentHashMap<>();
    private SharedPreferences mPrefs;
    private long mSessionStartTime;
    private String mSessionId;

    /**
     * Listener for state changes
     */
    public interface StateChangeListener {
        void onStateChanged(String key, Object oldValue, Object newValue);
    }

    private SessionStateManager() {
        mSessionStartTime = java.lang.System.currentTimeMillis();
        mSessionId = generateSessionId();
    }

    /**
     * Get singleton instance
     */
    @NonNull
    public static SessionStateManager getInstance() {
        if (sInstance == null) {
            synchronized (SessionStateManager.class) {
                if (sInstance == null) {
                    sInstance = new SessionStateManager();
                }
            }
        }
        return sInstance;
    }

    /**
     * Initialize with context (call in Application.onCreate or main Activity)
     */
    public void init(@NonNull Context context) {
        mPrefs = context.getApplicationContext().getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        LoggingHelper.d(TAG, "SessionStateManager initialized, session ID: " + mSessionId);
    }

    /**
     * Get current session ID
     */
    @NonNull
    public String getSessionId() {
        return mSessionId;
    }

    /**
     * Get session start time
     */
    public long getSessionStartTime() {
        return mSessionStartTime;
    }

    /**
     * Get session duration in milliseconds
     */
    public long getSessionDuration() {
        return java.lang.System.currentTimeMillis() - mSessionStartTime;
    }

    // ==================== In-Memory State ====================

    /**
     * Set session state value (in-memory only)
     */
    public void setState(@NonNull String key, @Nullable Object value) {
        Object oldValue = mSessionState.get(key);
        if (value == null) {
            mSessionState.remove(key);
        } else {
            mSessionState.put(key, value);
        }
        notifyListeners(key, oldValue, value);
    }

    /**
     * Get session state value
     */
    @Nullable
    public Object getState(@NonNull String key) {
        return mSessionState.get(key);
    }

    /**
     * Get session state value with default
     */
    @NonNull
    public Object getState(@NonNull String key, @NonNull Object defaultValue) {
        Object value = mSessionState.get(key);
        return value != null ? value : defaultValue;
    }

    /**
     * Get session state value as String
     */
    @Nullable
    public String getStateString(@NonNull String key) {
        Object value = mSessionState.get(key);
        return value != null ? value.toString() : null;
    }

    /**
     * Get session state value as String with default
     */
    @NonNull
    public String getStateString(@NonNull String key, @NonNull String defaultValue) {
        String value = getStateString(key);
        return value != null ? value : defaultValue;
    }

    /**
     * Get session state value as Integer
     */
    @Nullable
    public Integer getStateInt(@NonNull String key) {
        Object value = mSessionState.get(key);
        if (value instanceof Integer) {
            return (Integer) value;
        } else if (value instanceof Number) {
            return ((Number) value).intValue();
        } else if (value instanceof String) {
            try {
                return Integer.parseInt((String) value);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    /**
     * Get session state value as Integer with default
     */
    public int getStateInt(@NonNull String key, int defaultValue) {
        Integer value = getStateInt(key);
        return value != null ? value : defaultValue;
    }

    /**
     * Get session state value as Boolean
     */
    @Nullable
    public Boolean getStateBool(@NonNull String key) {
        Object value = mSessionState.get(key);
        if (value instanceof Boolean) {
            return (Boolean) value;
        } else if (value instanceof String) {
            return Boolean.parseBoolean((String) value);
        }
        return null;
    }

    /**
     * Get session state value as Boolean with default
     */
    public boolean getStateBool(@NonNull String key, boolean defaultValue) {
        Boolean value = getStateBool(key);
        return value != null ? value : defaultValue;
    }

    /**
     * Check if state key exists
     */
    public boolean hasState(@NonNull String key) {
        return mSessionState.containsKey(key);
    }

    /**
     * Remove state key
     */
    public void removeState(@NonNull String key) {
        Object oldValue = mSessionState.remove(key);
        if (oldValue != null) {
            notifyListeners(key, oldValue, null);
        }
    }

    /**
     * Clear all session state
     */
    public void clearState() {
        mSessionState.clear();
        LoggingHelper.d(TAG, "Session state cleared");
    }

    // ==================== Persistent State ====================

    /**
     * Save persistent state (survives app restart)
     */
    public void savePersistentState(@NonNull String key, @Nullable String value) {
        if (mPrefs == null) {
            LoggingHelper.w(TAG, "SessionStateManager not initialized");
            return;
        }
        SharedPreferences.Editor editor = mPrefs.edit();
        if (value == null) {
            editor.remove(key);
        } else {
            editor.putString(key, value);
        }
        editor.apply();
    }

    /**
     * Save persistent integer state
     */
    public void savePersistentState(@NonNull String key, int value) {
        if (mPrefs == null) return;
        mPrefs.edit().putInt(key, value).apply();
    }

    /**
     * Save persistent boolean state
     */
    public void savePersistentState(@NonNull String key, boolean value) {
        if (mPrefs == null) return;
        mPrefs.edit().putBoolean(key, value).apply();
    }

    /**
     * Load persistent state
     */
    @Nullable
    public String loadPersistentState(@NonNull String key) {
        if (mPrefs == null) return null;
        return mPrefs.getString(key, null);
    }

    /**
     * Load persistent state with default
     */
    @NonNull
    public String loadPersistentState(@NonNull String key, @NonNull String defaultValue) {
        if (mPrefs == null) return defaultValue;
        return mPrefs.getString(key, defaultValue);
    }

    /**
     * Load persistent integer state
     */
    public int loadPersistentInt(@NonNull String key, int defaultValue) {
        if (mPrefs == null) return defaultValue;
        return mPrefs.getInt(key, defaultValue);
    }

    /**
     * Load persistent boolean state
     */
    public boolean loadPersistentBool(@NonNull String key, boolean defaultValue) {
        if (mPrefs == null) return defaultValue;
        return mPrefs.getBoolean(key, defaultValue);
    }

    /**
     * Remove persistent state
     */
    public void removePersistentState(@NonNull String key) {
        if (mPrefs == null) return;
        mPrefs.edit().remove(key).apply();
    }

    /**
     * Clear all persistent state
     */
    public void clearPersistentState() {
        if (mPrefs == null) return;
        mPrefs.edit().clear().apply();
        LoggingHelper.d(TAG, "Persistent state cleared");
    }

    // ==================== Listeners ====================

    /**
     * Register a state change listener
     */
    public void addStateChangeListener(@NonNull String key, @NonNull StateChangeListener listener) {
        mListeners.put(key, listener);
    }

    /**
     * Remove a state change listener
     */
    public void removeStateChangeListener(@NonNull String key) {
        mListeners.remove(key);
    }

    private void notifyListeners(String key, Object oldValue, Object newValue) {
        StateChangeListener listener = mListeners.get(key);
        if (listener != null) {
            try {
                listener.onStateChanged(key, oldValue, newValue);
            } catch (Exception e) {
                LoggingHelper.e(TAG, "Error notifying listener for key: " + key, e);
            }
        }
    }

    // ==================== Session Lifecycle ====================

    /**
     * Start a new session (clears state and generates new ID)
     */
    public void startNewSession() {
        clearState();
        mSessionStartTime = java.lang.System.currentTimeMillis();
        mSessionId = generateSessionId();
        LoggingHelper.i(TAG, "New session started: " + mSessionId);
    }

    /**
     * End current session
     */
    public void endSession() {
        LoggingHelper.i(TAG, "Session ended: " + mSessionId + ", duration: " +
                StringHelper.formatDuration(getSessionDuration()));
        clearState();
    }

    private String generateSessionId() {
        return "session_" + java.lang.System.currentTimeMillis() + "_" +
                Integer.toHexString((int) (Math.random() * 0xFFFFFF));
    }

    /**
     * Get session summary for debugging
     */
    @NonNull
    public String getSessionSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("Session ID: ").append(mSessionId).append("\n");
        sb.append("Duration: ").append(StringHelper.formatDuration(getSessionDuration())).append("\n");
        sb.append("State keys: ").append(mSessionState.size()).append("\n");
        sb.append("Listeners: ").append(mListeners.size()).append("\n");
        return sb.toString();
    }
}
