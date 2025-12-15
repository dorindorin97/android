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
import android.content.SharedPreferences;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import org.csploit.android.core.System;
import org.csploit.android.net.Target;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * SessionPersistenceHelper - Manage scan session persistence
 *
 * Provides:
 * - Session auto-save functionality
 * - Session listing and management
 * - Session metadata tracking
 * - Quick session restoration
 *
 * Usage:
 * {@code
 * SessionPersistenceHelper helper = new SessionPersistenceHelper(context);
 * helper.autoSaveSession(targets);
 * List<SessionInfo> sessions = helper.listSessions();
 * helper.loadSession(sessions.get(0).filename);
 * }
 */
public final class SessionPersistenceHelper {

    private static final String TAG = "SessionPersistenceHelper";
    private static final String PREFS_NAME = "session_prefs";
    private static final String KEY_LAST_SESSION = "last_session_name";
    private static final String KEY_AUTO_SAVE_ENABLED = "auto_save_enabled";
    private static final String KEY_SESSION_COUNT = "session_count";

    private final Context mContext;
    private final SharedPreferences mPrefs;
    private final SimpleDateFormat mDateFormat;

    /**
     * Information about a saved session.
     */
    public static class SessionInfo {
        public final String filename;
        public final String displayName;
        public final long fileSize;
        public final long lastModified;
        public final String formattedDate;

        public SessionInfo(String filename, String displayName, long fileSize,
                          long lastModified, String formattedDate) {
            this.filename = filename;
            this.displayName = displayName;
            this.fileSize = fileSize;
            this.lastModified = lastModified;
            this.formattedDate = formattedDate;
        }

        @Override
        public String toString() {
            return displayName + " (" + formatFileSize(fileSize) + ")";
        }

        private String formatFileSize(long bytes) {
            if (bytes < 1024) return bytes + " B";
            if (bytes < 1024 * 1024) return String.format(Locale.US, "%.1f KB", bytes / 1024.0);
            return String.format(Locale.US, "%.1f MB", bytes / (1024.0 * 1024.0));
        }
    }

    public SessionPersistenceHelper(@NonNull Context context) {
        mContext = context.getApplicationContext();
        mPrefs = mContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        mDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US);
    }

    // ==================== Session Listing ====================

    /**
     * List all available session files.
     *
     * @return list of session information
     */
    @NonNull
    public List<SessionInfo> listSessions() {
        List<SessionInfo> sessions = new ArrayList<>();
        List<String> files = System.getAvailableSessionFiles();

        for (String filename : files) {
            File file = new File(System.getStoragePath(), filename);
            if (file.exists()) {
                String displayName = filename.replace(".dss", "");
                sessions.add(new SessionInfo(
                    filename,
                    displayName,
                    file.length(),
                    file.lastModified(),
                    mDateFormat.format(new Date(file.lastModified()))
                ));
            }
        }

        // Sort by last modified (newest first)
        sessions.sort((a, b) -> Long.compare(b.lastModified, a.lastModified));
        return sessions;
    }

    /**
     * Get the most recent session.
     *
     * @return most recent session info, or null if none
     */
    @Nullable
    public SessionInfo getMostRecentSession() {
        List<SessionInfo> sessions = listSessions();
        return sessions.isEmpty() ? null : sessions.get(0);
    }

    /**
     * Get session count.
     *
     * @return number of saved sessions
     */
    public int getSessionCount() {
        return System.getAvailableSessionFiles().size();
    }

    // ==================== Session Operations ====================

    /**
     * Save the current session with auto-generated name.
     *
     * @return the saved filename, or null on failure
     */
    @Nullable
    public String saveCurrentSession() {
        String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(new Date());
        String sessionName = "session_" + timestamp;
        return saveSession(sessionName);
    }

    /**
     * Save session with specified name.
     *
     * @param sessionName the session name
     * @return the saved filename, or null on failure
     */
    @Nullable
    public String saveSession(@NonNull String sessionName) {
        try {
            String filename = System.saveSession(sessionName);
            mPrefs.edit()
                .putString(KEY_LAST_SESSION, sessionName)
                .putInt(KEY_SESSION_COUNT, getSessionCount())
                .apply();
            LoggingHelper.d(TAG, "Session saved: " + filename);
            return filename;
        } catch (Exception e) {
            LoggingHelper.e(TAG, "Failed to save session", e);
            return null;
        }
    }

    /**
     * Load a session by filename.
     *
     * @param filename the session filename
     * @return true if loaded successfully
     */
    public boolean loadSession(@NonNull String filename) {
        try {
            System.loadSession(filename);
            String sessionName = filename.replace(".dss", "");
            mPrefs.edit().putString(KEY_LAST_SESSION, sessionName).apply();
            LoggingHelper.d(TAG, "Session loaded: " + filename);
            return true;
        } catch (Exception e) {
            LoggingHelper.e(TAG, "Failed to load session", e);
            return false;
        }
    }

    /**
     * Load the most recent session.
     *
     * @return true if loaded successfully
     */
    public boolean loadMostRecentSession() {
        SessionInfo recent = getMostRecentSession();
        if (recent != null) {
            return loadSession(recent.filename);
        }
        return false;
    }

    /**
     * Load the last used session.
     *
     * @return true if loaded successfully
     */
    public boolean loadLastSession() {
        String lastSession = mPrefs.getString(KEY_LAST_SESSION, null);
        if (lastSession != null) {
            return loadSession(lastSession + ".dss");
        }
        return false;
    }

    /**
     * Delete a session file.
     *
     * @param filename the session filename
     * @return true if deleted successfully
     */
    public boolean deleteSession(@NonNull String filename) {
        File file = new File(System.getStoragePath(), filename);
        if (file.exists()) {
            boolean deleted = file.delete();
            if (deleted) {
                LoggingHelper.d(TAG, "Session deleted: " + filename);
                mPrefs.edit().putInt(KEY_SESSION_COUNT, getSessionCount()).apply();
            }
            return deleted;
        }
        return false;
    }

    /**
     * Delete all sessions.
     *
     * @return number of sessions deleted
     */
    public int deleteAllSessions() {
        int count = 0;
        for (String filename : System.getAvailableSessionFiles()) {
            if (deleteSession(filename)) {
                count++;
            }
        }
        return count;
    }

    // ==================== Auto-save ====================

    /**
     * Check if auto-save is enabled.
     *
     * @return true if auto-save is enabled
     */
    public boolean isAutoSaveEnabled() {
        return mPrefs.getBoolean(KEY_AUTO_SAVE_ENABLED, false);
    }

    /**
     * Enable or disable auto-save.
     *
     * @param enabled true to enable
     */
    public void setAutoSaveEnabled(boolean enabled) {
        mPrefs.edit().putBoolean(KEY_AUTO_SAVE_ENABLED, enabled).apply();
    }

    /**
     * Auto-save session if enabled.
     *
     * @return the saved filename, or null if not saved
     */
    @Nullable
    public String autoSaveIfEnabled() {
        if (isAutoSaveEnabled()) {
            return saveCurrentSession();
        }
        return null;
    }

    // ==================== Session Metadata ====================

    /**
     * Get the name of the last session.
     *
     * @return last session name, or null
     */
    @Nullable
    public String getLastSessionName() {
        return mPrefs.getString(KEY_LAST_SESSION, null);
    }

    /**
     * Get total storage used by sessions.
     *
     * @return total size in bytes
     */
    public long getTotalSessionsSize() {
        long total = 0;
        for (String filename : System.getAvailableSessionFiles()) {
            File file = new File(System.getStoragePath(), filename);
            if (file.exists()) {
                total += file.length();
            }
        }
        return total;
    }

    /**
     * Get formatted total storage size.
     *
     * @return formatted size string
     */
    @NonNull
    public String getFormattedTotalSize() {
        long bytes = getTotalSessionsSize();
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format(Locale.US, "%.1f KB", bytes / 1024.0);
        return String.format(Locale.US, "%.2f MB", bytes / (1024.0 * 1024.0));
    }

    /**
     * Check if a session exists.
     *
     * @param sessionName session name (without .dss extension)
     * @return true if session exists
     */
    public boolean sessionExists(@NonNull String sessionName) {
        File file = new File(System.getStoragePath(), sessionName + ".dss");
        return file.exists();
    }

    /**
     * Generate a unique session name.
     *
     * @param baseName base name for the session
     * @return unique session name
     */
    @NonNull
    public String generateUniqueName(@NonNull String baseName) {
        if (!sessionExists(baseName)) {
            return baseName;
        }

        int counter = 1;
        String newName;
        do {
            newName = baseName + "_" + counter;
            counter++;
        } while (sessionExists(newName) && counter < 1000);

        return newName;
    }
}
