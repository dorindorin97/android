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
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * SessionLogger - Comprehensive session logging for security operations.
 * 
 * Provides:
 * - Structured session logging
 * - Activity timeline tracking
 * - Session persistence
 * - Log export functionality
 * - Search and filtering
 * 
 * Usage:
 * {@code
 * SessionLogger logger = SessionLogger.getInstance(context);
 * 
 * // Start a session
 * String sessionId = logger.startSession("Network Scan");
 * 
 * // Log activities
 * logger.logActivity(sessionId, "Started port scan on 192.168.1.1");
 * logger.logEvent(sessionId, EventType.SCAN, "Found open port 22");
 * 
 * // End session
 * logger.endSession(sessionId);
 * }
 */
public final class SessionLogger {
    
    public static final String TAG = "SessionLogger";
    
    private static final String SESSIONS_DIR = "sessions";
    private static final String SESSION_FILE_PREFIX = "session_";
    private static final String SESSION_FILE_SUFFIX = ".log";
    private static final int MAX_MEMORY_ENTRIES = 1000;
    private static final int MAX_SESSION_AGE_DAYS = 30;
    
    private static volatile SessionLogger instance;
    
    private final Context context;
    private final File sessionsDir;
    private final Map<String, Session> activeSessions = new HashMap<>();
    private final ConcurrentLinkedQueue<LogEntry> recentEntries = new ConcurrentLinkedQueue<>();
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US);
    
    private boolean persistenceEnabled = true;
    private LogListener listener;
    
    /**
     * Event types for categorization.
     */
    public enum EventType {
        SESSION_START,
        SESSION_END,
        SCAN,
        ATTACK,
        DISCOVERY,
        CONNECTION,
        ERROR,
        WARNING,
        INFO,
        DEBUG,
        RESULT,
        USER_ACTION
    }
    
    /**
     * Log entry.
     */
    public static class LogEntry {
        public final String sessionId;
        public final long timestamp;
        public final EventType type;
        public final String message;
        public final Map<String, String> metadata;
        
        LogEntry(String sessionId, EventType type, String message, Map<String, String> metadata) {
            this.sessionId = sessionId;
            this.timestamp = System.currentTimeMillis();
            this.type = type;
            this.message = message;
            this.metadata = metadata;
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("[%tF %tT] [%s] [%s] %s",
                    timestamp, timestamp, type.name(), sessionId, message);
        }
        
        public String toDetailedString() {
            StringBuilder sb = new StringBuilder();
            sb.append(String.format("[%tF %tT.%tL] [%s] [%s]\n",
                    timestamp, timestamp, timestamp, type.name(), sessionId));
            sb.append("  Message: ").append(message).append("\n");
            if (metadata != null && !metadata.isEmpty()) {
                sb.append("  Metadata:\n");
                for (Map.Entry<String, String> entry : metadata.entrySet()) {
                    sb.append("    ").append(entry.getKey()).append(": ")
                      .append(entry.getValue()).append("\n");
                }
            }
            return sb.toString();
        }
    }
    
    /**
     * Session information.
     */
    public static class Session {
        public final String id;
        public final String name;
        public final long startTime;
        public long endTime;
        public final List<LogEntry> entries = new ArrayList<>();
        public SessionStatus status = SessionStatus.ACTIVE;
        public Map<String, String> metadata = new HashMap<>();
        
        Session(String id, String name) {
            this.id = id;
            this.name = name;
            this.startTime = System.currentTimeMillis();
        }
        
        public long getDuration() {
            long end = endTime > 0 ? endTime : System.currentTimeMillis();
            return end - startTime;
        }
        
        public int getEntryCount() {
            return entries.size();
        }
    }
    
    /**
     * Session status.
     */
    public enum SessionStatus {
        ACTIVE,
        COMPLETED,
        FAILED,
        CANCELLED
    }
    
    /**
     * Log listener callback.
     */
    public interface LogListener {
        void onLogEntry(LogEntry entry);
        void onSessionStarted(Session session);
        void onSessionEnded(Session session);
    }
    
    private SessionLogger(Context context) {
        this.context = context.getApplicationContext();
        this.sessionsDir = new File(context.getFilesDir(), SESSIONS_DIR);
        
        if (!sessionsDir.exists()) {
            sessionsDir.mkdirs();
        }
        
        // Cleanup old sessions
        cleanupOldSessions();
    }
    
    /**
     * Get singleton instance.
     */
    public static SessionLogger getInstance(@NonNull Context context) {
        if (instance == null) {
            synchronized (SessionLogger.class) {
                if (instance == null) {
                    instance = new SessionLogger(context);
                }
            }
        }
        return instance;
    }
    
    /**
     * Set log listener.
     */
    public void setListener(@Nullable LogListener listener) {
        this.listener = listener;
    }
    
    /**
     * Enable or disable persistence.
     */
    public void setPersistenceEnabled(boolean enabled) {
        this.persistenceEnabled = enabled;
    }
    
    /**
     * Start a new session.
     * 
     * @param name session name/description
     * @return session ID
     */
    @NonNull
    public String startSession(@NonNull String name) {
        String sessionId = generateSessionId();
        Session session = new Session(sessionId, name);
        
        synchronized (activeSessions) {
            activeSessions.put(sessionId, session);
        }
        
        logEvent(sessionId, EventType.SESSION_START, "Session started: " + name, null);
        
        if (listener != null) {
            listener.onSessionStarted(session);
        }
        
        return sessionId;
    }
    
    /**
     * End a session.
     */
    public void endSession(@NonNull String sessionId) {
        endSession(sessionId, SessionStatus.COMPLETED);
    }
    
    /**
     * End a session with status.
     */
    public void endSession(@NonNull String sessionId, @NonNull SessionStatus status) {
        Session session;
        synchronized (activeSessions) {
            session = activeSessions.remove(sessionId);
        }
        
        if (session != null) {
            session.endTime = System.currentTimeMillis();
            session.status = status;
            
            logEvent(sessionId, EventType.SESSION_END, 
                    String.format("Session ended: %s (duration: %dms)", 
                            status.name(), session.getDuration()), null);
            
            if (persistenceEnabled) {
                persistSession(session);
            }
            
            if (listener != null) {
                listener.onSessionEnded(session);
            }
        }
    }
    
    /**
     * Log an activity message.
     */
    public void logActivity(@NonNull String sessionId, @NonNull String message) {
        logEvent(sessionId, EventType.INFO, message, null);
    }
    
    /**
     * Log an event with type.
     */
    public void logEvent(@NonNull String sessionId, @NonNull EventType type, @NonNull String message) {
        logEvent(sessionId, type, message, null);
    }
    
    /**
     * Log an event with metadata.
     */
    public void logEvent(@NonNull String sessionId, @NonNull EventType type, 
                        @NonNull String message, @Nullable Map<String, String> metadata) {
        LogEntry entry = new LogEntry(sessionId, type, message, metadata);
        
        // Add to memory queue
        recentEntries.offer(entry);
        while (recentEntries.size() > MAX_MEMORY_ENTRIES) {
            recentEntries.poll();
        }
        
        // Add to session if active
        Session session;
        synchronized (activeSessions) {
            session = activeSessions.get(sessionId);
        }
        if (session != null) {
            synchronized (session.entries) {
                session.entries.add(entry);
            }
        }
        
        // Notify listener
        if (listener != null) {
            listener.onLogEntry(entry);
        }
        
        // Log to Android logger
        String logMsg = String.format("[%s] %s", sessionId, message);
        switch (type) {
            case ERROR:
                Log.e(TAG, logMsg);
                break;
            case WARNING:
                Log.w(TAG, logMsg);
                break;
            case DEBUG:
                Log.d(TAG, logMsg);
                break;
            default:
                Log.i(TAG, logMsg);
        }
    }
    
    /**
     * Log a scan event.
     */
    public void logScan(@NonNull String sessionId, @NonNull String target, 
                        @NonNull String scanType, @Nullable String result) {
        Map<String, String> metadata = new HashMap<>();
        metadata.put("target", target);
        metadata.put("scanType", scanType);
        if (result != null) {
            metadata.put("result", result);
        }
        logEvent(sessionId, EventType.SCAN, 
                String.format("%s scan on %s", scanType, target), metadata);
    }
    
    /**
     * Log a discovery event.
     */
    public void logDiscovery(@NonNull String sessionId, @NonNull String discovered, 
                            @NonNull String details) {
        Map<String, String> metadata = new HashMap<>();
        metadata.put("discovered", discovered);
        metadata.put("details", details);
        logEvent(sessionId, EventType.DISCOVERY, 
                String.format("Discovered: %s - %s", discovered, details), metadata);
    }
    
    /**
     * Log an error.
     */
    public void logError(@NonNull String sessionId, @NonNull String error, 
                        @Nullable Throwable exception) {
        Map<String, String> metadata = new HashMap<>();
        metadata.put("error", error);
        if (exception != null) {
            metadata.put("exception", exception.getClass().getName());
            metadata.put("exceptionMessage", exception.getMessage());
        }
        logEvent(sessionId, EventType.ERROR, error, metadata);
    }
    
    /**
     * Get active session.
     */
    @Nullable
    public Session getSession(@NonNull String sessionId) {
        synchronized (activeSessions) {
            return activeSessions.get(sessionId);
        }
    }
    
    /**
     * Get all active sessions.
     */
    @NonNull
    public List<Session> getActiveSessions() {
        synchronized (activeSessions) {
            return new ArrayList<>(activeSessions.values());
        }
    }
    
    /**
     * Get recent log entries.
     */
    @NonNull
    public List<LogEntry> getRecentEntries() {
        return new ArrayList<>(recentEntries);
    }
    
    /**
     * Get entries filtered by type.
     */
    @NonNull
    public List<LogEntry> getEntriesByType(@NonNull EventType type) {
        List<LogEntry> filtered = new ArrayList<>();
        for (LogEntry entry : recentEntries) {
            if (entry.type == type) {
                filtered.add(entry);
            }
        }
        return filtered;
    }
    
    /**
     * Get entries filtered by session.
     */
    @NonNull
    public List<LogEntry> getEntriesBySession(@NonNull String sessionId) {
        List<LogEntry> filtered = new ArrayList<>();
        for (LogEntry entry : recentEntries) {
            if (entry.sessionId.equals(sessionId)) {
                filtered.add(entry);
            }
        }
        return filtered;
    }
    
    /**
     * Search entries by keyword.
     */
    @NonNull
    public List<LogEntry> searchEntries(@NonNull String keyword) {
        List<LogEntry> results = new ArrayList<>();
        String lowerKeyword = keyword.toLowerCase();
        
        for (LogEntry entry : recentEntries) {
            if (entry.message.toLowerCase().contains(lowerKeyword)) {
                results.add(entry);
            }
        }
        return results;
    }
    
    /**
     * Export session to file.
     */
    @Nullable
    public File exportSession(@NonNull String sessionId) {
        Session session;
        synchronized (activeSessions) {
            session = activeSessions.get(sessionId);
        }
        
        if (session == null) {
            // Try to load from persisted sessions
            session = loadSession(sessionId);
        }
        
        if (session == null) {
            return null;
        }
        
        File exportDir = new File(context.getExternalFilesDir(null), "exports");
        if (!exportDir.exists()) {
            exportDir.mkdirs();
        }
        
        String filename = String.format("session_%s_%tY%tm%td_%tH%tM%tS.txt",
                session.name.replaceAll("[^a-zA-Z0-9]", "_"),
                session.startTime, session.startTime, session.startTime,
                session.startTime, session.startTime, session.startTime);
        File exportFile = new File(exportDir, filename);
        
        try (FileWriter writer = new FileWriter(exportFile)) {
            writer.write("=== Session Export ===\n");
            writer.write("Session ID: " + session.id + "\n");
            writer.write("Name: " + session.name + "\n");
            writer.write("Start: " + dateFormat.format(new Date(session.startTime)) + "\n");
            if (session.endTime > 0) {
                writer.write("End: " + dateFormat.format(new Date(session.endTime)) + "\n");
            }
            writer.write("Status: " + session.status + "\n");
            writer.write("Duration: " + session.getDuration() + "ms\n");
            writer.write("Entries: " + session.entries.size() + "\n");
            writer.write("\n=== Log Entries ===\n\n");
            
            for (LogEntry entry : session.entries) {
                writer.write(entry.toDetailedString());
                writer.write("\n");
            }
            
            return exportFile;
        } catch (IOException e) {
            Log.e(TAG, "Failed to export session", e);
            return null;
        }
    }
    
    /**
     * List saved sessions.
     */
    @NonNull
    public List<String> listSavedSessions() {
        List<String> sessions = new ArrayList<>();
        File[] files = sessionsDir.listFiles();
        
        if (files != null) {
            for (File file : files) {
                if (file.getName().startsWith(SESSION_FILE_PREFIX) &&
                    file.getName().endsWith(SESSION_FILE_SUFFIX)) {
                    String sessionId = file.getName()
                            .replace(SESSION_FILE_PREFIX, "")
                            .replace(SESSION_FILE_SUFFIX, "");
                    sessions.add(sessionId);
                }
            }
        }
        
        return sessions;
    }
    
    /**
     * Clear all logs.
     */
    public void clearAll() {
        recentEntries.clear();
        synchronized (activeSessions) {
            activeSessions.clear();
        }
    }
    
    // Private helper methods
    
    private String generateSessionId() {
        return String.format("%d_%d", System.currentTimeMillis(), (int)(Math.random() * 10000));
    }
    
    private void persistSession(Session session) {
        executor.submit(() -> {
            File file = new File(sessionsDir, SESSION_FILE_PREFIX + session.id + SESSION_FILE_SUFFIX);
            try (FileWriter writer = new FileWriter(file)) {
                writer.write("ID:" + session.id + "\n");
                writer.write("NAME:" + session.name + "\n");
                writer.write("START:" + session.startTime + "\n");
                writer.write("END:" + session.endTime + "\n");
                writer.write("STATUS:" + session.status.name() + "\n");
                writer.write("ENTRIES:\n");
                
                for (LogEntry entry : session.entries) {
                    writer.write(String.format("ENTRY|%d|%s|%s\n",
                            entry.timestamp, entry.type.name(), entry.message));
                }
            } catch (IOException e) {
                Log.e(TAG, "Failed to persist session", e);
            }
        });
    }
    
    @Nullable
    private Session loadSession(String sessionId) {
        File file = new File(sessionsDir, SESSION_FILE_PREFIX + sessionId + SESSION_FILE_SUFFIX);
        if (!file.exists()) {
            return null;
        }
        
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            Session session = null;
            
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("ID:")) {
                    String id = line.substring(3);
                    line = reader.readLine();
                    String name = line.startsWith("NAME:") ? line.substring(5) : "Unknown";
                    session = new Session(id, name);
                } else if (session != null && line.startsWith("START:")) {
                    // startTime is final, set in constructor
                } else if (session != null && line.startsWith("END:")) {
                    session.endTime = Long.parseLong(line.substring(4));
                } else if (session != null && line.startsWith("STATUS:")) {
                    session.status = SessionStatus.valueOf(line.substring(7));
                } else if (session != null && line.startsWith("ENTRY|")) {
                    String[] parts = line.split("\\|", 4);
                    if (parts.length >= 4) {
                        LogEntry entry = new LogEntry(sessionId,
                                EventType.valueOf(parts[2]), parts[3], null);
                        session.entries.add(entry);
                    }
                }
            }
            
            return session;
        } catch (Exception e) {
            Log.e(TAG, "Failed to load session", e);
            return null;
        }
    }
    
    private void cleanupOldSessions() {
        executor.submit(() -> {
            long cutoff = System.currentTimeMillis() - (MAX_SESSION_AGE_DAYS * 24L * 60 * 60 * 1000);
            File[] files = sessionsDir.listFiles();
            
            if (files != null) {
                for (File file : files) {
                    if (file.lastModified() < cutoff) {
                        file.delete();
                    }
                }
            }
        });
    }
}
