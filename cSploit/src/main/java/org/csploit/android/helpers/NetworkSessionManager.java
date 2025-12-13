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

import androidx.annotation.NonNull;
import org.csploit.android.helpers.LoggingHelper;
import androidx.annotation.Nullable;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * NetworkSessionManager - Manages network scanning sessions and state.
 *
 * Provides:
 * - Session lifecycle management
 * - Session state tracking
 * - Session statistics
 * - Auto-cleanup of stale sessions
 * - Session persistence support
 *
 * Usage:
 * {@code
 * NetworkSessionManager manager = NetworkSessionManager.getInstance();
 *
 * // Start new session
 * Session session = manager.startSession("WiFi Network");
 *
 * // Track targets
 * session.addTarget("192.168.1.1");
 *
 * // End session
 * manager.endSession(session.id);
 * }
 */
public final class NetworkSessionManager {

    private static final String TAG = "NetworkSessionManager";
    private static final long SESSION_TIMEOUT_MS = TimeUnit.HOURS.toMillis(2);
    private static final long CLEANUP_INTERVAL_MS = TimeUnit.MINUTES.toMillis(5);

    private static volatile NetworkSessionManager instance;

    private final Map<String, Session> activeSessions;
    private final Map<String, Session> completedSessions;
    private final List<SessionListener> listeners;
    private final ScheduledExecutorService scheduler;
    private boolean cleanupEnabled = true;

    /**
     * Session states.
     */
    public enum SessionState {
        INITIALIZING,
        SCANNING,
        PAUSED,
        COMPLETED,
        FAILED,
        CANCELLED
    }

    /**
     * Session information container.
     */
    public static class Session {
        public final String id;
        public final String networkName;
        public final Date startTime;
        public Date endTime;
        public SessionState state;
        public String networkInterface;
        public String gatewayIp;
        public String localIp;
        public String subnetMask;

        // Statistics
        public int targetsDiscovered;
        public int targetsScanned;
        public int openPortsFound;
        public int servicesIdentified;
        public int vulnerabilitiesFound;

        // Target tracking
        public final List<String> targetIps;
        public final Map<String, TargetInfo> targets;

        // Timing
        public long scanDurationMs;
        public long lastActivityMs;

        // Notes
        public String notes;

        public Session(@NonNull String networkName) {
            this.id = UUID.randomUUID().toString();
            this.networkName = networkName;
            this.startTime = new Date();
            this.state = SessionState.INITIALIZING;
            this.targetIps = Collections.synchronizedList(new ArrayList<>());
            this.targets = new ConcurrentHashMap<>();
            this.lastActivityMs = java.lang.System.currentTimeMillis();
        }

        @NonNull
        @Override
        public String toString() {
            return String.format("Session{id='%s', network='%s', state=%s, targets=%d}",
                    id.substring(0, 8), networkName, state, targetsDiscovered);
        }
    }

    /**
     * Target information within a session.
     */
    public static class TargetInfo {
        public String ipAddress;
        public String macAddress;
        public String hostname;
        public String osGuess;
        public List<Integer> openPorts;
        public List<String> services;
        public List<String> vulnerabilities;
        public Date firstSeen;
        public Date lastSeen;
        public boolean isGateway;
        public boolean isLocal;

        public TargetInfo(@NonNull String ip) {
            this.ipAddress = ip;
            this.openPorts = new ArrayList<>();
            this.services = new ArrayList<>();
            this.vulnerabilities = new ArrayList<>();
            this.firstSeen = new Date();
            this.lastSeen = new Date();
        }
    }

    /**
     * Session event listener interface.
     */
    public interface SessionListener {
        void onSessionStarted(Session session);
        void onSessionUpdated(Session session);
        void onSessionEnded(Session session);
        void onTargetDiscovered(Session session, TargetInfo target);
    }

    private NetworkSessionManager() {
        activeSessions = new ConcurrentHashMap<>();
        completedSessions = new ConcurrentHashMap<>();
        listeners = Collections.synchronizedList(new ArrayList<>());
        scheduler = Executors.newSingleThreadScheduledExecutor();

        // Start cleanup task
        scheduler.scheduleAtFixedRate(this::cleanupStaleSessions,
                CLEANUP_INTERVAL_MS, CLEANUP_INTERVAL_MS, TimeUnit.MILLISECONDS);
    }

    /**
     * Get singleton instance.
     */
    @NonNull
    public static NetworkSessionManager getInstance() {
        if (instance == null) {
            synchronized (NetworkSessionManager.class) {
                if (instance == null) {
                    instance = new NetworkSessionManager();
                }
            }
        }
        return instance;
    }

    /**
     * Start a new session.
     */
    @NonNull
    public Session startSession(@NonNull String networkName) {
        Session session = new Session(networkName);
        activeSessions.put(session.id, session);

        LoggingHelper.i(TAG, "Started session: " + session.id + " for network: " + networkName);
        notifySessionStarted(session);

        return session;
    }

    /**
     * Start a session with network details.
     */
    @NonNull
    public Session startSession(@NonNull String networkName, @Nullable String iface,
            @Nullable String gateway, @Nullable String localIp, @Nullable String subnet) {
        Session session = startSession(networkName);
        session.networkInterface = iface;
        session.gatewayIp = gateway;
        session.localIp = localIp;
        session.subnetMask = subnet;
        return session;
    }

    /**
     * Get active session by ID.
     */
    @Nullable
    public Session getSession(@NonNull String sessionId) {
        Session session = activeSessions.get(sessionId);
        if (session == null) {
            session = completedSessions.get(sessionId);
        }
        return session;
    }

    /**
     * Get all active sessions.
     */
    @NonNull
    public List<Session> getActiveSessions() {
        return new ArrayList<>(activeSessions.values());
    }

    /**
     * Get current/most recent session.
     */
    @Nullable
    public Session getCurrentSession() {
        if (activeSessions.isEmpty()) {
            return null;
        }
        Session latest = null;
        for (Session s : activeSessions.values()) {
            if (latest == null || s.lastActivityMs > latest.lastActivityMs) {
                latest = s;
            }
        }
        return latest;
    }

    /**
     * Update session state.
     */
    public void updateSessionState(@NonNull String sessionId, @NonNull SessionState newState) {
        Session session = activeSessions.get(sessionId);
        if (session != null) {
            session.state = newState;
            session.lastActivityMs = java.lang.System.currentTimeMillis();
            notifySessionUpdated(session);
        }
    }

    /**
     * Add target to session.
     */
    public void addTarget(@NonNull String sessionId, @NonNull String ipAddress) {
        Session session = activeSessions.get(sessionId);
        if (session != null && !session.targetIps.contains(ipAddress)) {
            session.targetIps.add(ipAddress);
            TargetInfo target = new TargetInfo(ipAddress);
            session.targets.put(ipAddress, target);
            session.targetsDiscovered++;
            session.lastActivityMs = java.lang.System.currentTimeMillis();

            notifyTargetDiscovered(session, target);
        }
    }

    /**
     * Update target information.
     */
    public void updateTarget(@NonNull String sessionId, @NonNull TargetInfo targetInfo) {
        Session session = activeSessions.get(sessionId);
        if (session != null) {
            targetInfo.lastSeen = new Date();
            session.targets.put(targetInfo.ipAddress, targetInfo);
            session.lastActivityMs = java.lang.System.currentTimeMillis();
            notifySessionUpdated(session);
        }
    }

    /**
     * Record open port found.
     */
    public void recordOpenPort(@NonNull String sessionId, @NonNull String ipAddress, int port) {
        Session session = activeSessions.get(sessionId);
        if (session != null) {
            TargetInfo target = session.targets.get(ipAddress);
            if (target != null && !target.openPorts.contains(port)) {
                target.openPorts.add(port);
                session.openPortsFound++;
                session.lastActivityMs = java.lang.System.currentTimeMillis();
            }
        }
    }

    /**
     * Record service identified.
     */
    public void recordService(@NonNull String sessionId, @NonNull String ipAddress, @NonNull String service) {
        Session session = activeSessions.get(sessionId);
        if (session != null) {
            TargetInfo target = session.targets.get(ipAddress);
            if (target != null && !target.services.contains(service)) {
                target.services.add(service);
                session.servicesIdentified++;
                session.lastActivityMs = java.lang.System.currentTimeMillis();
            }
        }
    }

    /**
     * Record vulnerability found.
     */
    public void recordVulnerability(@NonNull String sessionId, @NonNull String ipAddress, @NonNull String vuln) {
        Session session = activeSessions.get(sessionId);
        if (session != null) {
            TargetInfo target = session.targets.get(ipAddress);
            if (target != null && !target.vulnerabilities.contains(vuln)) {
                target.vulnerabilities.add(vuln);
                session.vulnerabilitiesFound++;
                session.lastActivityMs = java.lang.System.currentTimeMillis();
            }
        }
    }

    /**
     * Pause session.
     */
    public void pauseSession(@NonNull String sessionId) {
        updateSessionState(sessionId, SessionState.PAUSED);
    }

    /**
     * Resume session.
     */
    public void resumeSession(@NonNull String sessionId) {
        updateSessionState(sessionId, SessionState.SCANNING);
    }

    /**
     * End session normally.
     */
    public void endSession(@NonNull String sessionId) {
        Session session = activeSessions.remove(sessionId);
        if (session != null) {
            session.state = SessionState.COMPLETED;
            session.endTime = new Date();
            session.scanDurationMs = session.endTime.getTime() - session.startTime.getTime();
            completedSessions.put(sessionId, session);

            LoggingHelper.i(TAG, "Ended session: " + sessionId +
                    " (targets: " + session.targetsDiscovered +
                    ", ports: " + session.openPortsFound + ")");
            notifySessionEnded(session);
        }
    }

    /**
     * Cancel session.
     */
    public void cancelSession(@NonNull String sessionId) {
        Session session = activeSessions.remove(sessionId);
        if (session != null) {
            session.state = SessionState.CANCELLED;
            session.endTime = new Date();
            completedSessions.put(sessionId, session);
            notifySessionEnded(session);
        }
    }

    /**
     * Mark session as failed.
     */
    public void failSession(@NonNull String sessionId, @Nullable String reason) {
        Session session = activeSessions.remove(sessionId);
        if (session != null) {
            session.state = SessionState.FAILED;
            session.endTime = new Date();
            if (reason != null) {
                session.notes = "Failed: " + reason;
            }
            completedSessions.put(sessionId, session);
            notifySessionEnded(session);
        }
    }

    /**
     * Add session listener.
     */
    public void addListener(@NonNull SessionListener listener) {
        if (!listeners.contains(listener)) {
            listeners.add(listener);
        }
    }

    /**
     * Remove session listener.
     */
    public void removeListener(@NonNull SessionListener listener) {
        listeners.remove(listener);
    }

    /**
     * Get session statistics.
     */
    @NonNull
    public SessionStats getStats() {
        SessionStats stats = new SessionStats();
        stats.activeSessions = activeSessions.size();
        stats.completedSessions = completedSessions.size();

        int totalTargets = 0, totalPorts = 0, totalVulns = 0;
        for (Session s : activeSessions.values()) {
            totalTargets += s.targetsDiscovered;
            totalPorts += s.openPortsFound;
            totalVulns += s.vulnerabilitiesFound;
        }
        for (Session s : completedSessions.values()) {
            totalTargets += s.targetsDiscovered;
            totalPorts += s.openPortsFound;
            totalVulns += s.vulnerabilitiesFound;
        }

        stats.totalTargets = totalTargets;
        stats.totalOpenPorts = totalPorts;
        stats.totalVulnerabilities = totalVulns;

        return stats;
    }

    /**
     * Export session to report format.
     */
    @NonNull
    public String exportSession(@NonNull String sessionId) {
        Session session = getSession(sessionId);
        if (session == null) {
            return "Session not found: " + sessionId;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("=== Network Scan Report ===\n\n");
        sb.append("Session ID: ").append(session.id).append("\n");
        sb.append("Network: ").append(session.networkName).append("\n");
        sb.append("Started: ").append(session.startTime).append("\n");
        if (session.endTime != null) {
            sb.append("Ended: ").append(session.endTime).append("\n");
            sb.append("Duration: ").append(session.scanDurationMs / 1000).append(" seconds\n");
        }
        sb.append("State: ").append(session.state).append("\n");
        sb.append("\n--- Network Details ---\n");
        sb.append("Interface: ").append(session.networkInterface).append("\n");
        sb.append("Local IP: ").append(session.localIp).append("\n");
        sb.append("Gateway: ").append(session.gatewayIp).append("\n");
        sb.append("Subnet: ").append(session.subnetMask).append("\n");
        sb.append("\n--- Statistics ---\n");
        sb.append("Targets Discovered: ").append(session.targetsDiscovered).append("\n");
        sb.append("Open Ports Found: ").append(session.openPortsFound).append("\n");
        sb.append("Services Identified: ").append(session.servicesIdentified).append("\n");
        sb.append("Vulnerabilities: ").append(session.vulnerabilitiesFound).append("\n");
        sb.append("\n--- Targets ---\n");

        for (TargetInfo target : session.targets.values()) {
            sb.append("\n").append(target.ipAddress);
            if (target.hostname != null) {
                sb.append(" (").append(target.hostname).append(")");
            }
            sb.append("\n");
            if (target.macAddress != null) {
                sb.append("  MAC: ").append(target.macAddress).append("\n");
            }
            if (target.osGuess != null) {
                sb.append("  OS: ").append(target.osGuess).append("\n");
            }
            if (!target.openPorts.isEmpty()) {
                sb.append("  Ports: ").append(target.openPorts).append("\n");
            }
            if (!target.services.isEmpty()) {
                sb.append("  Services: ").append(target.services).append("\n");
            }
            if (!target.vulnerabilities.isEmpty()) {
                sb.append("  Vulnerabilities: ").append(target.vulnerabilities).append("\n");
            }
        }

        return sb.toString();
    }

    /**
     * Clear all completed sessions.
     */
    public void clearCompletedSessions() {
        completedSessions.clear();
        LoggingHelper.i(TAG, "Cleared completed sessions");
    }

    /**
     * Set cleanup enabled.
     */
    public void setCleanupEnabled(boolean enabled) {
        this.cleanupEnabled = enabled;
    }

    /**
     * Cleanup stale sessions.
     */
    private void cleanupStaleSessions() {
        if (!cleanupEnabled) return;

        long now = java.lang.System.currentTimeMillis();
        List<String> stale = new ArrayList<>();

        for (Session session : activeSessions.values()) {
            if ((now - session.lastActivityMs) > SESSION_TIMEOUT_MS) {
                stale.add(session.id);
            }
        }

        for (String id : stale) {
            LoggingHelper.w(TAG, "Cleaning up stale session: " + id);
            failSession(id, "Session timeout");
        }
    }

    /**
     * Shutdown manager.
     */
    public void shutdown() {
        scheduler.shutdown();
        for (String id : new ArrayList<>(activeSessions.keySet())) {
            endSession(id);
        }
    }

    // Notification helpers
    private void notifySessionStarted(Session session) {
        for (SessionListener l : listeners) {
            try {
                l.onSessionStarted(session);
            } catch (Exception e) {
                LoggingHelper.w(TAG, "Listener exception on session started: " + e.getMessage());
            }
        }
    }

    private void notifySessionUpdated(Session session) {
        for (SessionListener l : listeners) {
            try {
                l.onSessionUpdated(session);
            } catch (Exception e) {
                LoggingHelper.w(TAG, "Listener exception on session updated: " + e.getMessage());
            }
        }
    }

    private void notifySessionEnded(Session session) {
        for (SessionListener l : listeners) {
            try {
                l.onSessionEnded(session);
            } catch (Exception e) {
                LoggingHelper.w(TAG, "Listener exception on session ended: " + e.getMessage());
            }
        }
    }

    private void notifyTargetDiscovered(Session session, TargetInfo target) {
        for (SessionListener l : listeners) {
            try {
                l.onTargetDiscovered(session, target);
            } catch (Exception e) {
                LoggingHelper.w(TAG, "Listener exception on target discovered: " + e.getMessage());
            }
        }
    }

    /**
     * Session statistics.
     */
    public static class SessionStats {
        public int activeSessions;
        public int completedSessions;
        public int totalTargets;
        public int totalOpenPorts;
        public int totalVulnerabilities;

        @NonNull
        @Override
        public String toString() {
            return String.format("Stats{active=%d, completed=%d, targets=%d, ports=%d, vulns=%d}",
                    activeSessions, completedSessions, totalTargets, totalOpenPorts, totalVulnerabilities);
        }
    }
}
