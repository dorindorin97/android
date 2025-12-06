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
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * HostTracker - Track and manage discovered hosts.
 * 
 * Provides:
 * - Host discovery tracking
 * - Host status monitoring
 * - Activity history
 * - Host statistics
 * 
 * Usage:
 * {@code
 * HostTracker tracker = HostTracker.getInstance();
 * 
 * // Track a host
 * tracker.trackHost("192.168.1.1", "AA:BB:CC:DD:EE:FF");
 * 
 * // Update status
 * tracker.updateHostStatus("192.168.1.1", HostStatus.ONLINE);
 * 
 * // Get host info
 * HostInfo info = tracker.getHost("192.168.1.1");
 * }
 */
public class HostTracker {
    
    private static final String TAG = "HostTracker";
    
    private static volatile HostTracker instance;
    
    private final ConcurrentHashMap<String, HostInfo> hosts = new ConcurrentHashMap<>();
    private final List<HostTrackerListener> listeners = new ArrayList<>();
    
    /**
     * Host status.
     */
    public enum HostStatus {
        UNKNOWN,
        ONLINE,
        OFFLINE,
        SCANNING,
        VULNERABLE
    }
    
    /**
     * Host information container.
     */
    public static class HostInfo {
        public final String ipAddress;
        public String macAddress;
        public String hostname;
        public String vendor;
        public String osFingerprint;
        public HostStatus status;
        public final long firstSeen;
        public long lastSeen;
        public long lastResponse;
        public int responseCount;
        public int openPortCount;
        public int vulnerabilityCount;
        public final List<Integer> openPorts;
        public final List<String> services;
        public final List<Activity> activityLog;
        
        HostInfo(String ip) {
            this.ipAddress = ip;
            this.status = HostStatus.UNKNOWN;
            this.firstSeen = java.lang.System.currentTimeMillis();
            this.lastSeen = firstSeen;
            this.openPorts = new ArrayList<>();
            this.services = new ArrayList<>();
            this.activityLog = new ArrayList<>();
        }
        
        public long getUptime() {
            return lastSeen - firstSeen;
        }
        
        public boolean isOnline() {
            return status == HostStatus.ONLINE;
        }
        
        public void addOpenPort(int port) {
            if (!openPorts.contains(port)) {
                openPorts.add(port);
                openPortCount = openPorts.size();
            }
        }
        
        public void addService(String service) {
            if (!services.contains(service)) {
                services.add(service);
            }
        }
        
        public void addActivity(String description) {
            activityLog.add(new Activity(description));
            if (activityLog.size() > 100) {
                activityLog.remove(0);
            }
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("HostInfo{ip=%s, mac=%s, status=%s, ports=%d}",
                    ipAddress, macAddress, status, openPortCount);
        }
    }
    
    /**
     * Activity log entry.
     */
    public static class Activity {
        public final long timestamp;
        public final String description;
        
        Activity(String description) {
            this.timestamp = java.lang.System.currentTimeMillis();
            this.description = description;
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("[%tT] %s", timestamp, description);
        }
    }
    
    /**
     * Listener for host tracking events.
     */
    public interface HostTrackerListener {
        void onHostDiscovered(HostInfo host);
        void onHostStatusChanged(HostInfo host, HostStatus oldStatus);
        void onHostLost(HostInfo host);
    }
    
    private HostTracker() {
        Log.d(TAG, "HostTracker initialized");
    }
    
    /**
     * Get singleton instance.
     */
    public static HostTracker getInstance() {
        if (instance == null) {
            synchronized (HostTracker.class) {
                if (instance == null) {
                    instance = new HostTracker();
                }
            }
        }
        return instance;
    }
    
    /**
     * Add a listener.
     */
    public void addListener(@NonNull HostTrackerListener listener) {
        synchronized (listeners) {
            if (!listeners.contains(listener)) {
                listeners.add(listener);
            }
        }
    }
    
    /**
     * Remove a listener.
     */
    public void removeListener(@NonNull HostTrackerListener listener) {
        synchronized (listeners) {
            listeners.remove(listener);
        }
    }
    
    /**
     * Track a new or existing host.
     * 
     * @param ip IP address
     * @param mac MAC address (optional)
     * @return HostInfo object
     */
    @NonNull
    public HostInfo trackHost(@NonNull String ip, @Nullable String mac) {
        HostInfo host = hosts.get(ip);
        boolean isNew = host == null;
        
        if (isNew) {
            host = new HostInfo(ip);
            hosts.put(ip, host);
        }
        
        host.lastSeen = java.lang.System.currentTimeMillis();
        
        if (mac != null && !mac.isEmpty()) {
            host.macAddress = mac.toUpperCase();
            // Try to get vendor
            if (host.vendor == null) {
                host.vendor = MacVendorHelper.getVendor(mac);
            }
        }
        
        if (isNew) {
            host.addActivity("Host discovered");
            notifyHostDiscovered(host);
        }
        
        return host;
    }
    
    /**
     * Update host status.
     */
    public void updateHostStatus(@NonNull String ip, @NonNull HostStatus status) {
        HostInfo host = hosts.get(ip);
        if (host == null) {
            host = trackHost(ip, null);
        }
        
        HostStatus oldStatus = host.status;
        if (oldStatus != status) {
            host.status = status;
            host.lastSeen = java.lang.System.currentTimeMillis();
            host.addActivity("Status changed: " + oldStatus + " -> " + status);
            notifyStatusChanged(host, oldStatus);
        }
    }
    
    /**
     * Record host response (for tracking online status).
     */
    public void recordResponse(@NonNull String ip, long responseTimeMs) {
        HostInfo host = hosts.get(ip);
        if (host != null) {
            host.lastResponse = java.lang.System.currentTimeMillis();
            host.responseCount++;
            host.lastSeen = host.lastResponse;
            
            if (host.status != HostStatus.ONLINE) {
                updateHostStatus(ip, HostStatus.ONLINE);
            }
        }
    }
    
    /**
     * Add open port to host.
     */
    public void addOpenPort(@NonNull String ip, int port, @Nullable String service) {
        HostInfo host = hosts.get(ip);
        if (host == null) {
            host = trackHost(ip, null);
        }
        
        host.addOpenPort(port);
        if (service != null && !service.isEmpty()) {
            host.addService(service);
        }
        host.addActivity("Open port found: " + port + (service != null ? " (" + service + ")" : ""));
    }
    
    /**
     * Set host OS fingerprint.
     */
    public void setOsFingerprint(@NonNull String ip, @NonNull String os) {
        HostInfo host = hosts.get(ip);
        if (host != null) {
            host.osFingerprint = os;
            host.addActivity("OS identified: " + os);
        }
    }
    
    /**
     * Set hostname.
     */
    public void setHostname(@NonNull String ip, @NonNull String hostname) {
        HostInfo host = hosts.get(ip);
        if (host != null) {
            host.hostname = hostname;
            host.addActivity("Hostname resolved: " + hostname);
        }
    }
    
    /**
     * Mark host as offline.
     */
    public void markOffline(@NonNull String ip) {
        HostInfo host = hosts.get(ip);
        if (host != null && host.status != HostStatus.OFFLINE) {
            updateHostStatus(ip, HostStatus.OFFLINE);
            notifyHostLost(host);
        }
    }
    
    /**
     * Get host info by IP.
     */
    @Nullable
    public HostInfo getHost(@NonNull String ip) {
        return hosts.get(ip);
    }
    
    /**
     * Get all tracked hosts.
     */
    @NonNull
    public List<HostInfo> getAllHosts() {
        return new ArrayList<>(hosts.values());
    }
    
    /**
     * Get online hosts only.
     */
    @NonNull
    public List<HostInfo> getOnlineHosts() {
        List<HostInfo> online = new ArrayList<>();
        for (HostInfo host : hosts.values()) {
            if (host.status == HostStatus.ONLINE) {
                online.add(host);
            }
        }
        return online;
    }
    
    /**
     * Get hosts sorted by last seen time.
     */
    @NonNull
    public List<HostInfo> getHostsByLastSeen() {
        List<HostInfo> sorted = new ArrayList<>(hosts.values());
        Collections.sort(sorted, (h1, h2) -> Long.compare(h2.lastSeen, h1.lastSeen));
        return sorted;
    }
    
    /**
     * Get hosts sorted by open port count.
     */
    @NonNull
    public List<HostInfo> getHostsByPortCount() {
        List<HostInfo> sorted = new ArrayList<>(hosts.values());
        Collections.sort(sorted, (h1, h2) -> Integer.compare(h2.openPortCount, h1.openPortCount));
        return sorted;
    }
    
    /**
     * Get host count.
     */
    public int getHostCount() {
        return hosts.size();
    }
    
    /**
     * Get online host count.
     */
    public int getOnlineCount() {
        int count = 0;
        for (HostInfo host : hosts.values()) {
            if (host.status == HostStatus.ONLINE) {
                count++;
            }
        }
        return count;
    }
    
    /**
     * Clear all tracked hosts.
     */
    public void clear() {
        hosts.clear();
        Log.d(TAG, "Cleared all tracked hosts");
    }
    
    /**
     * Remove a specific host.
     */
    public void removeHost(@NonNull String ip) {
        hosts.remove(ip);
    }
    
    /**
     * Check for stale hosts (not seen recently).
     * 
     * @param maxAgeMs maximum age in milliseconds
     * @return list of stale hosts
     */
    @NonNull
    public List<HostInfo> getStaleHosts(long maxAgeMs) {
        long now = java.lang.System.currentTimeMillis();
        List<HostInfo> stale = new ArrayList<>();
        
        for (HostInfo host : hosts.values()) {
            if (now - host.lastSeen > maxAgeMs) {
                stale.add(host);
            }
        }
        
        return stale;
    }
    
    /**
     * Mark stale hosts as offline.
     * 
     * @param maxAgeMs maximum age in milliseconds
     * @return number of hosts marked offline
     */
    public int markStaleHostsOffline(long maxAgeMs) {
        int count = 0;
        for (HostInfo host : getStaleHosts(maxAgeMs)) {
            if (host.status == HostStatus.ONLINE) {
                markOffline(host.ipAddress);
                count++;
            }
        }
        return count;
    }
    
    /**
     * Get statistics.
     */
    @NonNull
    public TrackerStats getStats() {
        int total = hosts.size();
        int online = 0;
        int offline = 0;
        int scanning = 0;
        int totalPorts = 0;
        
        for (HostInfo host : hosts.values()) {
            switch (host.status) {
                case ONLINE:
                    online++;
                    break;
                case OFFLINE:
                    offline++;
                    break;
                case SCANNING:
                    scanning++;
                    break;
                case UNKNOWN:
                case VULNERABLE:
                    // Not counted in basic stats
                    break;
            }
            totalPorts += host.openPortCount;
        }
        
        return new TrackerStats(total, online, offline, scanning, totalPorts);
    }
    
    /**
     * Tracker statistics.
     */
    public static class TrackerStats {
        public final int totalHosts;
        public final int onlineHosts;
        public final int offlineHosts;
        public final int scanningHosts;
        public final int totalOpenPorts;
        
        TrackerStats(int total, int online, int offline, int scanning, int ports) {
            this.totalHosts = total;
            this.onlineHosts = online;
            this.offlineHosts = offline;
            this.scanningHosts = scanning;
            this.totalOpenPorts = ports;
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("TrackerStats{total=%d, online=%d, offline=%d, ports=%d}",
                    totalHosts, onlineHosts, offlineHosts, totalOpenPorts);
        }
    }
    
    // Notification methods
    
    private void notifyHostDiscovered(HostInfo host) {
        synchronized (listeners) {
            for (HostTrackerListener listener : listeners) {
                try {
                    listener.onHostDiscovered(host);
                } catch (Exception e) {
                    Log.w(TAG, "Listener error", e);
                }
            }
        }
    }
    
    private void notifyStatusChanged(HostInfo host, HostStatus oldStatus) {
        synchronized (listeners) {
            for (HostTrackerListener listener : listeners) {
                try {
                    listener.onHostStatusChanged(host, oldStatus);
                } catch (Exception e) {
                    Log.w(TAG, "Listener error", e);
                }
            }
        }
    }
    
    private void notifyHostLost(HostInfo host) {
        synchronized (listeners) {
            for (HostTrackerListener listener : listeners) {
                try {
                    listener.onHostLost(host);
                } catch (Exception e) {
                    Log.w(TAG, "Listener error", e);
                }
            }
        }
    }
}
