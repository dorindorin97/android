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

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * ProcessHelper - System process management utilities.
 * 
 * Provides:
 * - Process listing and filtering
 * - Process killing/signaling
 * - CPU/memory usage monitoring
 * - Network process detection
 * - Process tree management
 * 
 * Usage:
 * {@code
 * // List all processes
 * List<ProcessInfo> processes = ProcessHelper.listProcesses();
 * 
 * // Find process by name
 * ProcessInfo nginx = ProcessHelper.findByName("nginx");
 * 
 * // Kill process
 * ProcessHelper.kill(pid);
 * 
 * // Get network processes
 * List<ProcessInfo> netProcs = ProcessHelper.getNetworkProcesses();
 * }
 */
public final class ProcessHelper {
    
    private static final String TAG = "ProcessHelper";
    
    @SuppressWarnings("unused") // Reserved for advanced parsing
    private static final Pattern PS_PATTERN = Pattern.compile(
            "^\\s*(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\S+)\\s+(\\S+)\\s+(.*)$"
    );
    
    /**
     * Process state.
     */
    public enum ProcessState {
        RUNNING("R"),
        SLEEPING("S"),
        DISK_SLEEP("D"),
        STOPPED("T"),
        ZOMBIE("Z"),
        DEAD("X"),
        UNKNOWN("?");
        
        private final String code;
        
        ProcessState(String code) {
            this.code = code;
        }
        
        public String getCode() {
            return code;
        }
        
        @NonNull
        public static ProcessState fromCode(@NonNull String code) {
            for (ProcessState state : values()) {
                if (code.startsWith(state.code)) {
                    return state;
                }
            }
            return UNKNOWN;
        }
    }
    
    /**
     * Signal types.
     */
    public enum Signal {
        SIGHUP(1, "Hangup"),
        SIGINT(2, "Interrupt"),
        SIGQUIT(3, "Quit"),
        SIGKILL(9, "Kill"),
        SIGTERM(15, "Terminate"),
        SIGCONT(18, "Continue"),
        SIGSTOP(19, "Stop");
        
        private final int number;
        private final String description;
        
        Signal(int number, String description) {
            this.number = number;
            this.description = description;
        }
        
        public int getNumber() {
            return number;
        }
        
        public String getDescription() {
            return description;
        }
    }
    
    /**
     * Process information.
     */
    public static class ProcessInfo {
        public int pid;
        public int ppid;        // Parent PID
        public int uid;
        public String user;
        public String name;
        public String cmdline;
        public ProcessState state;
        public float cpuPercent;
        public float memPercent;
        public long virtualMemory;  // VSZ in KB
        public long residentMemory; // RSS in KB
        public long startTime;
        public String tty;
        
        @NonNull
        @Override
        public String toString() {
            return String.format("Process{pid=%d, name='%s', state=%s, cpu=%.1f%%, mem=%.1f%%}",
                    pid, name, state, cpuPercent, memPercent);
        }
    }
    
    private ProcessHelper() {}
    
    /**
     * List all processes.
     */
    @NonNull
    public static List<ProcessInfo> listProcesses() {
        List<ProcessInfo> processes = new ArrayList<>();
        
        try {
            // Use ps command to get process list
            Process process = Runtime.getRuntime().exec(new String[]{
                    "ps", "-eo", "pid,ppid,uid,vsz,rss,stat,comm,args"
            });
            
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
            String line;
            boolean firstLine = true;
            
            while ((line = reader.readLine()) != null) {
                if (firstLine) {
                    firstLine = false;
                    continue; // Skip header
                }
                
                ProcessInfo info = parseProcessLine(line);
                if (info != null) {
                    processes.add(info);
                }
            }
            
            process.waitFor();
        } catch (Exception e) {
            Log.e(TAG, "Failed to list processes", e);
        }
        
        return processes;
    }
    
    /**
     * Parse a ps output line.
     */
    @Nullable
    private static ProcessInfo parseProcessLine(@NonNull String line) {
        try {
            String[] parts = line.trim().split("\\s+", 8);
            if (parts.length < 7) {
                return null;
            }
            
            ProcessInfo info = new ProcessInfo();
            info.pid = Integer.parseInt(parts[0]);
            info.ppid = Integer.parseInt(parts[1]);
            info.uid = Integer.parseInt(parts[2]);
            info.virtualMemory = Long.parseLong(parts[3]);
            info.residentMemory = Long.parseLong(parts[4]);
            info.state = ProcessState.fromCode(parts[5]);
            info.name = parts[6];
            info.cmdline = parts.length > 7 ? parts[7] : parts[6];
            
            return info;
        } catch (Exception e) {
            return null;
        }
    }
    
    /**
     * Find process by PID.
     */
    @Nullable
    public static ProcessInfo findByPid(int pid) {
        for (ProcessInfo process : listProcesses()) {
            if (process.pid == pid) {
                return process;
            }
        }
        return null;
    }
    
    /**
     * Find processes by name.
     */
    @NonNull
    public static List<ProcessInfo> findByName(@NonNull String name) {
        List<ProcessInfo> matches = new ArrayList<>();
        for (ProcessInfo process : listProcesses()) {
            if (process.name.equals(name) || process.name.contains(name)) {
                matches.add(process);
            }
        }
        return matches;
    }
    
    /**
     * Find first process by name.
     */
    @Nullable
    public static ProcessInfo findFirstByName(@NonNull String name) {
        List<ProcessInfo> matches = findByName(name);
        return matches.isEmpty() ? null : matches.get(0);
    }
    
    /**
     * Check if process with PID exists.
     */
    public static boolean exists(int pid) {
        return findByPid(pid) != null;
    }
    
    /**
     * Check if process with name exists.
     */
    public static boolean exists(@NonNull String name) {
        return !findByName(name).isEmpty();
    }
    
    /**
     * Kill process by PID.
     */
    public static boolean kill(int pid) {
        return kill(pid, Signal.SIGTERM);
    }
    
    /**
     * Force kill process by PID.
     */
    public static boolean forceKill(int pid) {
        return kill(pid, Signal.SIGKILL);
    }
    
    /**
     * Send signal to process.
     */
    public static boolean kill(int pid, @NonNull Signal signal) {
        try {
            Process process = Runtime.getRuntime().exec(new String[]{
                    "kill", "-" + signal.getNumber(), String.valueOf(pid)
            });
            process.waitFor();
            return process.exitValue() == 0;
        } catch (Exception e) {
            Log.e(TAG, "Failed to kill process " + pid, e);
            return false;
        }
    }
    
    /**
     * Kill all processes by name.
     */
    public static int killByName(@NonNull String name) {
        int killed = 0;
        for (ProcessInfo process : findByName(name)) {
            if (kill(process.pid)) {
                killed++;
            }
        }
        return killed;
    }
    
    /**
     * Get child processes.
     */
    @NonNull
    public static List<ProcessInfo> getChildren(int ppid) {
        List<ProcessInfo> children = new ArrayList<>();
        for (ProcessInfo process : listProcesses()) {
            if (process.ppid == ppid) {
                children.add(process);
            }
        }
        return children;
    }
    
    /**
     * Get process tree (process and all descendants).
     */
    @NonNull
    public static List<ProcessInfo> getProcessTree(int pid) {
        List<ProcessInfo> tree = new ArrayList<>();
        ProcessInfo root = findByPid(pid);
        if (root != null) {
            tree.add(root);
            addDescendants(pid, tree);
        }
        return tree;
    }
    
    private static void addDescendants(int pid, List<ProcessInfo> tree) {
        for (ProcessInfo child : getChildren(pid)) {
            tree.add(child);
            addDescendants(child.pid, tree);
        }
    }
    
    /**
     * Kill process and all its children.
     */
    public static int killTree(int pid) {
        int killed = 0;
        List<ProcessInfo> tree = getProcessTree(pid);
        
        // Kill children first (bottom-up)
        for (int i = tree.size() - 1; i >= 0; i--) {
            if (kill(tree.get(i).pid)) {
                killed++;
            }
        }
        
        return killed;
    }
    
    /**
     * Get processes listening on network ports.
     */
    @NonNull
    public static List<ProcessInfo> getNetworkProcesses() {
        List<ProcessInfo> netProcesses = new ArrayList<>();
        Map<Integer, Integer> portToPid = getListeningPorts();
        
        for (ProcessInfo process : listProcesses()) {
            if (portToPid.containsValue(process.pid)) {
                netProcesses.add(process);
            }
        }
        
        return netProcesses;
    }
    
    /**
     * Get listening ports and their PIDs.
     */
    @NonNull
    public static Map<Integer, Integer> getListeningPorts() {
        Map<Integer, Integer> portToPid = new HashMap<>();
        
        try {
            Process process = Runtime.getRuntime().exec(new String[]{
                    "netstat", "-tlnp"
            });
            
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
            String line;
            
            Pattern portPattern = Pattern.compile(":([0-9]+)\\s+");
            Pattern pidPattern = Pattern.compile("([0-9]+)/");
            
            while ((line = reader.readLine()) != null) {
                Matcher portMatcher = portPattern.matcher(line);
                Matcher pidMatcher = pidPattern.matcher(line);
                
                if (portMatcher.find() && pidMatcher.find()) {
                    try {
                        int port = Integer.parseInt(portMatcher.group(1));
                        int pid = Integer.parseInt(pidMatcher.group(1));
                        portToPid.put(port, pid);
                    } catch (NumberFormatException e) {
                        // Ignore parse errors
                    }
                }
            }
            
            process.waitFor();
        } catch (Exception e) {
            Log.w(TAG, "Failed to get listening ports", e);
        }
        
        return portToPid;
    }
    
    /**
     * Get process using specific port.
     */
    @Nullable
    public static ProcessInfo getProcessOnPort(int port) {
        Map<Integer, Integer> portToPid = getListeningPorts();
        Integer pid = portToPid.get(port);
        if (pid != null) {
            return findByPid(pid);
        }
        return null;
    }
    
    /**
     * Wait for process to exit.
     * 
     * @param pid process ID
     * @param timeoutMs timeout in milliseconds
     * @return true if process exited, false if timeout
     */
    public static boolean waitForExit(int pid, long timeoutMs) {
        long startTime = java.lang.System.currentTimeMillis();
        while (exists(pid)) {
            if (java.lang.System.currentTimeMillis() - startTime > timeoutMs) {
                return false;
            }
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                return false;
            }
        }
        return true;
    }
    
    /**
     * Get total system memory usage.
     */
    @NonNull
    public static MemoryStats getMemoryStats() {
        MemoryStats stats = new MemoryStats();
        
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"cat", "/proc/meminfo"});
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
            String line;
            
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split("\\s+");
                if (parts.length >= 2) {
                    long value = Long.parseLong(parts[1]);
                    switch (parts[0]) {
                        case "MemTotal:":
                            stats.totalKb = value;
                            break;
                        case "MemFree:":
                            stats.freeKb = value;
                            break;
                        case "MemAvailable:":
                            stats.availableKb = value;
                            break;
                        case "Buffers:":
                            stats.buffersKb = value;
                            break;
                        case "Cached:":
                            stats.cachedKb = value;
                            break;
                    }
                }
            }
            
            stats.usedKb = stats.totalKb - stats.freeKb - stats.buffersKb - stats.cachedKb;
            
            process.waitFor();
        } catch (Exception e) {
            Log.e(TAG, "Failed to get memory stats", e);
        }
        
        return stats;
    }
    
    /**
     * Memory statistics.
     */
    public static class MemoryStats {
        public long totalKb;
        public long freeKb;
        public long availableKb;
        public long usedKb;
        public long buffersKb;
        public long cachedKb;
        
        public float getUsedPercent() {
            return totalKb > 0 ? (usedKb * 100f / totalKb) : 0;
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("Memory{total=%dMB, used=%dMB (%.1f%%)}",
                    totalKb / 1024, usedKb / 1024, getUsedPercent());
        }
    }
    
    /**
     * Get current process ID.
     */
    public static int getCurrentPid() {
        return android.os.Process.myPid();
    }
    
    /**
     * Get current process UID.
     */
    public static int getCurrentUid() {
        return android.os.Process.myUid();
    }
    
    /**
     * Check if current process has root privileges.
     */
    public static boolean isRoot() {
        return getCurrentUid() == 0;
    }
}
