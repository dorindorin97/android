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

import android.os.Build;
import org.csploit.android.helpers.LoggingHelper;

import androidx.annotation.NonNull;
import org.csploit.android.helpers.LoggingHelper;
import androidx.annotation.Nullable;
import org.csploit.android.helpers.LoggingHelper;

import java.io.BufferedReader;
import org.csploit.android.helpers.LoggingHelper;
import java.io.IOException;
import org.csploit.android.helpers.LoggingHelper;
import java.io.InputStreamReader;
import org.csploit.android.helpers.LoggingHelper;
import java.io.OutputStream;
import org.csploit.android.helpers.LoggingHelper;
import java.util.ArrayList;
import org.csploit.android.helpers.LoggingHelper;
import java.util.List;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.TimeUnit;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.TimeoutException;
import org.csploit.android.helpers.LoggingHelper;

/**
 * ShellHelper - Execute shell commands with proper error handling.
 * 
 * Provides methods for running shell commands as both regular user and root,
 * with timeout support and output capture.
 * 
 * Usage:
 * {@code
 * ShellResult result = ShellHelper.exec("ls -la /data");
 * if (result.isSuccess()) {
 *     for (String line : result.getOutputLines()) {
 *         Log.d(TAG, line);
 *     }
 * }
 * }
 */
public final class ShellHelper {
    
    private static final String TAG = "ShellHelper";
    private static final long DEFAULT_TIMEOUT_MS = 30000; // 30 seconds
    
    private ShellHelper() {}
    
    /**
     * Result of shell command execution.
     */
    public static class ShellResult {
        private final int exitCode;
        private final String output;
        private final String error;
        private final boolean timedOut;
        
        public ShellResult(int exitCode, String output, String error, boolean timedOut) {
            this.exitCode = exitCode;
            this.output = output != null ? output : "";
            this.error = error != null ? error : "";
            this.timedOut = timedOut;
        }
        
        public int getExitCode() { return exitCode; }
        public String getOutput() { return output; }
        public String getError() { return error; }
        public boolean isSuccess() { return exitCode == 0 && !timedOut; }
        public boolean isTimedOut() { return timedOut; }
        
        @NonNull
        public List<String> getOutputLines() {
            List<String> lines = new ArrayList<>();
            if (output != null && !output.isEmpty()) {
                for (String line : output.split("\n")) {
                    if (!line.isEmpty()) {
                        lines.add(line);
                    }
                }
            }
            return lines;
        }
        
        @NonNull
        public List<String> getErrorLines() {
            List<String> lines = new ArrayList<>();
            if (error != null && !error.isEmpty()) {
                for (String line : error.split("\n")) {
                    if (!line.isEmpty()) {
                        lines.add(line);
                    }
                }
            }
            return lines;
        }
        
        @Override
        @NonNull
        public String toString() {
            return "ShellResult{exitCode=" + exitCode + ", timedOut=" + timedOut + 
                   ", output='" + output.substring(0, Math.min(output.length(), 100)) + "...'}";
        }
    }
    
    /**
     * Execute a shell command.
     * 
     * @param command Command to execute
     * @return Shell result
     */
    @NonNull
    public static ShellResult exec(@NonNull String command) {
        return exec(command, DEFAULT_TIMEOUT_MS);
    }
    
    /**
     * Execute a shell command with timeout.
     * 
     * @param command Command to execute
     * @param timeoutMs Timeout in milliseconds
     * @return Shell result
     */
    @NonNull
    public static ShellResult exec(@NonNull String command, long timeoutMs) {
        return execInternal(command, false, timeoutMs, null);
    }
    
    /**
     * Execute a shell command as root (su).
     * 
     * @param command Command to execute as root
     * @return Shell result
     */
    @NonNull
    public static ShellResult execRoot(@NonNull String command) {
        return execRoot(command, DEFAULT_TIMEOUT_MS);
    }
    
    /**
     * Execute a shell command as root with timeout.
     * 
     * @param command Command to execute as root
     * @param timeoutMs Timeout in milliseconds
     * @return Shell result
     */
    @NonNull
    public static ShellResult execRoot(@NonNull String command, long timeoutMs) {
        return execInternal(command, true, timeoutMs, null);
    }
    
    /**
     * Execute a shell command with input.
     * 
     * @param command Command to execute
     * @param input Input to write to stdin
     * @return Shell result
     */
    @NonNull
    public static ShellResult execWithInput(@NonNull String command, @NonNull String input) {
        return execInternal(command, false, DEFAULT_TIMEOUT_MS, input);
    }
    
    /**
     * Execute a shell command as root with input.
     * 
     * @param command Command to execute as root
     * @param input Input to write to stdin
     * @return Shell result
     */
    @NonNull
    public static ShellResult execRootWithInput(@NonNull String command, @NonNull String input) {
        return execInternal(command, true, DEFAULT_TIMEOUT_MS, input);
    }
    
    private static ShellResult execInternal(String command, boolean asRoot, 
                                             long timeoutMs, @Nullable String input) {
        Process process = null;
        StringBuilder outputBuilder = new StringBuilder();
        StringBuilder errorBuilder = new StringBuilder();
        boolean timedOut = false;
        int exitCode = -1;
        
        try {
            String[] shellCmd;
            if (asRoot) {
                shellCmd = new String[]{"su", "-c", command};
            } else {
                shellCmd = new String[]{"sh", "-c", command};
            }
            
            ProcessBuilder pb = new ProcessBuilder(shellCmd);
            pb.redirectErrorStream(false);
            process = pb.start();
            
            // Write input if provided
            if (input != null) {
                try (OutputStream os = process.getOutputStream()) {
                    os.write(input.getBytes());
                    os.flush();
                }
            }
            
            // Read output in separate threads to prevent deadlock
            Thread outputThread = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        outputBuilder.append(line).append("\n");
                    }
                } catch (IOException e) {
                    // Ignore
                }
            });
            
            Thread errorThread = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getErrorStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        errorBuilder.append(line).append("\n");
                    }
                } catch (IOException e) {
                    // Ignore
                }
            });
            
            outputThread.start();
            errorThread.start();
            
            // Wait for process with timeout
            boolean completed = process.waitFor(timeoutMs, TimeUnit.MILLISECONDS);
            
            if (!completed) {
                timedOut = true;
                process.destroyForcibly();
            }
            
            // Wait for reader threads
            outputThread.join(1000);
            errorThread.join(1000);
            
            exitCode = completed ? process.exitValue() : -1;
            
        } catch (IOException | InterruptedException e) {
            errorBuilder.append(e.getMessage());
            LoggingHelper.e(TAG, "Shell execution failed: " + command, e);
        } finally {
            if (process != null) {
                process.destroy();
            }
        }
        
        return new ShellResult(exitCode, outputBuilder.toString(), errorBuilder.toString(), timedOut);
    }
    
    /**
     * Check if root access is available.
     * 
     * @return true if root access is available
     */
    public static boolean isRootAvailable() {
        ShellResult result = execRoot("id", 5000);
        return result.isSuccess() && result.getOutput().contains("uid=0");
    }
    
    /**
     * Check if a command exists in PATH.
     * 
     * @param command Command name
     * @return true if command exists
     */
    public static boolean commandExists(@NonNull String command) {
        ShellResult result = exec("which " + InputSanitizer.sanitizeForShell(command), 5000);
        return result.isSuccess() && !result.getOutput().isEmpty();
    }
    
    /**
     * Get the path of a command.
     * 
     * @param command Command name
     * @return Full path or null if not found
     */
    @Nullable
    public static String getCommandPath(@NonNull String command) {
        ShellResult result = exec("which " + InputSanitizer.sanitizeForShell(command), 5000);
        if (result.isSuccess()) {
            String output = result.getOutput().trim();
            return output.isEmpty() ? null : output;
        }
        return null;
    }
    
    /**
     * Kill a process by name.
     * 
     * @param processName Process name
     * @return true if process was killed
     */
    public static boolean killProcess(@NonNull String processName) {
        String safeName = InputSanitizer.sanitizeForShell(processName);
        ShellResult result = execRoot("pkill -9 " + safeName, 5000);
        return result.getExitCode() == 0;
    }
    
    /**
     * Kill a process by PID.
     * 
     * @param pid Process ID
     * @return true if process was killed
     */
    public static boolean killProcess(int pid) {
        ShellResult result = execRoot("kill -9 " + pid, 5000);
        return result.getExitCode() == 0;
    }
    
    /**
     * Get process ID by name.
     * 
     * @param processName Process name
     * @return PID or -1 if not found
     */
    public static int getProcessId(@NonNull String processName) {
        String safeName = InputSanitizer.sanitizeForShell(processName);
        ShellResult result = exec("pidof " + safeName, 5000);
        if (result.isSuccess()) {
            try {
                return Integer.parseInt(result.getOutput().trim().split("\\s+")[0]);
            } catch (NumberFormatException e) {
                return -1;
            }
        }
        return -1;
    }
    
    /**
     * Check if a process is running.
     * 
     * @param processName Process name
     * @return true if process is running
     */
    public static boolean isProcessRunning(@NonNull String processName) {
        return getProcessId(processName) > 0;
    }
    
    /**
     * Read file contents using cat (can read system files with root).
     * 
     * @param filePath File path
     * @param asRoot Whether to use root access
     * @return File contents or null on error
     */
    @Nullable
    public static String readFile(@NonNull String filePath, boolean asRoot) {
        String safePath = InputSanitizer.sanitizeFilePath(filePath);
        ShellResult result = asRoot ? 
                execRoot("cat '" + safePath + "'") : 
                exec("cat '" + safePath + "'");
        return result.isSuccess() ? result.getOutput() : null;
    }
    
    /**
     * Write file contents using echo (can write system files with root).
     * 
     * @param filePath File path
     * @param content Content to write
     * @param asRoot Whether to use root access
     * @return true if successful
     */
    public static boolean writeFile(@NonNull String filePath, @NonNull String content, boolean asRoot) {
        String safePath = InputSanitizer.sanitizeFilePath(filePath);
        String safeContent = InputSanitizer.escapeForShell(content);
        String command = "echo '" + safeContent + "' > '" + safePath + "'";
        ShellResult result = asRoot ? execRoot(command) : exec(command);
        return result.isSuccess();
    }
    
    /**
     * Append to file using echo.
     * 
     * @param filePath File path
     * @param content Content to append
     * @param asRoot Whether to use root access
     * @return true if successful
     */
    public static boolean appendFile(@NonNull String filePath, @NonNull String content, boolean asRoot) {
        String safePath = InputSanitizer.sanitizeFilePath(filePath);
        String safeContent = InputSanitizer.escapeForShell(content);
        String command = "echo '" + safeContent + "' >> '" + safePath + "'";
        ShellResult result = asRoot ? execRoot(command) : exec(command);
        return result.isSuccess();
    }
    
    /**
     * Change file permissions.
     * 
     * @param filePath File path
     * @param mode Permission mode (e.g., "755")
     * @param asRoot Whether to use root access
     * @return true if successful
     */
    public static boolean chmod(@NonNull String filePath, @NonNull String mode, boolean asRoot) {
        String safePath = InputSanitizer.sanitizeFilePath(filePath);
        String safeMode = InputSanitizer.sanitizeForShell(mode);
        String command = "chmod " + safeMode + " '" + safePath + "'";
        ShellResult result = asRoot ? execRoot(command) : exec(command);
        return result.isSuccess();
    }
    
    /**
     * Change file ownership.
     * 
     * @param filePath File path
     * @param owner Owner (e.g., "root:root")
     * @return true if successful
     */
    public static boolean chown(@NonNull String filePath, @NonNull String owner) {
        String safePath = InputSanitizer.sanitizeFilePath(filePath);
        String safeOwner = InputSanitizer.sanitizeForShell(owner);
        ShellResult result = execRoot("chown " + safeOwner + " '" + safePath + "'");
        return result.isSuccess();
    }
    
    /**
     * Mount a filesystem.
     * 
     * @param options Mount options (e.g., "-o remount,rw")
     * @param path Mount path
     * @return true if successful
     */
    public static boolean mount(@NonNull String options, @NonNull String path) {
        String safeOptions = InputSanitizer.sanitizeForShell(options);
        String safePath = InputSanitizer.sanitizeFilePath(path);
        ShellResult result = execRoot("mount " + safeOptions + " '" + safePath + "'");
        return result.isSuccess();
    }
    
    /**
     * Remount /system as read-write.
     * 
     * @return true if successful
     */
    public static boolean remountSystemRW() {
        return mount("-o remount,rw", "/system");
    }
    
    /**
     * Remount /system as read-only.
     * 
     * @return true if successful
     */
    public static boolean remountSystemRO() {
        return mount("-o remount,ro", "/system");
    }
}
