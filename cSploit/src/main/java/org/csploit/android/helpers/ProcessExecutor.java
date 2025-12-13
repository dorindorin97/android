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
import androidx.annotation.Nullable;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * ProcessExecutor - Safe and robust process execution utility.
 *
 * Provides:
 * - Safe command execution with proper stream handling
 * - Timeout support
 * - Output capture (stdout/stderr)
 * - Environment variable management
 * - Working directory control
 * - Proper resource cleanup
 *
 * Usage:
 * {@code
 * // Simple execution
 * ProcessResult result = ProcessExecutor.execute("ls", "-la");
 *
 * // With timeout
 * ProcessResult result = ProcessExecutor.builder("ping", "-c", "5", "google.com")
 *     .timeout(10, TimeUnit.SECONDS)
 *     .execute();
 *
 * // With environment variables
 * ProcessResult result = ProcessExecutor.builder("./script.sh")
 *     .env("MY_VAR", "value")
 *     .workingDir(new File("/tmp"))
 *     .execute();
 * }
 */
public final class ProcessExecutor {

    private static final String TAG = "ProcessExecutor";
    private static final int DEFAULT_TIMEOUT_SECONDS = 60;
    private static final int BUFFER_SIZE = 8192;

    private ProcessExecutor() {}

    /**
     * Result of process execution.
     */
    public static class ProcessResult {
        private final int exitCode;
        private final String stdout;
        private final String stderr;
        private final long executionTimeMs;
        private final boolean timedOut;
        private final Exception exception;

        private ProcessResult(int exitCode, String stdout, String stderr,
                long executionTimeMs, boolean timedOut, Exception exception) {
            this.exitCode = exitCode;
            this.stdout = stdout != null ? stdout : "";
            this.stderr = stderr != null ? stderr : "";
            this.executionTimeMs = executionTimeMs;
            this.timedOut = timedOut;
            this.exception = exception;
        }

        public int getExitCode() { return exitCode; }
        public String getStdout() { return stdout; }
        public String getStderr() { return stderr; }
        public long getExecutionTimeMs() { return executionTimeMs; }
        public boolean isTimedOut() { return timedOut; }
        public boolean isSuccess() { return exitCode == 0 && exception == null && !timedOut; }
        @Nullable public Exception getException() { return exception; }

        /**
         * Get combined output (stdout + stderr).
         */
        @NonNull
        public String getCombinedOutput() {
            StringBuilder sb = new StringBuilder();
            if (!stdout.isEmpty()) {
                sb.append(stdout);
            }
            if (!stderr.isEmpty()) {
                if (sb.length() > 0) sb.append("\n");
                sb.append(stderr);
            }
            return sb.toString();
        }

        /**
         * Get stdout lines as list.
         */
        @NonNull
        public List<String> getStdoutLines() {
            if (stdout.isEmpty()) return new ArrayList<>();
            return Arrays.asList(stdout.split("\n"));
        }

        /**
         * Get stderr lines as list.
         */
        @NonNull
        public List<String> getStderrLines() {
            if (stderr.isEmpty()) return new ArrayList<>();
            return Arrays.asList(stderr.split("\n"));
        }

        @NonNull
        @Override
        public String toString() {
            return String.format("ProcessResult{exitCode=%d, success=%b, timedOut=%b, time=%dms}",
                    exitCode, isSuccess(), timedOut, executionTimeMs);
        }

        // Builder methods for creating results
        static ProcessResult success(int exitCode, String stdout, String stderr, long timeMs) {
            return new ProcessResult(exitCode, stdout, stderr, timeMs, false, null);
        }

        static ProcessResult timeout(String stdout, String stderr, long timeMs) {
            return new ProcessResult(-1, stdout, stderr, timeMs, true, new TimeoutException());
        }

        static ProcessResult error(Exception e, long timeMs) {
            return new ProcessResult(-1, "", e.getMessage(), timeMs, false, e);
        }
    }

    /**
     * Process execution builder.
     */
    public static class Builder {
        private final List<String> command;
        private final Map<String, String> environment;
        private File workingDir;
        private long timeoutMs;
        private boolean redirectErrorStream;
        private String input;

        private Builder(@NonNull String... command) {
            this.command = new ArrayList<>(Arrays.asList(command));
            this.environment = new HashMap<>();
            this.timeoutMs = TimeUnit.SECONDS.toMillis(DEFAULT_TIMEOUT_SECONDS);
            this.redirectErrorStream = false;
        }

        /**
         * Add command argument.
         */
        @NonNull
        public Builder arg(@NonNull String arg) {
            command.add(arg);
            return this;
        }

        /**
         * Add multiple command arguments.
         */
        @NonNull
        public Builder args(@NonNull String... args) {
            command.addAll(Arrays.asList(args));
            return this;
        }

        /**
         * Set environment variable.
         */
        @NonNull
        public Builder env(@NonNull String key, @NonNull String value) {
            environment.put(key, value);
            return this;
        }

        /**
         * Set multiple environment variables.
         */
        @NonNull
        public Builder env(@NonNull Map<String, String> env) {
            environment.putAll(env);
            return this;
        }

        /**
         * Set working directory.
         */
        @NonNull
        public Builder workingDir(@Nullable File dir) {
            this.workingDir = dir;
            return this;
        }

        /**
         * Set working directory from path.
         */
        @NonNull
        public Builder workingDir(@NonNull String path) {
            this.workingDir = new File(path);
            return this;
        }

        /**
         * Set execution timeout.
         */
        @NonNull
        public Builder timeout(long timeout, @NonNull TimeUnit unit) {
            this.timeoutMs = unit.toMillis(timeout);
            return this;
        }

        /**
         * Set timeout in milliseconds.
         */
        @NonNull
        public Builder timeoutMs(long timeoutMs) {
            this.timeoutMs = timeoutMs;
            return this;
        }

        /**
         * Redirect stderr to stdout.
         */
        @NonNull
        public Builder redirectErrorStream(boolean redirect) {
            this.redirectErrorStream = redirect;
            return this;
        }

        /**
         * Set stdin input.
         */
        @NonNull
        public Builder input(@Nullable String input) {
            this.input = input;
            return this;
        }

        /**
         * Execute the command.
         */
        @NonNull
        public ProcessResult execute() {
            return ProcessExecutor.executeInternal(this);
        }
    }

    /**
     * Create a new process builder.
     */
    @NonNull
    public static Builder builder(@NonNull String... command) {
        return new Builder(command);
    }

    /**
     * Execute a command with default settings.
     */
    @NonNull
    public static ProcessResult execute(@NonNull String... command) {
        return builder(command).execute();
    }

    /**
     * Execute a command with timeout.
     */
    @NonNull
    public static ProcessResult execute(@NonNull String[] command, long timeoutMs) {
        return builder(command).timeoutMs(timeoutMs).execute();
    }

    /**
     * Execute a command string (splits by spaces).
     */
    @NonNull
    public static ProcessResult executeCommand(@NonNull String command) {
        return execute(command.split("\\s+"));
    }

    /**
     * Internal execution logic.
     */
    private static ProcessResult executeInternal(@NonNull Builder builder) {
        long startTime = java.lang.System.currentTimeMillis();
        Process process = null;
        StringBuilder stdout = new StringBuilder();
        StringBuilder stderr = new StringBuilder();

        try {
            ProcessBuilder pb = new ProcessBuilder(builder.command);

            // Set environment
            if (!builder.environment.isEmpty()) {
                pb.environment().putAll(builder.environment);
            }

            // Set working directory
            if (builder.workingDir != null) {
                pb.directory(builder.workingDir);
            }

            // Redirect error stream
            pb.redirectErrorStream(builder.redirectErrorStream);

            // Start process
            process = pb.start();

            // Write input if provided
            if (builder.input != null) {
                try (OutputStream os = process.getOutputStream()) {
                    os.write(builder.input.getBytes());
                    os.flush();
                }
            }

            // Create threads to read stdout and stderr
            final Process p = process;
            Thread stdoutThread = new Thread(() -> readStream(p.getInputStream(), stdout));
            Thread stderrThread = new Thread(() -> readStream(p.getErrorStream(), stderr));

            stdoutThread.start();
            if (!builder.redirectErrorStream) {
                stderrThread.start();
            }

            // Wait for process with timeout
            boolean completed = process.waitFor(builder.timeoutMs, TimeUnit.MILLISECONDS);

            if (!completed) {
                // Timeout - destroy the process
                process.destroyForcibly();
                stdoutThread.join(1000);
                if (!builder.redirectErrorStream) {
                    stderrThread.join(1000);
                }
                return ProcessResult.timeout(
                        stdout.toString(), stderr.toString(),
                        java.lang.System.currentTimeMillis() - startTime);
            }

            // Wait for output threads to complete
            stdoutThread.join(5000);
            if (!builder.redirectErrorStream) {
                stderrThread.join(5000);
            }

            return ProcessResult.success(
                    process.exitValue(),
                    stdout.toString(),
                    stderr.toString(),
                    java.lang.System.currentTimeMillis() - startTime);

        } catch (Exception e) {
            LoggingHelper.e(TAG, "Process execution failed", e);
            return ProcessResult.error(e, java.lang.System.currentTimeMillis() - startTime);
        } finally {
            if (process != null) {
                try {
                    process.destroyForcibly();
                } catch (Exception e) {
                    LoggingHelper.d(TAG, "Error destroying process: " + e.getMessage());
                }
            }
        }
    }

    /**
     * Read an input stream into a StringBuilder.
     */
    private static void readStream(@NonNull InputStream is, @NonNull StringBuilder output) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(is), BUFFER_SIZE)) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (output.length() > 0) {
                    output.append("\n");
                }
                output.append(line);
            }
        } catch (IOException e) {
            LoggingHelper.d(TAG, "Error reading stream: " + e.getMessage());
        }
    }

    /**
     * Check if a command exists in PATH.
     */
    public static boolean commandExists(@NonNull String command) {
        ProcessResult result = execute("which", command);
        return result.isSuccess() && !result.getStdout().isEmpty();
    }

    /**
     * Get the path of a command.
     */
    @Nullable
    public static String getCommandPath(@NonNull String command) {
        ProcessResult result = execute("which", command);
        if (result.isSuccess()) {
            return result.getStdout().trim();
        }
        return null;
    }

    /**
     * Execute command as root (requires su).
     */
    @NonNull
    public static ProcessResult executeAsRoot(@NonNull String... command) {
        List<String> fullCommand = new ArrayList<>();
        fullCommand.add("su");
        fullCommand.add("-c");
        fullCommand.add(String.join(" ", command));
        return builder(fullCommand.toArray(new String[0])).execute();
    }

    /**
     * Execute command and return just the output.
     */
    @NonNull
    public static String getOutput(@NonNull String... command) {
        return execute(command).getStdout();
    }

    /**
     * Execute command and return exit code.
     */
    public static int getExitCode(@NonNull String... command) {
        return execute(command).getExitCode();
    }
}
