package org.csploit.android.core;

import android.util.Log;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Manages execution of external tools and commands.
 * Extracted from System.java to improve separation of concerns.
 * Provides safe, thread-safe execution of tools with timeout support and resource cleanup.
 */
public class ToolExecutor {
    private static final String TAG = "ToolExecutor";
    private static final long DEFAULT_TIMEOUT_SECONDS = 300; // 5 minutes

    private final ExecutorService executorService;
    private final List<Process> activeProcesses;

    /**
     * Initialize tool executor with thread pool.
     *
     * @param threadPoolSize Number of threads for parallel tool execution
     */
    public ToolExecutor(int threadPoolSize) {
        this.executorService = Executors.newFixedThreadPool(threadPoolSize);
        this.activeProcesses = new ArrayList<>();
    }

    /**
     * Execute a command synchronously.
     *
     * @param command The command to execute
     * @return ProcessResult containing output and exit code
     * @throws IOException if process fails to start
     */
    @NonNull
    public ProcessResult execute(@NonNull String command) throws IOException {
        return execute(command, DEFAULT_TIMEOUT_SECONDS);
    }

    /**
     * Execute a command with timeout.
     *
     * @param command The command to execute
     * @param timeoutSeconds Timeout in seconds
     * @return ProcessResult containing output and exit code
     * @throws IOException if process fails to start
     */
    @NonNull
    public ProcessResult execute(@NonNull String command, long timeoutSeconds) throws IOException {
        if (command == null || command.isEmpty()) {
            throw new IllegalArgumentException("Command cannot be null or empty");
        }

        try {
            Process process = Runtime.getRuntime().exec(command);
            synchronized (activeProcesses) {
                activeProcesses.add(process);
            }

            Log.d(TAG, "Executing command: " + command);

            boolean completed;
            try {
                completed = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                process.destroyForcibly();
                return new ProcessResult(-1, "Process interrupted");
            }

            if (!completed) {
                process.destroyForcibly();
                Log.w(TAG, "Process timeout: " + command);
                return new ProcessResult(-1, "Process timeout after " + timeoutSeconds + " seconds");
            }

            int exitCode = process.exitValue();
            String output = readProcessOutput(process);

            Log.d(TAG, "Command completed with exit code: " + exitCode);

            return new ProcessResult(exitCode, output);
        } finally {
            synchronized (activeProcesses) {
                activeProcesses.removeIf(p -> !p.isAlive());
            }
        }
    }

    /**
     * Execute a command asynchronously.
     *
     * @param command The command to execute
     * @param callback Callback to invoke when execution completes
     */
    public void executeAsync(@NonNull String command, @NonNull ExecutionCallback callback) {
        executeAsync(command, DEFAULT_TIMEOUT_SECONDS, callback);
    }

    /**
     * Execute a command asynchronously with timeout.
     *
     * @param command The command to execute
     * @param timeoutSeconds Timeout in seconds
     * @param callback Callback to invoke when execution completes
     */
    public void executeAsync(@NonNull String command, long timeoutSeconds, @NonNull ExecutionCallback callback) {
        executorService.submit(() -> {
            try {
                ProcessResult result = execute(command, timeoutSeconds);
                callback.onSuccess(result);
            } catch (Exception e) {
                Log.e(TAG, "Async execution failed: " + command, e);
                callback.onFailure(e);
            }
        });
    }

    /**
     * Kill a specific process.
     *
     * @param process The process to kill
     */
    public void killProcess(@NonNull Process process) {
        if (process == null) {
            return;
        }

        try {
            process.destroy();
            if (!process.waitFor(5, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                Log.w(TAG, "Process required forcible termination");
            }
        } catch (InterruptedException e) {
            process.destroyForcibly();
            Thread.currentThread().interrupt();
        } finally {
            synchronized (activeProcesses) {
                activeProcesses.remove(process);
            }
        }
    }

    /**
     * Kill all active processes.
     */
    public void killAllProcesses() {
        synchronized (activeProcesses) {
            for (Process process : activeProcesses) {
                if (process.isAlive()) {
                    process.destroyForcibly();
                }
            }
            activeProcesses.clear();
        }
    }

    /**
     * Get number of active processes.
     *
     * @return Count of currently running processes
     */
    public int getActiveProcessCount() {
        synchronized (activeProcesses) {
            return (int) activeProcesses.stream()
                    .filter(Process::isAlive)
                    .count();
        }
    }

    /**
     * Shutdown the executor service.
     */
    public void shutdown() {
        killAllProcesses();
        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(30, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
                Log.w(TAG, "Executor service shutdown timeout");
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Read output from a process.
     *
     * @param process The process to read from
     * @return Combined stdout and stderr output
     */
    @NonNull
    private String readProcessOutput(@NonNull Process process) {
        StringBuilder output = new StringBuilder();

        try (java.io.BufferedReader reader = new java.io.BufferedReader(
                new java.io.InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
        } catch (IOException e) {
            Log.e(TAG, "Error reading process output", e);
        }

        return output.toString();
    }

    /**
     * Result of a process execution.
     */
    public static class ProcessResult {
        private final int exitCode;
        private final String output;

        public ProcessResult(int exitCode, String output) {
            this.exitCode = exitCode;
            this.output = output;
        }

        public int getExitCode() {
            return exitCode;
        }

        public String getOutput() {
            return output;
        }

        public boolean isSuccess() {
            return exitCode == 0;
        }

        @NonNull
        @Override
        public String toString() {
            return String.format("ProcessResult [exit: %d, output: %d chars]", exitCode, output.length());
        }
    }

    /**
     * Callback for asynchronous execution.
     */
    public interface ExecutionCallback {
        void onSuccess(ProcessResult result);
        void onFailure(Exception e);
    }
}
