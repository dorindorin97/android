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

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.Closeable;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Helper class for managing and cleaning up resources.
 *
 * Provides:
 * - Automatic resource tracking and cleanup
 * - ExecutorService lifecycle management
 * - Cleanup callbacks with proper ordering
 * - Thread-safe resource management
 *
 * Usage:
 * {@code
 * ResourceCleanupHelper cleanup = new ResourceCleanupHelper();
 * try {
 *     Socket socket = new Socket(host, port);
 *     cleanup.register(socket);
 *     // Use socket...
 * } finally {
 *     cleanup.cleanupAll();
 * }
 * }
 */
public class ResourceCleanupHelper {

    private static final String TAG = "ResourceCleanupHelper";
    private static final long DEFAULT_EXECUTOR_SHUTDOWN_TIMEOUT_MS = 5000;

    private final List<Closeable> closeables = new ArrayList<>();
    private final List<ExecutorService> executors = new ArrayList<>();
    private final List<Runnable> cleanupCallbacks = new ArrayList<>();
    private final Object lock = new Object();
    private boolean cleanedUp = false;

    /**
     * Register a Closeable resource for cleanup.
     *
     * @param closeable Resource to track
     * @param <T> Resource type
     * @return The same resource for chaining
     */
    @NonNull
    public <T extends Closeable> T register(@NonNull T closeable) {
        synchronized (lock) {
            if (cleanedUp) {
                CloseableHelper.closeQuietly(closeable);
                throw new IllegalStateException("Cannot register after cleanup");
            }
            closeables.add(closeable);
        }
        return closeable;
    }

    /**
     * Register an ExecutorService for cleanup.
     *
     * @param executor Executor to track
     * @param <T> Executor type
     * @return The same executor for chaining
     */
    @NonNull
    public <T extends ExecutorService> T register(@NonNull T executor) {
        synchronized (lock) {
            if (cleanedUp) {
                executor.shutdownNow();
                throw new IllegalStateException("Cannot register after cleanup");
            }
            executors.add(executor);
        }
        return executor;
    }

    /**
     * Register a cleanup callback to run during cleanup.
     *
     * @param callback Cleanup action
     */
    public void onCleanup(@NonNull Runnable callback) {
        synchronized (lock) {
            if (cleanedUp) {
                throw new IllegalStateException("Cannot register after cleanup");
            }
            cleanupCallbacks.add(callback);
        }
    }

    /**
     * Clean up all registered resources.
     * Resources are cleaned up in reverse order of registration.
     */
    public void cleanupAll() {
        synchronized (lock) {
            if (cleanedUp) {
                return;
            }
            cleanedUp = true;
        }

        // Run callbacks first (in reverse order)
        for (int i = cleanupCallbacks.size() - 1; i >= 0; i--) {
            try {
                cleanupCallbacks.get(i).run();
            } catch (Exception e) {
                LoggingHelper.w(TAG, "Cleanup callback failed: " + e.getMessage());
            }
        }

        // Shutdown executors
        for (int i = executors.size() - 1; i >= 0; i--) {
            shutdownExecutor(executors.get(i));
        }

        // Close closeables
        for (int i = closeables.size() - 1; i >= 0; i--) {
            CloseableHelper.closeQuietly(closeables.get(i));
        }

        cleanupCallbacks.clear();
        executors.clear();
        closeables.clear();
    }

    /**
     * Shutdown an executor gracefully.
     *
     * @param executor Executor to shutdown
     */
    private void shutdownExecutor(ExecutorService executor) {
        if (executor == null || executor.isShutdown()) {
            return;
        }

        executor.shutdown();
        try {
            if (!executor.awaitTermination(DEFAULT_EXECUTOR_SHUTDOWN_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                executor.shutdownNow();
                if (!executor.awaitTermination(1, TimeUnit.SECONDS)) {
                    LoggingHelper.w(TAG, "ExecutorService did not terminate");
                }
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Check if cleanup has been performed.
     *
     * @return true if cleaned up
     */
    public boolean isCleanedUp() {
        synchronized (lock) {
            return cleanedUp;
        }
    }

    /**
     * Get count of registered resources.
     *
     * @return Total resource count
     */
    public int getResourceCount() {
        synchronized (lock) {
            return closeables.size() + executors.size() + cleanupCallbacks.size();
        }
    }

    /**
     * Create a scope that automatically cleans up on completion.
     *
     * @param action Action to run with cleanup
     */
    public static void withCleanup(@NonNull CleanupAction action) {
        ResourceCleanupHelper helper = new ResourceCleanupHelper();
        try {
            action.execute(helper);
        } finally {
            helper.cleanupAll();
        }
    }

    /**
     * Functional interface for cleanup scope.
     */
    public interface CleanupAction {
        void execute(@NonNull ResourceCleanupHelper helper) throws Exception;
    }

    /**
     * Builder for creating resource scopes with pre-registered resources.
     */
    public static class Builder {
        private final ResourceCleanupHelper helper = new ResourceCleanupHelper();

        public Builder add(@NonNull Closeable closeable) {
            helper.register(closeable);
            return this;
        }

        public Builder add(@NonNull ExecutorService executor) {
            helper.register(executor);
            return this;
        }

        public Builder onCleanup(@NonNull Runnable callback) {
            helper.onCleanup(callback);
            return this;
        }

        public ResourceCleanupHelper build() {
            return helper;
        }
    }

    /**
     * Create a new builder.
     *
     * @return Builder instance
     */
    public static Builder builder() {
        return new Builder();
    }
}
