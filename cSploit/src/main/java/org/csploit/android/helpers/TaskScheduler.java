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

import java.util.Comparator;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * Advanced task scheduler with prioritization, rate limiting, and monitoring.
 *
 * Features:
 * - Priority-based task execution
 * - Rate limiting per category
 * - Task batching
 * - Progress tracking
 * - Cancellation support
 * - Statistics and monitoring
 */
public final class TaskScheduler {

    private static final String TAG = "TaskScheduler";

    /**
     * Task priority levels
     */
    public enum Priority {
        LOW(0),
        NORMAL(5),
        HIGH(10),
        CRITICAL(15);

        private final int value;
        Priority(int value) { this.value = value; }
        public int getValue() { return value; }
    }

    /**
     * Task state
     */
    public enum TaskState {
        PENDING,
        RUNNING,
        COMPLETED,
        FAILED,
        CANCELLED
    }

    /**
     * Task wrapper with metadata
     */
    public static class Task implements Comparable<Task> {
        private final String id;
        private final String category;
        private final Priority priority;
        private final Runnable action;
        private final long createdAt;
        private volatile TaskState state = TaskState.PENDING;
        private volatile long startedAt;
        private volatile long completedAt;
        private volatile Throwable error;
        private volatile boolean cancelled;

        public Task(@NonNull String id, @NonNull String category, @NonNull Priority priority,
                   @NonNull Runnable action) {
            this.id = id;
            this.category = category;
            this.priority = priority;
            this.action = action;
            this.createdAt = System.currentTimeMillis();
        }

        @Override
        public int compareTo(Task other) {
            // Higher priority first, then earlier creation time
            int priorityCompare = Integer.compare(other.priority.getValue(), this.priority.getValue());
            if (priorityCompare != 0) return priorityCompare;
            return Long.compare(this.createdAt, other.createdAt);
        }

        public String getId() { return id; }
        public String getCategory() { return category; }
        public Priority getPriority() { return priority; }
        public TaskState getState() { return state; }
        public long getCreatedAt() { return createdAt; }
        public long getStartedAt() { return startedAt; }
        public long getCompletedAt() { return completedAt; }
        public Throwable getError() { return error; }
        public boolean isCancelled() { return cancelled; }

        public void cancel() {
            cancelled = true;
            state = TaskState.CANCELLED;
        }

        public long getDuration() {
            if (startedAt == 0) return 0;
            if (completedAt == 0) return System.currentTimeMillis() - startedAt;
            return completedAt - startedAt;
        }

        public long getWaitTime() {
            if (startedAt == 0) return System.currentTimeMillis() - createdAt;
            return startedAt - createdAt;
        }
    }

    /**
     * Rate limiter for controlling task execution rate
     */
    public static class RateLimiter {
        private final int maxTasks;
        private final long periodMs;
        private final BlockingQueue<Long> timestamps;

        public RateLimiter(int maxTasks, long periodMs) {
            this.maxTasks = maxTasks;
            this.periodMs = periodMs;
            this.timestamps = new java.util.concurrent.LinkedBlockingQueue<>(maxTasks);
        }

        /**
         * Try to acquire a permit (non-blocking).
         */
        public boolean tryAcquire() {
            long now = System.currentTimeMillis();
            long cutoff = now - periodMs;

            // Remove expired timestamps
            while (!timestamps.isEmpty() && timestamps.peek() < cutoff) {
                timestamps.poll();
            }

            if (timestamps.size() < maxTasks) {
                return timestamps.offer(now);
            }
            return false;
        }

        /**
         * Acquire a permit (blocking).
         */
        public void acquire() throws InterruptedException {
            while (!tryAcquire()) {
                long oldest = timestamps.peek();
                if (oldest != null) {
                    long waitTime = oldest + periodMs - System.currentTimeMillis();
                    if (waitTime > 0) {
                        Thread.sleep(Math.min(waitTime, 100));
                    }
                } else {
                    Thread.sleep(10);
                }
            }
        }

        /**
         * Get current rate (tasks per period).
         */
        public int getCurrentRate() {
            long now = System.currentTimeMillis();
            long cutoff = now - periodMs;
            int count = 0;
            for (Long ts : timestamps) {
                if (ts >= cutoff) count++;
            }
            return count;
        }
    }

    // Singleton instance
    private static volatile TaskScheduler instance;

    // Executor services
    private final ExecutorService executor;
    private final ScheduledExecutorService scheduler;
    private final PriorityBlockingQueue<Task> taskQueue;
    private final AtomicBoolean running = new AtomicBoolean(true);

    // Task tracking
    private final Map<String, Task> activeTasks = new ConcurrentHashMap<>();
    private final Map<String, RateLimiter> rateLimiters = new ConcurrentHashMap<>();

    // Statistics
    private final AtomicLong totalSubmitted = new AtomicLong(0);
    private final AtomicLong totalCompleted = new AtomicLong(0);
    private final AtomicLong totalFailed = new AtomicLong(0);
    private final AtomicLong totalCancelled = new AtomicLong(0);
    private final AtomicInteger taskIdCounter = new AtomicInteger(0);

    // Listeners
    private Consumer<Task> taskCompletionListener;

    private TaskScheduler(int poolSize) {
        ThreadFactory threadFactory = new ThreadFactory() {
            private final AtomicInteger counter = new AtomicInteger(0);
            @Override
            public Thread newThread(Runnable r) {
                Thread t = new Thread(r, "TaskScheduler-Worker-" + counter.incrementAndGet());
                t.setDaemon(true);
                return t;
            }
        };

        this.executor = Executors.newFixedThreadPool(poolSize, threadFactory);
        this.scheduler = Executors.newScheduledThreadPool(2, r -> {
            Thread t = new Thread(r, "TaskScheduler-Scheduler");
            t.setDaemon(true);
            return t;
        });
        this.taskQueue = new PriorityBlockingQueue<>(100);

        // Start worker threads to process tasks
        for (int i = 0; i < poolSize; i++) {
            executor.submit(this::workerLoop);
        }

        LoggingHelper.i(TAG, "TaskScheduler initialized with pool size: " + poolSize);
    }

    /**
     * Get singleton instance.
     */
    @NonNull
    public static synchronized TaskScheduler getInstance() {
        if (instance == null) {
            int cores = Runtime.getRuntime().availableProcessors();
            instance = new TaskScheduler(Math.max(2, cores));
        }
        return instance;
    }

    /**
     * Initialize with custom pool size.
     */
    public static synchronized void initialize(int poolSize) {
        if (instance == null) {
            instance = new TaskScheduler(poolSize);
        }
    }

    private void workerLoop() {
        while (running.get()) {
            try {
                Task task = taskQueue.poll(100, TimeUnit.MILLISECONDS);
                if (task != null && !task.isCancelled()) {
                    executeTask(task);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private void executeTask(Task task) {
        // Check rate limiter
        RateLimiter limiter = rateLimiters.get(task.getCategory());
        if (limiter != null) {
            try {
                limiter.acquire();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }

        task.state = TaskState.RUNNING;
        task.startedAt = System.currentTimeMillis();

        try {
            task.action.run();
            task.state = TaskState.COMPLETED;
            totalCompleted.incrementAndGet();
        } catch (Exception e) {
            task.state = TaskState.FAILED;
            task.error = e;
            totalFailed.incrementAndGet();
            LoggingHelper.e(TAG, "Task failed: " + task.getId(), e);
        } finally {
            task.completedAt = System.currentTimeMillis();
            activeTasks.remove(task.getId());

            if (taskCompletionListener != null) {
                try {
                    taskCompletionListener.accept(task);
                } catch (Exception e) {
                    LoggingHelper.w(TAG, "Error in task completion listener", e);
                }
            }
        }
    }

    /**
     * Submit a task with priority.
     */
    @NonNull
    public Task submit(@NonNull String category, @NonNull Priority priority, @NonNull Runnable action) {
        String id = category + "-" + taskIdCounter.incrementAndGet();
        Task task = new Task(id, category, priority, action);

        activeTasks.put(id, task);
        taskQueue.offer(task);
        totalSubmitted.incrementAndGet();

        LoggingHelper.v(TAG, "Submitted task: " + id + " (priority=" + priority + ")");
        return task;
    }

    /**
     * Submit a task with normal priority.
     */
    @NonNull
    public Task submit(@NonNull String category, @NonNull Runnable action) {
        return submit(category, Priority.NORMAL, action);
    }

    /**
     * Schedule a task for delayed execution.
     */
    @NonNull
    public ScheduledFuture<?> schedule(@NonNull String category, @NonNull Runnable action,
                                       long delay, @NonNull TimeUnit unit) {
        return scheduler.schedule(() -> submit(category, action), delay, unit);
    }

    /**
     * Schedule a repeating task.
     */
    @NonNull
    public ScheduledFuture<?> scheduleAtFixedRate(@NonNull String category, @NonNull Runnable action,
                                                  long initialDelay, long period, @NonNull TimeUnit unit) {
        return scheduler.scheduleAtFixedRate(() -> submit(category, action), initialDelay, period, unit);
    }

    /**
     * Set rate limit for a category.
     */
    public void setRateLimit(@NonNull String category, int maxTasksPerSecond) {
        rateLimiters.put(category, new RateLimiter(maxTasksPerSecond, 1000));
        LoggingHelper.i(TAG, "Set rate limit for " + category + ": " + maxTasksPerSecond + "/sec");
    }

    /**
     * Remove rate limit for a category.
     */
    public void removeRateLimit(@NonNull String category) {
        rateLimiters.remove(category);
    }

    /**
     * Cancel a task by ID.
     */
    public boolean cancel(@NonNull String taskId) {
        Task task = activeTasks.get(taskId);
        if (task != null && task.getState() == TaskState.PENDING) {
            task.cancel();
            totalCancelled.incrementAndGet();
            activeTasks.remove(taskId);
            return true;
        }
        return false;
    }

    /**
     * Cancel all tasks in a category.
     */
    public int cancelCategory(@NonNull String category) {
        int cancelled = 0;
        for (Task task : activeTasks.values()) {
            if (task.getCategory().equals(category) && task.getState() == TaskState.PENDING) {
                task.cancel();
                totalCancelled.incrementAndGet();
                cancelled++;
            }
        }
        return cancelled;
    }

    /**
     * Get a task by ID.
     */
    @Nullable
    public Task getTask(@NonNull String taskId) {
        return activeTasks.get(taskId);
    }

    /**
     * Set task completion listener.
     */
    public void setTaskCompletionListener(@Nullable Consumer<Task> listener) {
        this.taskCompletionListener = listener;
    }

    /**
     * Get current queue size.
     */
    public int getQueueSize() {
        return taskQueue.size();
    }

    /**
     * Get active task count.
     */
    public int getActiveTaskCount() {
        return activeTasks.size();
    }

    /**
     * Get statistics.
     */
    @NonNull
    public String getStatistics() {
        return String.format(
                "TaskScheduler Stats: submitted=%d, completed=%d, failed=%d, cancelled=%d, queue=%d, active=%d",
                totalSubmitted.get(), totalCompleted.get(), totalFailed.get(),
                totalCancelled.get(), taskQueue.size(), activeTasks.size()
        );
    }

    /**
     * Shutdown the scheduler.
     */
    public void shutdown() {
        running.set(false);
        executor.shutdown();
        scheduler.shutdown();

        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
            if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            scheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }

        LoggingHelper.i(TAG, "TaskScheduler shutdown complete. " + getStatistics());
    }

    /**
     * Check if scheduler is running.
     */
    public boolean isRunning() {
        return running.get();
    }
}
