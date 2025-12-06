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

import org.csploit.android.core.ChildManager;
import org.csploit.android.core.System;
import org.csploit.android.net.Network;
import org.csploit.android.net.Target;
import org.csploit.android.tools.NMap;
import org.csploit.android.tools.Child;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * BatchScannerHelper - Enables batch port scanning across multiple targets.
 *
 * Features:
 * - Scan multiple targets in parallel
 * - Progress tracking with callbacks
 * - Configurable scan options
 * - Results aggregation
 * - Scan cancellation support
 *
 * Usage:
 * {@code
 * BatchScannerHelper scanner = new BatchScannerHelper();
 * scanner.setProgressListener(progress -> updateUI(progress));
 * BatchScanResult result = scanner.scanTargets(targets, "1-1000");
 * }
 */
public final class BatchScannerHelper {
    private static final String TAG = "BatchScannerHelper";
    private static final int DEFAULT_THREAD_POOL_SIZE = 4;
    private static final int DEFAULT_TIMEOUT_SECONDS = 300;

    private ExecutorService mExecutor;
    private volatile boolean mCancelled = false;
    private BatchProgressListener mProgressListener;
    private int mThreadPoolSize = DEFAULT_THREAD_POOL_SIZE;
    private int mTimeoutSeconds = DEFAULT_TIMEOUT_SECONDS;
    private final List<Child> mActiveScans = new CopyOnWriteArrayList<>();

    /**
     * Progress listener interface
     */
    public interface BatchProgressListener {
        void onProgress(BatchProgress progress);
        void onTargetComplete(Target target, int portsFound);
        void onScanComplete(BatchScanResult result);
        void onError(Target target, String error);
    }

    /**
     * Scan progress information
     */
    public static class BatchProgress {
        public final int totalTargets;
        public final int completedTargets;
        public final int failedTargets;
        public final int totalPortsFound;
        public final float progressPercent;
        public final String currentTarget;
        public final long elapsedTimeMs;

        BatchProgress(int total, int completed, int failed, int ports,
                     String current, long elapsed) {
            this.totalTargets = total;
            this.completedTargets = completed;
            this.failedTargets = failed;
            this.totalPortsFound = ports;
            this.progressPercent = total > 0 ? (completed * 100f / total) : 0;
            this.currentTarget = current;
            this.elapsedTimeMs = elapsed;
        }

        public String getFormattedProgress() {
            return String.format("%.1f%% (%d/%d targets)",
                progressPercent, completedTargets, totalTargets);
        }
    }

    /**
     * Scan result
     */
    public static class BatchScanResult {
        public final int targetsScanned;
        public final int targetsSuccessful;
        public final int targetsFailed;
        public final int totalPortsFound;
        public final long durationMs;
        public final boolean wasCancelled;
        public final List<TargetScanResult> results;

        BatchScanResult(int scanned, int successful, int failed, int ports,
                       long duration, boolean cancelled, List<TargetScanResult> results) {
            this.targetsScanned = scanned;
            this.targetsSuccessful = successful;
            this.targetsFailed = failed;
            this.totalPortsFound = ports;
            this.durationMs = duration;
            this.wasCancelled = cancelled;
            this.results = results;
        }

        @Override
        public String toString() {
            return String.format(
                "BatchScanResult{scanned=%d, successful=%d, failed=%d, ports=%d, duration=%dms, cancelled=%b}",
                targetsScanned, targetsSuccessful, targetsFailed, totalPortsFound, durationMs, wasCancelled
            );
        }

        public String getSummary() {
            StringBuilder sb = new StringBuilder();
            sb.append("Batch Scan Complete\n");
            sb.append("-------------------\n");
            sb.append("Targets Scanned: ").append(targetsScanned).append("\n");
            sb.append("Successful: ").append(targetsSuccessful).append("\n");
            sb.append("Failed: ").append(targetsFailed).append("\n");
            sb.append("Total Ports Found: ").append(totalPortsFound).append("\n");
            sb.append("Duration: ").append(formatDuration(durationMs)).append("\n");
            if (wasCancelled) {
                sb.append("(Scan was cancelled)\n");
            }
            return sb.toString();
        }

        private String formatDuration(long ms) {
            if (ms < 1000) return ms + "ms";
            if (ms < 60000) return String.format("%.1fs", ms / 1000.0);
            long min = ms / 60000;
            long sec = (ms % 60000) / 1000;
            return String.format("%dm %ds", min, sec);
        }
    }

    /**
     * Individual target scan result
     */
    public static class TargetScanResult {
        public final Target target;
        public final int portsFound;
        public final boolean successful;
        public final String errorMessage;
        public final long durationMs;

        TargetScanResult(Target target, int ports, boolean success, String error, long duration) {
            this.target = target;
            this.portsFound = ports;
            this.successful = success;
            this.errorMessage = error;
            this.durationMs = duration;
        }
    }

    /**
     * Set progress listener
     */
    public void setProgressListener(@Nullable BatchProgressListener listener) {
        mProgressListener = listener;
    }

    /**
     * Set thread pool size for parallel scanning
     */
    public void setThreadPoolSize(int size) {
        if (size > 0 && size <= 16) {
            mThreadPoolSize = size;
        }
    }

    /**
     * Set scan timeout in seconds
     */
    public void setTimeoutSeconds(int timeout) {
        if (timeout > 0) {
            mTimeoutSeconds = timeout;
        }
    }

    /**
     * Scan all selected targets
     */
    @NonNull
    public BatchScanResult scanSelectedTargets(@Nullable String portRange) {
        List<Target> selected = new ArrayList<>();
        for (Target t : System.getTargets()) {
            if (t.isSelected() && t.getType() != Target.Type.NETWORK) {
                selected.add(t);
            }
        }
        return scanTargets(selected, portRange);
    }

    /**
     * Scan all endpoint targets
     */
    @NonNull
    public BatchScanResult scanAllEndpoints(@Nullable String portRange) {
        List<Target> endpoints = new ArrayList<>();
        for (Target t : System.getTargets()) {
            if (t.getType() == Target.Type.ENDPOINT) {
                endpoints.add(t);
            }
        }
        return scanTargets(endpoints, portRange);
    }

    /**
     * Scan specific targets
     */
    @NonNull
    public BatchScanResult scanTargets(@NonNull List<Target> targets, @Nullable String portRange) {
        if (targets.isEmpty()) {
            return new BatchScanResult(0, 0, 0, 0, 0, false, new ArrayList<>());
        }

        mCancelled = false;
        mActiveScans.clear();
        mExecutor = Executors.newFixedThreadPool(mThreadPoolSize);

        final long startTime = java.lang.System.currentTimeMillis();
        final AtomicInteger completed = new AtomicInteger(0);
        final AtomicInteger failed = new AtomicInteger(0);
        final AtomicInteger totalPorts = new AtomicInteger(0);
        final List<TargetScanResult> results = new CopyOnWriteArrayList<>();
        final CountDownLatch latch = new CountDownLatch(targets.size());

        for (final Target target : targets) {
            if (mCancelled) break;

            mExecutor.submit(() -> {
                if (mCancelled) {
                    latch.countDown();
                    return;
                }

                long targetStart = java.lang.System.currentTimeMillis();
                int portsFound = 0;
                boolean success = false;
                String error = null;

                try {
                    portsFound = scanSingleTarget(target, portRange);
                    success = true;
                    totalPorts.addAndGet(portsFound);
                    completed.incrementAndGet();

                    if (mProgressListener != null) {
                        mProgressListener.onTargetComplete(target, portsFound);
                    }
                } catch (Exception e) {
                    failed.incrementAndGet();
                    error = e.getMessage();
                    LoggingHelper.e(TAG, "Scan failed for " + target.getDisplayAddress(), e);

                    if (mProgressListener != null) {
                        mProgressListener.onError(target, error);
                    }
                }

                long targetDuration = java.lang.System.currentTimeMillis() - targetStart;
                results.add(new TargetScanResult(target, portsFound, success, error, targetDuration));

                // Update progress
                if (mProgressListener != null) {
                    long elapsed = java.lang.System.currentTimeMillis() - startTime;
                    BatchProgress progress = new BatchProgress(
                        targets.size(),
                        completed.get(),
                        failed.get(),
                        totalPorts.get(),
                        target.getDisplayAddress(),
                        elapsed
                    );
                    mProgressListener.onProgress(progress);
                }

                latch.countDown();
            });
        }

        // Wait for completion or timeout
        try {
            boolean finished = latch.await(mTimeoutSeconds, TimeUnit.SECONDS);
            if (!finished) {
                LoggingHelper.w(TAG, "Batch scan timed out after " + mTimeoutSeconds + " seconds");
            }
        } catch (InterruptedException e) {
            LoggingHelper.w(TAG, "Batch scan interrupted");
        }

        mExecutor.shutdown();
        cancelActiveScans();

        long duration = java.lang.System.currentTimeMillis() - startTime;
        BatchScanResult result = new BatchScanResult(
            targets.size(),
            completed.get(),
            failed.get(),
            totalPorts.get(),
            duration,
            mCancelled,
            results
        );

        if (mProgressListener != null) {
            mProgressListener.onScanComplete(result);
        }

        return result;
    }

    /**
     * Cancel ongoing batch scan
     */
    public void cancel() {
        mCancelled = true;
        cancelActiveScans();
        if (mExecutor != null) {
            mExecutor.shutdownNow();
        }
    }

    /**
     * Check if scan is in progress
     */
    public boolean isScanning() {
        return mExecutor != null && !mExecutor.isTerminated();
    }

    /**
     * Scan a single target and return number of ports found
     */
    private int scanSingleTarget(@NonNull Target target, @Nullable String portRange)
            throws ChildManager.ChildNotStartedException {

        final AtomicInteger portsFound = new AtomicInteger(0);
        final CountDownLatch scanLatch = new CountDownLatch(1);

        NMap.SynScanReceiver receiver = new NMap.SynScanReceiver() {
            @Override
            public void onPortFound(int port, String protocol) {
                target.addOpenPort(port, Network.Protocol.fromString(protocol));
                portsFound.incrementAndGet();
            }

            @Override
            public void onEnd(int exitCode) {
                super.onEnd(exitCode);
                scanLatch.countDown();
            }
        };

        Child process = System.getTools().nmap.synScan(target, receiver, portRange);
        mActiveScans.add(process);

        try {
            // Wait for scan to complete with timeout
            scanLatch.await(60, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            process.kill();
        }

        mActiveScans.remove(process);
        return portsFound.get();
    }

    /**
     * Cancel all active scans
     */
    private void cancelActiveScans() {
        for (Child scan : mActiveScans) {
            try {
                scan.kill();
            } catch (Exception e) {
                LoggingHelper.w(TAG, "Failed to kill scan process");
            }
        }
        mActiveScans.clear();
    }

    /**
     * Quick scan common ports on all targets
     */
    @NonNull
    public BatchScanResult quickScanAllTargets() {
        // Common ports: HTTP, HTTPS, SSH, FTP, SMTP, POP3, DNS, MySQL, etc.
        return scanAllEndpoints("21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,8080,8443");
    }

    /**
     * Full scan (all ports) on specific targets - use with caution
     */
    @NonNull
    public BatchScanResult fullScan(@NonNull List<Target> targets) {
        return scanTargets(targets, "1-65535");
    }

    /**
     * Service detection scan
     */
    @NonNull
    public BatchScanResult serviceScan(@NonNull List<Target> targets) {
        // Common service ports
        return scanTargets(targets, "20,21,22,23,25,53,80,110,111,135,139,143,443,445,465,587,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,27017");
    }
}
