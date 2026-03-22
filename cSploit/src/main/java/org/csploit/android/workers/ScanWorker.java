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
package org.csploit.android.workers;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;

import androidx.annotation.NonNull;
import androidx.preference.PreferenceManager;
import androidx.work.Constraints;
import androidx.work.ExistingPeriodicWorkPolicy;
import androidx.work.NetworkType;
import androidx.work.PeriodicWorkRequest;
import androidx.work.ListenableWorker.Result;
import androidx.work.WorkManager;
import androidx.work.Worker;
import androidx.work.WorkerParameters;

import org.csploit.android.helpers.LoggingHelper;
import org.csploit.android.services.ScheduledScanService;

import java.util.concurrent.TimeUnit;

/**
 * WorkManager-based worker that triggers {@link ScheduledScanService} on a periodic schedule.
 *
 * <p>Use {@link #schedule(Context)} to enqueue a unique periodic job and
 * {@link #cancel(Context)} to remove it. The interval is read from the
 * {@link ScheduledScanService#PREF_SCAN_INTERVAL} preference (stored as a
 * {@link ScheduledScanService.ScanInterval} enum name). If the stored value cannot be
 * resolved, the worker falls back to a 1-hour interval.</p>
 */
public class ScanWorker extends Worker {

    private static final String TAG = "ScanWorker";
    private static final String WORK_NAME = "scheduled_scan";

    /** Minimum interval enforced by WorkManager for periodic work (15 minutes). */
    private static final long MIN_INTERVAL_MINUTES = 15L;

    public ScanWorker(@NonNull Context context, @NonNull WorkerParameters params) {
        super(context, params);
    }

    @NonNull
    @Override
    public Result doWork() {
        Context context = getApplicationContext();
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);

        // Read preferences used by ScheduledScanService
        String scanTypeName = prefs.getString(ScheduledScanService.PREF_SCAN_TYPE,
                ScheduledScanService.ScanType.DISCOVERY.name());
        boolean autoExport = prefs.getBoolean(ScheduledScanService.PREF_AUTO_EXPORT, true);
        String intervalName = prefs.getString(ScheduledScanService.PREF_SCAN_INTERVAL,
                ScheduledScanService.ScanInterval.HOURLY.name());

        // Validate scan type preference so callers can detect misconfiguration early
        try {
            ScheduledScanService.ScanType.valueOf(scanTypeName);
        } catch (IllegalArgumentException e) {
            LoggingHelper.warning("ScanWorker: invalid scan type '" + scanTypeName
                    + "', defaulting to DISCOVERY");
            prefs.edit()
                    .putString(ScheduledScanService.PREF_SCAN_TYPE,
                            ScheduledScanService.ScanType.DISCOVERY.name())
                    .apply();
        }

        LoggingHelper.info("ScanWorker: triggering scan — type=" + scanTypeName
                + ", autoExport=" + autoExport + ", interval=" + intervalName);

        try {
            // Delegate the actual scan work to ScheduledScanService, preserving all
            // existing scan logic (wake lock, notifications, export, etc.).
            Intent intent = new Intent(context, ScheduledScanService.class);
            intent.setAction("org.csploit.android.SCHEDULED_SCAN");

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent);
            } else {
                context.startService(intent);
            }

            return Result.success();
        } catch (Exception e) {
            LoggingHelper.e(TAG, "ScanWorker: failed to start ScheduledScanService", e);
            return Result.failure();
        }
    }

    // ==================== Static Scheduling Helpers ====================

    /**
     * Enqueue (or replace) a unique periodic WorkManager job for network scanning.
     *
     * <p>The repeat interval is derived from the {@link ScheduledScanService#PREF_SCAN_INTERVAL}
     * preference. WorkManager enforces a minimum of 15 minutes; shorter intervals stored in
     * preferences are silently clamped to that minimum.</p>
     *
     * @param context Application context
     */
    public static void schedule(@NonNull Context context) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);

        // Resolve interval from the ScanInterval enum stored in preferences
        long intervalMinutes = resolveIntervalMinutes(prefs);

        Constraints constraints = new Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build();

        PeriodicWorkRequest scanRequest = new PeriodicWorkRequest.Builder(
                ScanWorker.class, intervalMinutes, TimeUnit.MINUTES)
                .setConstraints(constraints)
                .build();

        WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                WORK_NAME,
                ExistingPeriodicWorkPolicy.UPDATE,
                scanRequest);

        LoggingHelper.info("ScanWorker: scheduled periodic work every "
                + intervalMinutes + " minutes");
    }

    /**
     * Cancel the unique periodic WorkManager job for network scanning.
     *
     * @param context Application context
     */
    public static void cancel(@NonNull Context context) {
        WorkManager.getInstance(context).cancelUniqueWork(WORK_NAME);
        LoggingHelper.info("ScanWorker: cancelled periodic work");
    }

    // ==================== Private Helpers ====================

    /**
     * Reads {@link ScheduledScanService#PREF_SCAN_INTERVAL} and converts the stored
     * {@link ScheduledScanService.ScanInterval} enum name into minutes.
     * Falls back to 60 minutes (1 hour) if the value is missing or unrecognised.
     */
    private static long resolveIntervalMinutes(@NonNull SharedPreferences prefs) {
        String intervalName = prefs.getString(
                ScheduledScanService.PREF_SCAN_INTERVAL,
                ScheduledScanService.ScanInterval.HOURLY.name());

        ScheduledScanService.ScanInterval interval;
        try {
            interval = ScheduledScanService.ScanInterval.valueOf(intervalName);
        } catch (IllegalArgumentException e) {
            LoggingHelper.warning("ScanWorker: unknown interval '" + intervalName
                    + "', defaulting to HOURLY");
            interval = ScheduledScanService.ScanInterval.HOURLY;
        }

        // Convert millis to minutes; clamp to WorkManager's 15-minute minimum
        long minutes = TimeUnit.MILLISECONDS.toMinutes(interval.millis);
        return Math.max(minutes, MIN_INTERVAL_MINUTES);
    }
}
