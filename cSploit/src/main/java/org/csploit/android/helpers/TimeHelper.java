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

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;
import java.util.concurrent.TimeUnit;

/**
 * TimeHelper - Comprehensive time and date utilities
 *
 * Provides:
 * - Time formatting and parsing
 * - Duration calculations
 * - Relative time descriptions
 * - Timezone conversions
 * - Stopwatch functionality
 * - Schedule/cron helpers
 */
public final class TimeHelper {

    private static final String TAG = "TimeHelper";

    // Common date formats
    public static final String ISO_8601 = "yyyy-MM-dd'T'HH:mm:ss'Z'";
    public static final String ISO_8601_MILLIS = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
    public static final String DATE_ONLY = "yyyy-MM-dd";
    public static final String TIME_ONLY = "HH:mm:ss";
    public static final String TIME_12H = "hh:mm:ss a";
    public static final String DATETIME_DISPLAY = "MMM dd, yyyy HH:mm";
    public static final String DATETIME_FILE = "yyyyMMdd_HHmmss";
    public static final String DATETIME_LOG = "yyyy-MM-dd HH:mm:ss.SSS";

    // Time constants
    public static final long SECOND_MS = 1000;
    public static final long MINUTE_MS = 60 * SECOND_MS;
    public static final long HOUR_MS = 60 * MINUTE_MS;
    public static final long DAY_MS = 24 * HOUR_MS;
    public static final long WEEK_MS = 7 * DAY_MS;

    private TimeHelper() {}

    // ==================== Formatting ====================

    /**
     * Format a date using the specified pattern
     */
    @NonNull
    public static String format(@Nullable Date date, @NonNull String pattern) {
        if (date == null) {
            return "";
        }
        try {
            SimpleDateFormat sdf = new SimpleDateFormat(pattern, Locale.US);
            return sdf.format(date);
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * Format current time using the specified pattern
     */
    @NonNull
    public static String formatNow(@NonNull String pattern) {
        return format(new Date(), pattern);
    }

    /**
     * Format a timestamp in milliseconds
     */
    @NonNull
    public static String format(long timestampMs, @NonNull String pattern) {
        return format(new Date(timestampMs), pattern);
    }

    /**
     * Format a date as ISO 8601
     */
    @NonNull
    public static String toIso8601(@Nullable Date date) {
        if (date == null) return "";
        SimpleDateFormat sdf = new SimpleDateFormat(ISO_8601, Locale.US);
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        return sdf.format(date);
    }

    /**
     * Format for log entries
     */
    @NonNull
    public static String formatForLog() {
        return formatNow(DATETIME_LOG);
    }

    /**
     * Format for file names
     */
    @NonNull
    public static String formatForFile() {
        return formatNow(DATETIME_FILE);
    }

    // ==================== Parsing ====================

    /**
     * Parse a date string using the specified pattern
     */
    @Nullable
    public static Date parse(@Nullable String dateStr, @NonNull String pattern) {
        if (dateStr == null || dateStr.isEmpty()) {
            return null;
        }
        try {
            SimpleDateFormat sdf = new SimpleDateFormat(pattern, Locale.US);
            return sdf.parse(dateStr);
        } catch (ParseException e) {
            return null;
        }
    }

    /**
     * Parse an ISO 8601 date string
     */
    @Nullable
    public static Date parseIso8601(@Nullable String dateStr) {
        if (dateStr == null) return null;
        SimpleDateFormat sdf = new SimpleDateFormat(ISO_8601, Locale.US);
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        try {
            return sdf.parse(dateStr);
        } catch (ParseException e) {
            // Try with milliseconds
            try {
                sdf = new SimpleDateFormat(ISO_8601_MILLIS, Locale.US);
                sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
                return sdf.parse(dateStr);
            } catch (ParseException e2) {
                return null;
            }
        }
    }

    // ==================== Duration Formatting ====================

    /**
     * Format a duration in milliseconds to human-readable format
     */
    @NonNull
    public static String formatDuration(long millis) {
        if (millis < 0) return "0ms";

        if (millis < SECOND_MS) {
            return millis + "ms";
        } else if (millis < MINUTE_MS) {
            return String.format(Locale.US, "%.1fs", millis / 1000.0);
        } else if (millis < HOUR_MS) {
            long minutes = millis / MINUTE_MS;
            long seconds = (millis % MINUTE_MS) / SECOND_MS;
            return String.format(Locale.US, "%dm %ds", minutes, seconds);
        } else if (millis < DAY_MS) {
            long hours = millis / HOUR_MS;
            long minutes = (millis % HOUR_MS) / MINUTE_MS;
            return String.format(Locale.US, "%dh %dm", hours, minutes);
        } else {
            long days = millis / DAY_MS;
            long hours = (millis % DAY_MS) / HOUR_MS;
            return String.format(Locale.US, "%dd %dh", days, hours);
        }
    }

    /**
     * Format a duration with full units
     */
    @NonNull
    public static String formatDurationFull(long millis) {
        if (millis < 0) return "0 milliseconds";

        StringBuilder sb = new StringBuilder();
        long days = millis / DAY_MS;
        millis %= DAY_MS;
        long hours = millis / HOUR_MS;
        millis %= HOUR_MS;
        long minutes = millis / MINUTE_MS;
        millis %= MINUTE_MS;
        long seconds = millis / SECOND_MS;

        if (days > 0) {
            sb.append(days).append(days == 1 ? " day " : " days ");
        }
        if (hours > 0) {
            sb.append(hours).append(hours == 1 ? " hour " : " hours ");
        }
        if (minutes > 0) {
            sb.append(minutes).append(minutes == 1 ? " minute " : " minutes ");
        }
        if (seconds > 0 || sb.length() == 0) {
            sb.append(seconds).append(seconds == 1 ? " second" : " seconds");
        }

        return sb.toString().trim();
    }

    /**
     * Format duration as HH:MM:SS
     */
    @NonNull
    public static String formatAsTimer(long millis) {
        if (millis < 0) millis = 0;

        long hours = millis / HOUR_MS;
        millis %= HOUR_MS;
        long minutes = millis / MINUTE_MS;
        millis %= MINUTE_MS;
        long seconds = millis / SECOND_MS;

        if (hours > 0) {
            return String.format(Locale.US, "%02d:%02d:%02d", hours, minutes, seconds);
        }
        return String.format(Locale.US, "%02d:%02d", minutes, seconds);
    }

    // ==================== Relative Time ====================

    /**
     * Get a relative time description (e.g., "5 minutes ago", "in 2 hours")
     */
    @NonNull
    public static String getRelativeTime(long timestampMs) {
        return getRelativeTime(timestampMs, System.currentTimeMillis());
    }

    /**
     * Get relative time from a reference point
     */
    @NonNull
    public static String getRelativeTime(long timestampMs, long referenceMs) {
        long diff = referenceMs - timestampMs;
        boolean past = diff >= 0;
        diff = Math.abs(diff);

        String prefix = past ? "" : "in ";
        String suffix = past ? " ago" : "";

        if (diff < MINUTE_MS) {
            return "just now";
        } else if (diff < HOUR_MS) {
            long minutes = diff / MINUTE_MS;
            return prefix + minutes + (minutes == 1 ? " minute" : " minutes") + suffix;
        } else if (diff < DAY_MS) {
            long hours = diff / HOUR_MS;
            return prefix + hours + (hours == 1 ? " hour" : " hours") + suffix;
        } else if (diff < WEEK_MS) {
            long days = diff / DAY_MS;
            return prefix + days + (days == 1 ? " day" : " days") + suffix;
        } else if (diff < 30 * DAY_MS) {
            long weeks = diff / WEEK_MS;
            return prefix + weeks + (weeks == 1 ? " week" : " weeks") + suffix;
        } else if (diff < 365 * DAY_MS) {
            long months = diff / (30 * DAY_MS);
            return prefix + months + (months == 1 ? " month" : " months") + suffix;
        } else {
            long years = diff / (365 * DAY_MS);
            return prefix + years + (years == 1 ? " year" : " years") + suffix;
        }
    }

    /**
     * Get a short relative time (e.g., "5m", "2h", "3d")
     */
    @NonNull
    public static String getRelativeTimeShort(long timestampMs) {
        long diff = Math.abs(System.currentTimeMillis() - timestampMs);

        if (diff < MINUTE_MS) {
            return "now";
        } else if (diff < HOUR_MS) {
            return (diff / MINUTE_MS) + "m";
        } else if (diff < DAY_MS) {
            return (diff / HOUR_MS) + "h";
        } else if (diff < WEEK_MS) {
            return (diff / DAY_MS) + "d";
        } else if (diff < 365 * DAY_MS) {
            return (diff / WEEK_MS) + "w";
        } else {
            return (diff / (365 * DAY_MS)) + "y";
        }
    }

    // ==================== Comparisons ====================

    /**
     * Check if a timestamp is today
     */
    public static boolean isToday(long timestampMs) {
        Calendar cal1 = Calendar.getInstance();
        Calendar cal2 = Calendar.getInstance();
        cal2.setTimeInMillis(timestampMs);

        return cal1.get(Calendar.YEAR) == cal2.get(Calendar.YEAR) &&
               cal1.get(Calendar.DAY_OF_YEAR) == cal2.get(Calendar.DAY_OF_YEAR);
    }

    /**
     * Check if a timestamp is yesterday
     */
    public static boolean isYesterday(long timestampMs) {
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_YEAR, -1);

        Calendar cal2 = Calendar.getInstance();
        cal2.setTimeInMillis(timestampMs);

        return cal.get(Calendar.YEAR) == cal2.get(Calendar.YEAR) &&
               cal.get(Calendar.DAY_OF_YEAR) == cal2.get(Calendar.DAY_OF_YEAR);
    }

    /**
     * Check if a timestamp is within the last N hours
     */
    public static boolean isWithinHours(long timestampMs, int hours) {
        return System.currentTimeMillis() - timestampMs < hours * HOUR_MS;
    }

    /**
     * Check if a timestamp is within the last N days
     */
    public static boolean isWithinDays(long timestampMs, int days) {
        return System.currentTimeMillis() - timestampMs < days * DAY_MS;
    }

    /**
     * Check if a timestamp is in the future
     */
    public static boolean isFuture(long timestampMs) {
        return timestampMs > System.currentTimeMillis();
    }

    /**
     * Check if a timestamp is in the past
     */
    public static boolean isPast(long timestampMs) {
        return timestampMs < System.currentTimeMillis();
    }

    // ==================== Calendar Operations ====================

    /**
     * Get start of today (midnight)
     */
    public static long getStartOfToday() {
        Calendar cal = Calendar.getInstance();
        cal.set(Calendar.HOUR_OF_DAY, 0);
        cal.set(Calendar.MINUTE, 0);
        cal.set(Calendar.SECOND, 0);
        cal.set(Calendar.MILLISECOND, 0);
        return cal.getTimeInMillis();
    }

    /**
     * Get end of today (23:59:59.999)
     */
    public static long getEndOfToday() {
        Calendar cal = Calendar.getInstance();
        cal.set(Calendar.HOUR_OF_DAY, 23);
        cal.set(Calendar.MINUTE, 59);
        cal.set(Calendar.SECOND, 59);
        cal.set(Calendar.MILLISECOND, 999);
        return cal.getTimeInMillis();
    }

    /**
     * Get start of the current week (Monday)
     */
    public static long getStartOfWeek() {
        Calendar cal = Calendar.getInstance();
        cal.set(Calendar.DAY_OF_WEEK, Calendar.MONDAY);
        cal.set(Calendar.HOUR_OF_DAY, 0);
        cal.set(Calendar.MINUTE, 0);
        cal.set(Calendar.SECOND, 0);
        cal.set(Calendar.MILLISECOND, 0);
        return cal.getTimeInMillis();
    }

    /**
     * Add duration to a timestamp
     */
    public static long add(long timestampMs, long durationMs) {
        return timestampMs + durationMs;
    }

    /**
     * Add hours to a timestamp
     */
    public static long addHours(long timestampMs, int hours) {
        return timestampMs + (hours * HOUR_MS);
    }

    /**
     * Add days to a timestamp
     */
    public static long addDays(long timestampMs, int days) {
        return timestampMs + (days * DAY_MS);
    }

    // ==================== Stopwatch ====================

    /**
     * Simple stopwatch for measuring elapsed time
     */
    public static class Stopwatch {
        private long startTime;
        private long stopTime;
        private boolean running;

        public Stopwatch() {
            reset();
        }

        public Stopwatch start() {
            if (!running) {
                startTime = System.nanoTime();
                running = true;
            }
            return this;
        }

        public Stopwatch stop() {
            if (running) {
                stopTime = System.nanoTime();
                running = false;
            }
            return this;
        }

        public Stopwatch reset() {
            startTime = 0;
            stopTime = 0;
            running = false;
            return this;
        }

        public long elapsedNanos() {
            return running ? System.nanoTime() - startTime : stopTime - startTime;
        }

        public long elapsedMillis() {
            return TimeUnit.NANOSECONDS.toMillis(elapsedNanos());
        }

        public long elapsedSeconds() {
            return TimeUnit.NANOSECONDS.toSeconds(elapsedNanos());
        }

        public boolean isRunning() {
            return running;
        }

        @NonNull
        @Override
        public String toString() {
            return formatDuration(elapsedMillis());
        }

        /**
         * Create and start a new stopwatch
         */
        public static Stopwatch createStarted() {
            return new Stopwatch().start();
        }
    }

    // ==================== Utilities ====================

    /**
     * Get current timestamp in milliseconds
     */
    public static long now() {
        return System.currentTimeMillis();
    }

    /**
     * Get current timestamp in seconds
     */
    public static long nowSeconds() {
        return System.currentTimeMillis() / 1000;
    }

    /**
     * Sleep for specified milliseconds (with interruption handling)
     */
    public static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Sleep for specified duration
     */
    public static void sleep(long duration, TimeUnit unit) {
        sleep(unit.toMillis(duration));
    }

    /**
     * Convert between time units
     */
    public static long convert(long duration, TimeUnit from, TimeUnit to) {
        return to.convert(duration, from);
    }

    /**
     * Get timezone offset in hours
     */
    public static int getTimezoneOffsetHours() {
        return TimeZone.getDefault().getRawOffset() / (int) HOUR_MS;
    }

    /**
     * Get timezone name
     */
    @NonNull
    public static String getTimezoneName() {
        return TimeZone.getDefault().getDisplayName();
    }
}
