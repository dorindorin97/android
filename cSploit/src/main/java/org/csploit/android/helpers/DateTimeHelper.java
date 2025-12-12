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
 * Utility class for date and time operations.
 * Provides formatting, parsing, and time difference calculations.
 */
public final class DateTimeHelper {

    private static final String DEFAULT_DATE_FORMAT = "yyyy-MM-dd";
    private static final String DEFAULT_TIME_FORMAT = "HH:mm:ss";
    private static final String DEFAULT_DATETIME_FORMAT = "yyyy-MM-dd HH:mm:ss";
    private static final String ISO_8601_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
    private static final String LOG_FORMAT = "yyyy-MM-dd_HH-mm-ss";

    private DateTimeHelper() {
        // Private constructor to prevent instantiation
    }

    /**
     * Get current timestamp in milliseconds
     */
    public static long now() {
        return System.currentTimeMillis();
    }

    /**
     * Get current date
     */
    @NonNull
    public static Date currentDate() {
        return new Date();
    }

    /**
     * Format date with default format
     */
    @NonNull
    public static String format(@Nullable Date date) {
        return format(date, DEFAULT_DATETIME_FORMAT);
    }

    /**
     * Format date with custom format
     */
    @NonNull
    public static String format(@Nullable Date date, @NonNull String pattern) {
        if (date == null) {
            return "";
        }
        SimpleDateFormat sdf = new SimpleDateFormat(pattern, Locale.US);
        return sdf.format(date);
    }

    /**
     * Format timestamp with default format
     */
    @NonNull
    public static String format(long timestamp) {
        return format(new Date(timestamp), DEFAULT_DATETIME_FORMAT);
    }

    /**
     * Format timestamp with custom format
     */
    @NonNull
    public static String format(long timestamp, @NonNull String pattern) {
        return format(new Date(timestamp), pattern);
    }

    /**
     * Format date for log file names (safe for filenames)
     */
    @NonNull
    public static String formatForLog(@Nullable Date date) {
        return format(date, LOG_FORMAT);
    }

    /**
     * Format date to ISO 8601 format
     */
    @NonNull
    public static String toISO8601(@Nullable Date date) {
        if (date == null) {
            return "";
        }
        SimpleDateFormat sdf = new SimpleDateFormat(ISO_8601_FORMAT, Locale.US);
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        return sdf.format(date);
    }

    /**
     * Parse date from ISO 8601 format
     */
    @Nullable
    public static Date fromISO8601(@Nullable String dateString) {
        if (ValidationHelper.isEmpty(dateString)) {
            return null;
        }
        try {
            SimpleDateFormat sdf = new SimpleDateFormat(ISO_8601_FORMAT, Locale.US);
            sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
            return sdf.parse(dateString);
        } catch (ParseException e) {
            LoggingHelper.error("Failed to parse ISO 8601 date: " + dateString);
            return null;
        }
    }

    /**
     * Parse date from string
     */
    @Nullable
    public static Date parse(@Nullable String dateString, @NonNull String pattern) {
        if (ValidationHelper.isEmpty(dateString)) {
            return null;
        }
        try {
            SimpleDateFormat sdf = new SimpleDateFormat(pattern, Locale.US);
            return sdf.parse(dateString);
        } catch (ParseException e) {
            LoggingHelper.error("Failed to parse date: " + dateString + " with pattern: " + pattern);
            return null;
        }
    }

    /**
     * Get human-readable time difference
     */
    @NonNull
    public static String getTimeAgo(long timestamp) {
        long diff = System.currentTimeMillis() - timestamp;

        if (diff < 0) {
            return "in the future";
        }

        if (diff < TimeUnit.MINUTES.toMillis(1)) {
            long seconds = TimeUnit.MILLISECONDS.toSeconds(diff);
            return seconds + " second" + (seconds != 1 ? "s" : "") + " ago";
        }

        if (diff < TimeUnit.HOURS.toMillis(1)) {
            long minutes = TimeUnit.MILLISECONDS.toMinutes(diff);
            return minutes + " minute" + (minutes != 1 ? "s" : "") + " ago";
        }

        if (diff < TimeUnit.DAYS.toMillis(1)) {
            long hours = TimeUnit.MILLISECONDS.toHours(diff);
            return hours + " hour" + (hours != 1 ? "s" : "") + " ago";
        }

        if (diff < TimeUnit.DAYS.toMillis(7)) {
            long days = TimeUnit.MILLISECONDS.toDays(diff);
            return days + " day" + (days != 1 ? "s" : "") + " ago";
        }

        if (diff < TimeUnit.DAYS.toMillis(30)) {
            long weeks = TimeUnit.MILLISECONDS.toDays(diff) / 7;
            return weeks + " week" + (weeks != 1 ? "s" : "") + " ago";
        }

        if (diff < TimeUnit.DAYS.toMillis(365)) {
            long months = TimeUnit.MILLISECONDS.toDays(diff) / 30;
            return months + " month" + (months != 1 ? "s" : "") + " ago";
        }

        long years = TimeUnit.MILLISECONDS.toDays(diff) / 365;
        return years + " year" + (years != 1 ? "s" : "") + " ago";
    }

    /**
     * Get time difference in human readable format
     */
    @NonNull
    public static String getTimeDifference(long startTime, long endTime) {
        long diff = Math.abs(endTime - startTime);

        long hours = TimeUnit.MILLISECONDS.toHours(diff);
        long minutes = TimeUnit.MILLISECONDS.toMinutes(diff) % 60;
        long seconds = TimeUnit.MILLISECONDS.toSeconds(diff) % 60;
        long millis = diff % 1000;

        if (hours > 0) {
            return String.format(Locale.US, "%d:%02d:%02d", hours, minutes, seconds);
        } else if (minutes > 0) {
            return String.format(Locale.US, "%d:%02d", minutes, seconds);
        } else if (seconds > 0) {
            return String.format(Locale.US, "%d.%03ds", seconds, millis);
        } else {
            return String.format(Locale.US, "%dms", millis);
        }
    }

    /**
     * Check if date is today
     */
    public static boolean isToday(@Nullable Date date) {
        if (date == null) {
            return false;
        }
        Calendar cal1 = Calendar.getInstance();
        Calendar cal2 = Calendar.getInstance();
        cal1.setTime(date);
        cal2.setTime(new Date());
        return cal1.get(Calendar.YEAR) == cal2.get(Calendar.YEAR) &&
               cal1.get(Calendar.DAY_OF_YEAR) == cal2.get(Calendar.DAY_OF_YEAR);
    }

    /**
     * Check if date is yesterday
     */
    public static boolean isYesterday(@Nullable Date date) {
        if (date == null) {
            return false;
        }
        Calendar cal1 = Calendar.getInstance();
        Calendar cal2 = Calendar.getInstance();
        cal1.setTime(date);
        cal2.setTime(new Date());
        cal2.add(Calendar.DAY_OF_YEAR, -1);
        return cal1.get(Calendar.YEAR) == cal2.get(Calendar.YEAR) &&
               cal1.get(Calendar.DAY_OF_YEAR) == cal2.get(Calendar.DAY_OF_YEAR);
    }

    /**
     * Add days to date
     */
    @NonNull
    public static Date addDays(@NonNull Date date, int days) {
        Calendar cal = Calendar.getInstance();
        cal.setTime(date);
        cal.add(Calendar.DAY_OF_YEAR, days);
        return cal.getTime();
    }

    /**
     * Add hours to date
     */
    @NonNull
    public static Date addHours(@NonNull Date date, int hours) {
        Calendar cal = Calendar.getInstance();
        cal.setTime(date);
        cal.add(Calendar.HOUR_OF_DAY, hours);
        return cal.getTime();
    }

    /**
     * Add minutes to date
     */
    @NonNull
    public static Date addMinutes(@NonNull Date date, int minutes) {
        Calendar cal = Calendar.getInstance();
        cal.setTime(date);
        cal.add(Calendar.MINUTE, minutes);
        return cal.getTime();
    }

    /**
     * Get start of day
     */
    @NonNull
    public static Date startOfDay(@NonNull Date date) {
        Calendar cal = Calendar.getInstance();
        cal.setTime(date);
        cal.set(Calendar.HOUR_OF_DAY, 0);
        cal.set(Calendar.MINUTE, 0);
        cal.set(Calendar.SECOND, 0);
        cal.set(Calendar.MILLISECOND, 0);
        return cal.getTime();
    }

    /**
     * Get end of day
     */
    @NonNull
    public static Date endOfDay(@NonNull Date date) {
        Calendar cal = Calendar.getInstance();
        cal.setTime(date);
        cal.set(Calendar.HOUR_OF_DAY, 23);
        cal.set(Calendar.MINUTE, 59);
        cal.set(Calendar.SECOND, 59);
        cal.set(Calendar.MILLISECOND, 999);
        return cal.getTime();
    }

    /**
     * Check if date is within range
     */
    public static boolean isWithinRange(@NonNull Date date, @NonNull Date start, @NonNull Date end) {
        return !date.before(start) && !date.after(end);
    }

    /**
     * Get days between two dates
     */
    public static long daysBetween(@NonNull Date start, @NonNull Date end) {
        long diff = Math.abs(end.getTime() - start.getTime());
        return TimeUnit.MILLISECONDS.toDays(diff);
    }

    /**
     * Format uptime duration
     */
    @NonNull
    public static String formatUptime(long uptimeMillis) {
        if (uptimeMillis < 0) {
            return "0s";
        }

        long days = TimeUnit.MILLISECONDS.toDays(uptimeMillis);
        long hours = TimeUnit.MILLISECONDS.toHours(uptimeMillis) % 24;
        long minutes = TimeUnit.MILLISECONDS.toMinutes(uptimeMillis) % 60;
        long seconds = TimeUnit.MILLISECONDS.toSeconds(uptimeMillis) % 60;

        StringBuilder sb = new StringBuilder();
        if (days > 0) {
            sb.append(days).append("d ");
        }
        if (hours > 0 || days > 0) {
            sb.append(hours).append("h ");
        }
        if (minutes > 0 || hours > 0 || days > 0) {
            sb.append(minutes).append("m ");
        }
        sb.append(seconds).append("s");

        return sb.toString().trim();
    }

    /**
     * Get current time formatted for display
     */
    @NonNull
    public static String getCurrentTimeFormatted() {
        return format(new Date(), DEFAULT_TIME_FORMAT);
    }

    /**
     * Get current date formatted for display
     */
    @NonNull
    public static String getCurrentDateFormatted() {
        return format(new Date(), DEFAULT_DATE_FORMAT);
    }

    /**
     * Get current datetime formatted for display
     */
    @NonNull
    public static String getCurrentDateTimeFormatted() {
        return format(new Date(), DEFAULT_DATETIME_FORMAT);
    }
}
