package org.csploit.android.helpers;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import android.util.Log;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * Enhanced logging utility with structured logging capabilities.
 * Provides methods for consistent logging across the application.
 */
public final class LoggingHelper {

    private static final String TAG = "cSploit";
    private static final SimpleDateFormat dateFormat = 
        new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US);

    /**
     * Log level for categorizing messages
     */
    public enum LogLevel {
        VERBOSE(Log.VERBOSE, "V"),
        DEBUG(Log.DEBUG, "D"),
        INFO(Log.INFO, "I"),
        WARN(Log.WARN, "W"),
        ERROR(Log.ERROR, "E");

        public final int level;
        public final String letter;

        LogLevel(int level, String letter) {
            this.level = level;
            this.letter = letter;
        }
    }

    /**
     * Log a verbose message
     */
    public static void v(@NonNull String tag, @NonNull String message) {
        log(LogLevel.VERBOSE, tag, message, null);
    }

    /**
     * Log a debug message
     */
    public static void d(@NonNull String tag, @NonNull String message) {
        log(LogLevel.DEBUG, tag, message, null);
    }

    /**
     * Log an info message
     */
    public static void i(@NonNull String tag, @NonNull String message) {
        log(LogLevel.INFO, tag, message, null);
    }

    /**
     * Log a warning message
     */
    public static void w(@NonNull String tag, @NonNull String message) {
        log(LogLevel.WARN, tag, message, null);
    }

    /**
     * Log an error message
     */
    public static void e(@NonNull String tag, @NonNull String message) {
        log(LogLevel.ERROR, tag, message, null);
    }

    /**
     * Log an error with exception
     */
    public static void e(@NonNull String tag, @NonNull String message, @NonNull Throwable throwable) {
        log(LogLevel.ERROR, tag, message, throwable);
    }

    /**
     * Log an exception
     */
    public static void logException(@NonNull String tag, @NonNull Throwable throwable) {
        e(tag, "Exception occurred", throwable);
    }

    /**
     * Core logging method
     */
    private static void log(
            @NonNull LogLevel level,
            @NonNull String tag,
            @NonNull String message,
            @Nullable Throwable throwable) {

        String logMessage = String.format(
            "%s [%s] %s: %s",
            getTimestamp(),
            level.letter,
            tag,
            message
        );

        // Log to Android logger
        if (throwable != null) {
            Log.println(level.level, TAG, logMessage + "\n" + getStackTrace(throwable));
        } else {
            Log.println(level.level, TAG, logMessage);
        }
    }

    /**
     * Get current timestamp
     */
    @NonNull
    private static String getTimestamp() {
        return dateFormat.format(new Date());
    }

    /**
     * Get stack trace from exception
     */
    @NonNull
    private static String getStackTrace(@NonNull Throwable throwable) {
        StringWriter sw = new StringWriter();
        throwable.printStackTrace(new PrintWriter(sw));
        return sw.toString();
    }

    /**
     * Log method entry (for debugging)
     */
    public static void logMethodEntry(@NonNull String tag, @NonNull String methodName) {
        d(tag, ">>> " + methodName);
    }

    /**
     * Log method exit (for debugging)
     */
    public static void logMethodExit(@NonNull String tag, @NonNull String methodName) {
        d(tag, "<<< " + methodName);
    }

    /**
     * Log a value for debugging
     */
    public static void logValue(@NonNull String tag, @NonNull String key, @Nullable Object value) {
        d(tag, key + " = " + (value != null ? value.toString() : "null"));
    }

    /**
     * Log performance metric
     */
    public static void logPerformance(
            @NonNull String tag,
            @NonNull String operation,
            long durationMs) {
        
        d(tag, operation + " took " + durationMs + "ms");
    }

    /**
     * Create a formatted performance message
     */
    @NonNull
    public static String formatPerformance(@NonNull String operation, long durationMs) {
        return operation + " took " + durationMs + "ms";
    }

    /**
     * Safely log an object (null-safe)
     */
    public static void logObject(
            @NonNull String tag,
            @NonNull String name,
            @Nullable Object obj) {
        
        d(tag, name + " = " + (obj != null ? obj : "null"));
    }

    /**
     * Log collection size
     */
    public static void logCollectionSize(
            @NonNull String tag,
            @NonNull String name,
            @Nullable java.util.Collection<?> collection) {
        
        d(tag, name + " size = " + (collection != null ? collection.size() : 0));
    }
}
