package org.csploit.android.helpers;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import android.util.Log;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

/**
 * Enhanced logging utility with structured logging capabilities.
 * Provides methods for consistent logging across the application.
 *
 * This class consolidates logging functionality from the legacy Logger class
 * and provides both explicit tag logging and automatic class/method detection.
 *
 * Usage:
 * {@code
 * // With explicit tag
 * LoggingHelper.d("MyClass", "Debug message");
 *
 * // With automatic detection (slower but convenient for debugging)
 * LoggingHelper.debug("Debug message");
 *
 * // With exception
 * LoggingHelper.e("MyClass", "Error occurred", exception);
 * }
 */
public final class LoggingHelper {

    private static final String TAG = "cSploit";
    private static final String CLASS_NAME = LoggingHelper.class.getName();
    // Thread-safe DateTimeFormatter (immutable and thread-safe unlike SimpleDateFormat)
    private static final DateTimeFormatter DATE_FORMATTER =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS", Locale.US);

    // Enable/disable debug logging globally
    private static volatile boolean sDebugEnabled = true;

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

    // ==================== Debug Control ====================

    /**
     * Enable or disable debug logging globally.
     * @param enabled true to enable debug logging
     */
    public static void setDebugEnabled(boolean enabled) {
        sDebugEnabled = enabled;
    }

    /**
     * Check if debug logging is enabled.
     * @return true if debug logging is enabled
     */
    public static boolean isDebugEnabled() {
        return sDebugEnabled;
    }

    // ==================== Tagged Logging Methods ====================

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
     * Log a debug message with exception
     */
    public static void d(@NonNull String tag, @NonNull String message, @NonNull Throwable throwable) {
        log(LogLevel.DEBUG, tag, message, throwable);
    }

    /**
     * Log an info message
     */
    public static void i(@NonNull String tag, @NonNull String message) {
        log(LogLevel.INFO, tag, message, null);
    }

    /**
     * Log an info message with exception
     */
    public static void i(@NonNull String tag, @NonNull String message, @NonNull Throwable throwable) {
        log(LogLevel.INFO, tag, message, throwable);
    }

    /**
     * Log a warning message
     */
    public static void w(@NonNull String tag, @NonNull String message) {
        log(LogLevel.WARN, tag, message, null);
    }

    /**
     * Log a warning with exception
     */
    public static void w(@NonNull String tag, @NonNull String message, @NonNull Throwable throwable) {
        log(LogLevel.WARN, tag, message, throwable);
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

    // ==================== Auto-detecting Logging Methods ====================
    // These methods automatically detect the calling class and method name

    /**
     * Log a verbose message with automatic class/method detection.
     */
    public static void verbose(@NonNull String message) {
        logAuto(LogLevel.VERBOSE, message, null);
    }

    /**
     * Log a debug message with automatic class/method detection.
     */
    public static void debug(@NonNull String message) {
        logAuto(LogLevel.DEBUG, message, null);
    }

    /**
     * Log an info message with automatic class/method detection.
     */
    public static void info(@NonNull String message) {
        logAuto(LogLevel.INFO, message, null);
    }

    /**
     * Log a warning message with automatic class/method detection.
     */
    public static void warning(@NonNull String message) {
        logAuto(LogLevel.WARN, message, null);
    }

    /**
     * Log an error message with automatic class/method detection.
     */
    public static void error(@NonNull String message) {
        logAuto(LogLevel.ERROR, message, null);
    }

    /**
     * Log an error message with exception using automatic detection.
     */
    public static void error(@NonNull String message, @NonNull Throwable throwable) {
        logAuto(LogLevel.ERROR, message, throwable);
    }

    /**
     * Log just an exception with automatic detection.
     */
    public static void exception(@NonNull Throwable throwable) {
        logAuto(LogLevel.ERROR, "Exception occurred", throwable);
    }

    /**
     * Log with custom tag (useful for specific components).
     * @param customTag custom tag suffix
     * @param message log message
     */
    public static void debugWithTag(@NonNull String customTag, @NonNull String message) {
        if (!sDebugEnabled) {
            return;
        }
        Log.d(TAG + "[" + customTag + "]", message != null ? message : "(null)");
    }

    // ==================== Core Logging Methods ====================

    /**
     * Core logging method with explicit tag.
     */
    private static void log(
            @NonNull LogLevel level,
            @NonNull String tag,
            @NonNull String message,
            @Nullable Throwable throwable) {

        // Skip debug logs if disabled
        if (!sDebugEnabled && level.level <= Log.DEBUG) {
            return;
        }

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
     * Core logging method with automatic class/method detection.
     */
    private static void logAuto(
            @NonNull LogLevel level,
            @NonNull String message,
            @Nullable Throwable throwable) {

        // Skip debug logs if disabled
        if (!sDebugEnabled && level.level <= Log.DEBUG) {
            return;
        }

        // Get caller info
        CallerInfo caller = getCallerInfo();

        String logTag = String.format("%s[%s.%s:%d]",
            TAG, caller.className, caller.methodName, caller.lineNumber);

        String logMessage = message != null ? message : "(null)";

        // Log to Android logger
        if (throwable != null) {
            Log.println(level.level, logTag, logMessage + "\n" + getStackTrace(throwable));
        } else {
            Log.println(level.level, logTag, logMessage);
        }
    }

    // ==================== Helper Methods ====================

    /**
     * Get current timestamp
     */
    @NonNull
    private static String getTimestamp() {
        return LocalDateTime.now().format(DATE_FORMATTER);
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
     * Get caller class and method information.
     */
    @NonNull
    private static CallerInfo getCallerInfo() {
        StackTraceElement[] elements = Thread.currentThread().getStackTrace();

        for (StackTraceElement element : elements) {
            String className = element.getClassName();
            if (className.startsWith("org.csploit.android.") && !className.equals(CLASS_NAME)) {
                return new CallerInfo(
                    className.replace("org.csploit.android.", ""),
                    element.getMethodName(),
                    element.getLineNumber()
                );
            }
        }

        return new CallerInfo("unknown", "unknown", -1);
    }

    /**
     * Caller information holder
     */
    private static class CallerInfo {
        final String className;
        final String methodName;
        final int lineNumber;

        CallerInfo(String className, String methodName, int lineNumber) {
            this.className = className;
            this.methodName = methodName;
            this.lineNumber = lineNumber;
        }
    }

    // ==================== Debug Utility Methods ====================

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

    // ==================== Timing Utilities ====================

    /**
     * Start a timed operation. Returns the start time in nanoseconds.
     */
    public static long startTiming() {
        return java.lang.System.nanoTime();
    }

    /**
     * End a timed operation and log the duration.
     */
    public static void endTiming(@NonNull String tag, @NonNull String operation, long startNanos) {
        long durationMs = (java.lang.System.nanoTime() - startNanos) / 1_000_000;
        logPerformance(tag, operation, durationMs);
    }

    /**
     * Create a scoped timer that logs duration when closed.
     */
    @NonNull
    public static ScopedTimer scopedTimer(@NonNull String tag, @NonNull String operation) {
        return new ScopedTimer(tag, operation);
    }

    /**
     * Scoped timer that logs duration when closed.
     * Use with try-with-resources for automatic timing.
     */
    public static class ScopedTimer implements AutoCloseable {
        private final String tag;
        private final String operation;
        private final long startNanos;

        ScopedTimer(String tag, String operation) {
            this.tag = tag;
            this.operation = operation;
            this.startNanos = java.lang.System.nanoTime();
        }

        @Override
        public void close() {
            long durationMs = (java.lang.System.nanoTime() - startNanos) / 1_000_000;
            logPerformance(tag, operation, durationMs);
        }
    }
}
