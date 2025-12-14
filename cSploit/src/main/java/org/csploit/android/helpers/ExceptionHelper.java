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

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.concurrent.TimeoutException;

/**
 * Helper class for exception handling and analysis.
 *
 * Provides utilities for:
 * - Categorizing exceptions
 * - Extracting root causes
 * - Building user-friendly error messages
 * - Stack trace formatting
 */
public final class ExceptionHelper {

    private static final String TAG = "ExceptionHelper";

    /**
     * Exception categories for easier handling.
     */
    public enum ExceptionCategory {
        NETWORK,
        TIMEOUT,
        SECURITY,
        IO,
        INTERRUPTED,
        VALIDATION,
        RUNTIME,
        UNKNOWN
    }

    private ExceptionHelper() {
        // Prevent instantiation
    }

    /**
     * Get the root cause of an exception chain.
     *
     * @param throwable The exception to analyze
     * @return The root cause
     */
    @NonNull
    public static Throwable getRootCause(@NonNull Throwable throwable) {
        Throwable cause = throwable;
        while (cause.getCause() != null && cause.getCause() != cause) {
            cause = cause.getCause();
        }
        return cause;
    }

    /**
     * Get root cause message or class name if message is null.
     *
     * @param throwable The exception to analyze
     * @return User-friendly error message
     */
    @NonNull
    public static String getRootCauseMessage(@NonNull Throwable throwable) {
        Throwable root = getRootCause(throwable);
        String message = root.getMessage();
        if (message == null || message.isEmpty()) {
            return root.getClass().getSimpleName();
        }
        return message;
    }

    /**
     * Categorize an exception for easier handling.
     *
     * @param throwable The exception to categorize
     * @return Exception category
     */
    @NonNull
    public static ExceptionCategory categorize(@Nullable Throwable throwable) {
        if (throwable == null) {
            return ExceptionCategory.UNKNOWN;
        }

        Throwable root = getRootCause(throwable);

        if (root instanceof SocketTimeoutException ||
            root instanceof TimeoutException) {
            return ExceptionCategory.TIMEOUT;
        }

        if (root instanceof UnknownHostException ||
            root instanceof ConnectException ||
            isNetworkException(root)) {
            return ExceptionCategory.NETWORK;
        }

        if (root instanceof SecurityException) {
            return ExceptionCategory.SECURITY;
        }

        if (root instanceof IOException) {
            return ExceptionCategory.IO;
        }

        if (root instanceof InterruptedException) {
            return ExceptionCategory.INTERRUPTED;
        }

        if (root instanceof IllegalArgumentException ||
            root instanceof IllegalStateException ||
            root instanceof NullPointerException) {
            return ExceptionCategory.VALIDATION;
        }

        if (root instanceof RuntimeException) {
            return ExceptionCategory.RUNTIME;
        }

        return ExceptionCategory.UNKNOWN;
    }

    /**
     * Check if an exception is network-related.
     *
     * @param throwable The exception to check
     * @return true if network-related
     */
    public static boolean isNetworkException(@Nullable Throwable throwable) {
        if (throwable == null) return false;

        String message = throwable.getMessage();
        if (message == null) message = "";
        message = message.toLowerCase();

        return throwable instanceof java.net.SocketException ||
               throwable instanceof UnknownHostException ||
               throwable instanceof ConnectException ||
               message.contains("network") ||
               message.contains("connection") ||
               message.contains("unreachable") ||
               message.contains("refused");
    }

    /**
     * Check if an exception is retryable.
     *
     * @param throwable The exception to check
     * @return true if operation should be retried
     */
    public static boolean isRetryable(@Nullable Throwable throwable) {
        if (throwable == null) return false;

        ExceptionCategory category = categorize(throwable);
        return category == ExceptionCategory.NETWORK ||
               category == ExceptionCategory.TIMEOUT;
    }

    /**
     * Get a user-friendly error message.
     *
     * @param throwable The exception to format
     * @return User-friendly message
     */
    @NonNull
    public static String getUserFriendlyMessage(@Nullable Throwable throwable) {
        if (throwable == null) {
            return "Unknown error occurred";
        }

        ExceptionCategory category = categorize(throwable);
        switch (category) {
            case NETWORK:
                return "Network error: Please check your connection";
            case TIMEOUT:
                return "Operation timed out. Please try again";
            case SECURITY:
                return "Permission denied: " + getRootCauseMessage(throwable);
            case IO:
                return "I/O error: " + getRootCauseMessage(throwable);
            case INTERRUPTED:
                return "Operation was cancelled";
            case VALIDATION:
                return "Invalid input: " + getRootCauseMessage(throwable);
            case RUNTIME:
            case UNKNOWN:
            default:
                return getRootCauseMessage(throwable);
        }
    }

    /**
     * Get the full stack trace as a string.
     *
     * @param throwable The exception to format
     * @return Full stack trace
     */
    @NonNull
    public static String getStackTraceString(@NonNull Throwable throwable) {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        throwable.printStackTrace(pw);
        return sw.toString();
    }

    /**
     * Get a condensed stack trace (first N lines).
     *
     * @param throwable The exception to format
     * @param maxLines Maximum number of lines to include
     * @return Condensed stack trace
     */
    @NonNull
    public static String getCondensedStackTrace(@NonNull Throwable throwable, int maxLines) {
        String full = getStackTraceString(throwable);
        String[] lines = full.split("\n");
        if (lines.length <= maxLines) {
            return full;
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < maxLines; i++) {
            sb.append(lines[i]).append("\n");
        }
        sb.append("... (").append(lines.length - maxLines).append(" more lines)");
        return sb.toString();
    }

    /**
     * Log an exception with appropriate log level.
     *
     * @param throwable The exception to log
     * @param context Context message
     */
    public static void log(@Nullable Throwable throwable, @NonNull String context) {
        if (throwable == null) {
            LoggingHelper.warning(context + ": null exception");
            return;
        }

        ExceptionCategory category = categorize(throwable);
        String message = context + ": " + getRootCauseMessage(throwable);

        switch (category) {
            case NETWORK:
            case TIMEOUT:
                LoggingHelper.warning(message);
                break;
            case SECURITY:
            case IO:
            case RUNTIME:
                LoggingHelper.e(TAG, message, throwable);
                break;
            case INTERRUPTED:
                LoggingHelper.debug(message);
                break;
            default:
                LoggingHelper.e(TAG, message, throwable);
        }
    }

    /**
     * Wrap a checked exception in a RuntimeException if needed.
     *
     * @param throwable The exception to wrap
     * @return RuntimeException
     */
    @NonNull
    public static RuntimeException wrapIfNeeded(@NonNull Throwable throwable) {
        if (throwable instanceof RuntimeException) {
            return (RuntimeException) throwable;
        }
        return new RuntimeException(throwable);
    }

    /**
     * Rethrow if the exception is an Error (shouldn't be caught normally).
     *
     * @param throwable The throwable to check
     */
    public static void rethrowIfError(@NonNull Throwable throwable) {
        if (throwable instanceof Error) {
            throw (Error) throwable;
        }
    }

    /**
     * Rethrow if the exception is unchecked (RuntimeException or Error).
     *
     * @param throwable The throwable to check
     */
    public static void rethrowIfUnchecked(@NonNull Throwable throwable) {
        if (throwable instanceof RuntimeException) {
            throw (RuntimeException) throwable;
        }
        if (throwable instanceof Error) {
            throw (Error) throwable;
        }
    }
}
