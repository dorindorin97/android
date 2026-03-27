package org.csploit.android.helpers;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;

/**
 * Utility class for exception handling, categorization, and user-friendly messaging.
 */
public class ExceptionHelper {

    private ExceptionHelper() {}

    public enum ExceptionCategory {
        TIMEOUT, NETWORK, IO, SECURITY, VALIDATION, UNKNOWN
    }

    /** Traverse the cause chain and return the root (deepest) cause. */
    public static Throwable getRootCause(Throwable t) {
        if (t == null) return null;
        Throwable cause = t.getCause();
        return cause == null ? t : getRootCause(cause);
    }

    /** Return the message of the root cause, or the class name if message is null. */
    public static String getRootCauseMessage(Throwable t) {
        Throwable root = getRootCause(t);
        if (root == null) return "Unknown error";
        String msg = root.getMessage();
        return msg != null ? msg : root.getClass().getSimpleName();
    }

    /** Categorize an exception based on its type. */
    public static ExceptionCategory categorize(Throwable t) {
        if (t == null) return ExceptionCategory.UNKNOWN;
        if (t instanceof SocketTimeoutException) return ExceptionCategory.TIMEOUT;
        if (t instanceof UnknownHostException || t instanceof ConnectException)
            return ExceptionCategory.NETWORK;
        if (t instanceof java.io.IOException) return ExceptionCategory.IO;
        if (t instanceof SecurityException || t instanceof GeneralSecurityException)
            return ExceptionCategory.SECURITY;
        if (t instanceof IllegalArgumentException || t instanceof IllegalStateException)
            return ExceptionCategory.VALIDATION;
        return ExceptionCategory.UNKNOWN;
    }

    /** Return true if this exception is a network-related exception. */
    public static boolean isNetworkException(Throwable t) {
        if (t == null) return false;
        ExceptionCategory cat = categorize(t);
        return cat == ExceptionCategory.NETWORK || cat == ExceptionCategory.TIMEOUT;
    }

    /** Return true if the operation that threw this exception may succeed on retry. */
    public static boolean isRetryable(Throwable t) {
        if (t == null) return false;
        ExceptionCategory cat = categorize(t);
        return cat == ExceptionCategory.TIMEOUT || cat == ExceptionCategory.NETWORK;
    }

    /** Return a user-friendly message for the exception. */
    public static String getUserFriendlyMessage(Throwable t) {
        if (t == null) return "Unknown error occurred";
        ExceptionCategory cat = categorize(t);
        switch (cat) {
            case TIMEOUT:  return "The operation timed out. Please try again.";
            case NETWORK:  return "Network connection error. Please check your connection.";
            case IO:       return "An I/O error occurred.";
            case SECURITY: return "A security error occurred.";
            case VALIDATION: return "Invalid input provided.";
            default:       return "An unknown error occurred: " + getRootCauseMessage(t);
        }
    }

    /** Return the full stack trace as a String. */
    public static String getStackTraceString(Throwable t) {
        if (t == null) return "";
        StringWriter sw = new StringWriter();
        t.printStackTrace(new PrintWriter(sw));
        return sw.toString();
    }

    /** Return up to {@code maxLines} lines of the stack trace. */
    public static String getCondensedStackTrace(Throwable t, int maxLines) {
        if (t == null) return "";
        String full = getStackTraceString(t);
        String[] lines = full.split("\n");
        if (lines.length <= maxLines) return full;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < maxLines; i++) {
            sb.append(lines[i]).append('\n');
        }
        sb.append("... ").append(lines.length - maxLines).append(" more");
        return sb.toString();
    }

    /** Wrap a checked exception in a RuntimeException if needed. */
    public static RuntimeException wrapIfNeeded(Throwable t) {
        if (t instanceof RuntimeException) return (RuntimeException) t;
        return new RuntimeException(t);
    }

    /** Return a short error code string for the exception. */
    public static String getErrorCode(Throwable t) {
        if (t == null) return "ERR_UNKNOWN";
        if (t instanceof UnknownHostException)  return "ERR_DNS";
        if (t instanceof ConnectException)      return "ERR_CONNECT";
        if (t instanceof SocketTimeoutException) return "ERR_TIMEOUT";
        if (t instanceof java.io.IOException)   return "ERR_IO";
        if (t instanceof SecurityException)     return "ERR_SECURITY";
        return "ERR_UNKNOWN";
    }

    /** Return true if the exception chain contains an exception of the given type. */
    public static boolean containsType(Throwable t, Class<? extends Throwable> type) {
        if (t == null || type == null) return false;
        if (type.isInstance(t)) return true;
        return containsType(t.getCause(), type);
    }
}
