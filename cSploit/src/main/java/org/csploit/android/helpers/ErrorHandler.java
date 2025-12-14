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

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * Centralized error handling framework for cSploit.
 *
 * Provides:
 * - Custom exception hierarchy
 * - Error codes for user-friendly messaging
 * - Error recovery strategies
 * - Error statistics tracking
 * - Callback-based error notification
 */
public final class ErrorHandler {

    private static final String TAG = "ErrorHandler";

    /**
     * Error severity levels
     */
    public enum Severity {
        DEBUG,      // Debug information
        INFO,       // Informational
        WARNING,    // Non-critical issue
        ERROR,      // Recoverable error
        CRITICAL    // Fatal error
    }

    /**
     * Error categories for classification
     */
    public enum Category {
        NETWORK,        // Network-related errors
        SECURITY,       // Security-related errors
        IO,             // File/IO errors
        PERMISSION,     // Permission errors
        CONFIGURATION,  // Configuration errors
        VALIDATION,     // Input validation errors
        INTERNAL,       // Internal application errors
        EXTERNAL,       // External service errors
        UNKNOWN         // Uncategorized errors
    }

    /**
     * Error codes with user-friendly messages
     */
    public enum ErrorCode {
        // Network errors (1000-1999)
        NETWORK_UNAVAILABLE(1000, "Network is unavailable"),
        CONNECTION_TIMEOUT(1001, "Connection timed out"),
        CONNECTION_REFUSED(1002, "Connection refused"),
        HOST_UNREACHABLE(1003, "Host is unreachable"),
        DNS_RESOLUTION_FAILED(1004, "DNS resolution failed"),
        SSL_HANDSHAKE_FAILED(1005, "SSL handshake failed"),
        SOCKET_CLOSED(1006, "Socket was closed unexpectedly"),
        NETWORK_INTERFACE_ERROR(1007, "Network interface error"),

        // Security errors (2000-2999)
        AUTHENTICATION_FAILED(2000, "Authentication failed"),
        AUTHORIZATION_DENIED(2001, "Authorization denied"),
        CERTIFICATE_ERROR(2002, "Certificate validation error"),
        ENCRYPTION_ERROR(2003, "Encryption error"),
        DECRYPTION_ERROR(2004, "Decryption error"),
        SIGNATURE_INVALID(2005, "Invalid signature"),

        // IO errors (3000-3999)
        FILE_NOT_FOUND(3000, "File not found"),
        FILE_ACCESS_DENIED(3001, "File access denied"),
        DISK_FULL(3002, "Disk is full"),
        READ_ERROR(3003, "Read error"),
        WRITE_ERROR(3004, "Write error"),

        // Permission errors (4000-4999)
        PERMISSION_DENIED(4000, "Permission denied"),
        ROOT_REQUIRED(4001, "Root access required"),
        STORAGE_PERMISSION_NEEDED(4002, "Storage permission required"),

        // Configuration errors (5000-5999)
        INVALID_CONFIGURATION(5000, "Invalid configuration"),
        MISSING_CONFIGURATION(5001, "Missing configuration"),
        INITIALIZATION_FAILED(5002, "Initialization failed"),

        // Validation errors (6000-6999)
        INVALID_INPUT(6000, "Invalid input"),
        INVALID_IP_ADDRESS(6001, "Invalid IP address"),
        INVALID_PORT(6002, "Invalid port number"),
        INVALID_MAC_ADDRESS(6003, "Invalid MAC address"),
        INVALID_FORMAT(6004, "Invalid format"),

        // Internal errors (7000-7999)
        INTERNAL_ERROR(7000, "Internal error"),
        NULL_POINTER(7001, "Null value encountered"),
        ILLEGAL_STATE(7002, "Illegal state"),
        UNSUPPORTED_OPERATION(7003, "Unsupported operation"),

        // External errors (8000-8999)
        SERVICE_UNAVAILABLE(8000, "Service unavailable"),
        RATE_LIMITED(8001, "Rate limited"),
        API_ERROR(8002, "API error"),

        // Generic
        UNKNOWN_ERROR(9999, "An unknown error occurred");

        private final int code;
        private final String message;

        ErrorCode(int code, String message) {
            this.code = code;
            this.message = message;
        }

        public int getCode() { return code; }
        public String getMessage() { return message; }
    }

    /**
     * Custom application exception
     */
    public static class AppException extends Exception {
        private final ErrorCode errorCode;
        private final Category category;
        private final Severity severity;

        public AppException(ErrorCode errorCode, Category category, Severity severity) {
            super(errorCode.getMessage());
            this.errorCode = errorCode;
            this.category = category;
            this.severity = severity;
        }

        public AppException(ErrorCode errorCode, Category category, Severity severity, Throwable cause) {
            super(errorCode.getMessage(), cause);
            this.errorCode = errorCode;
            this.category = category;
            this.severity = severity;
        }

        public AppException(ErrorCode errorCode, Category category, Severity severity, String details) {
            super(errorCode.getMessage() + ": " + details);
            this.errorCode = errorCode;
            this.category = category;
            this.severity = severity;
        }

        public ErrorCode getErrorCode() { return errorCode; }
        public Category getCategory() { return category; }
        public Severity getSeverity() { return severity; }
    }

    /**
     * Error context with additional information
     */
    public static class ErrorContext {
        private final Throwable throwable;
        private final ErrorCode errorCode;
        private final Category category;
        private final Severity severity;
        private final long timestamp;
        private final String source;

        public ErrorContext(Throwable throwable, ErrorCode errorCode, Category category,
                          Severity severity, String source) {
            this.throwable = throwable;
            this.errorCode = errorCode;
            this.category = category;
            this.severity = severity;
            this.timestamp = System.currentTimeMillis();
            this.source = source;
        }

        public Throwable getThrowable() { return throwable; }
        public ErrorCode getErrorCode() { return errorCode; }
        public Category getCategory() { return category; }
        public Severity getSeverity() { return severity; }
        public long getTimestamp() { return timestamp; }
        public String getSource() { return source; }
    }

    // Error statistics
    private static final ConcurrentHashMap<ErrorCode, AtomicInteger> errorCounts = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<Category, AtomicInteger> categoryCounts = new ConcurrentHashMap<>();

    // Global error listeners
    private static Consumer<ErrorContext> globalErrorListener = null;

    private ErrorHandler() {}

    /**
     * Set global error listener for monitoring all errors
     */
    public static void setGlobalErrorListener(@Nullable Consumer<ErrorContext> listener) {
        globalErrorListener = listener;
    }

    /**
     * Handle an exception with automatic classification
     */
    public static void handle(@NonNull Throwable throwable, @NonNull String source) {
        ErrorCode code = classifyException(throwable);
        Category category = classifyCategory(throwable);
        Severity severity = classifySeverity(throwable);

        handleInternal(throwable, code, category, severity, source);
    }

    /**
     * Handle an exception with specific error code
     */
    public static void handle(@NonNull Throwable throwable, @NonNull ErrorCode code,
                             @NonNull String source) {
        Category category = getCategoryForCode(code);
        Severity severity = classifySeverity(throwable);

        handleInternal(throwable, code, category, severity, source);
    }

    /**
     * Handle an exception with full context
     */
    public static void handle(@NonNull Throwable throwable, @NonNull ErrorCode code,
                             @NonNull Category category, @NonNull Severity severity,
                             @NonNull String source) {
        handleInternal(throwable, code, category, severity, source);
    }

    private static void handleInternal(Throwable throwable, ErrorCode code, Category category,
                                       Severity severity, String source) {
        // Track statistics
        errorCounts.computeIfAbsent(code, k -> new AtomicInteger(0)).incrementAndGet();
        categoryCounts.computeIfAbsent(category, k -> new AtomicInteger(0)).incrementAndGet();

        // Log the error
        String message = String.format("[%s] %s: %s - %s",
                severity, code.name(), code.getMessage(), throwable.getMessage());

        switch (severity) {
            case DEBUG:
                LoggingHelper.d(source, message);
                break;
            case INFO:
                LoggingHelper.i(source, message);
                break;
            case WARNING:
                LoggingHelper.w(source, message);
                break;
            case ERROR:
            case CRITICAL:
                LoggingHelper.e(source, message, throwable);
                break;
        }

        // Notify listener
        if (globalErrorListener != null) {
            ErrorContext context = new ErrorContext(throwable, code, category, severity, source);
            try {
                globalErrorListener.accept(context);
            } catch (Exception e) {
                LoggingHelper.e(TAG, "Error in global error listener", e);
            }
        }
    }

    /**
     * Classify exception to error code
     */
    private static ErrorCode classifyException(Throwable throwable) {
        String className = throwable.getClass().getName();
        String message = throwable.getMessage() != null ? throwable.getMessage().toLowerCase() : "";

        // Network exceptions
        if (className.contains("SocketTimeoutException") || message.contains("timeout")) {
            return ErrorCode.CONNECTION_TIMEOUT;
        }
        if (className.contains("ConnectException") || message.contains("connection refused")) {
            return ErrorCode.CONNECTION_REFUSED;
        }
        if (className.contains("UnknownHostException")) {
            return ErrorCode.DNS_RESOLUTION_FAILED;
        }
        if (className.contains("NoRouteToHostException") || message.contains("unreachable")) {
            return ErrorCode.HOST_UNREACHABLE;
        }
        if (className.contains("SSLException") || className.contains("SSLHandshakeException")) {
            return ErrorCode.SSL_HANDSHAKE_FAILED;
        }
        if (className.contains("SocketException")) {
            return ErrorCode.SOCKET_CLOSED;
        }

        // IO exceptions
        if (className.contains("FileNotFoundException")) {
            return ErrorCode.FILE_NOT_FOUND;
        }
        if (className.contains("IOException")) {
            if (message.contains("permission")) {
                return ErrorCode.FILE_ACCESS_DENIED;
            }
            if (message.contains("space") || message.contains("disk full")) {
                return ErrorCode.DISK_FULL;
            }
            return ErrorCode.READ_ERROR;
        }

        // Security exceptions
        if (className.contains("SecurityException")) {
            return ErrorCode.PERMISSION_DENIED;
        }
        if (className.contains("CertificateException")) {
            return ErrorCode.CERTIFICATE_ERROR;
        }

        // Validation exceptions
        if (className.contains("IllegalArgumentException")) {
            return ErrorCode.INVALID_INPUT;
        }
        if (className.contains("NumberFormatException")) {
            return ErrorCode.INVALID_FORMAT;
        }

        // Internal exceptions
        if (className.contains("NullPointerException")) {
            return ErrorCode.NULL_POINTER;
        }
        if (className.contains("IllegalStateException")) {
            return ErrorCode.ILLEGAL_STATE;
        }
        if (className.contains("UnsupportedOperationException")) {
            return ErrorCode.UNSUPPORTED_OPERATION;
        }

        return ErrorCode.UNKNOWN_ERROR;
    }

    /**
     * Classify exception to category
     */
    private static Category classifyCategory(Throwable throwable) {
        String className = throwable.getClass().getName();

        if (className.contains("net.") || className.contains("Socket") ||
            className.contains("Connection") || className.contains("Http")) {
            return Category.NETWORK;
        }
        if (className.contains("security.") || className.contains("SSL") ||
            className.contains("Certificate") || className.contains("Cipher")) {
            return Category.SECURITY;
        }
        if (className.contains("io.") || className.contains("File") ||
            className.contains("Stream")) {
            return Category.IO;
        }
        if (className.contains("SecurityException") ||
            className.contains("Permission")) {
            return Category.PERMISSION;
        }
        if (className.contains("IllegalArgument") ||
            className.contains("NumberFormat")) {
            return Category.VALIDATION;
        }

        return Category.INTERNAL;
    }

    /**
     * Classify exception to severity
     */
    private static Severity classifySeverity(Throwable throwable) {
        if (throwable instanceof Error) {
            return Severity.CRITICAL;
        }
        if (throwable instanceof SecurityException) {
            return Severity.ERROR;
        }
        if (throwable instanceof IllegalArgumentException ||
            throwable instanceof IllegalStateException) {
            return Severity.WARNING;
        }
        return Severity.ERROR;
    }

    /**
     * Get category for error code
     */
    private static Category getCategoryForCode(ErrorCode code) {
        int codeNum = code.getCode();
        if (codeNum >= 1000 && codeNum < 2000) return Category.NETWORK;
        if (codeNum >= 2000 && codeNum < 3000) return Category.SECURITY;
        if (codeNum >= 3000 && codeNum < 4000) return Category.IO;
        if (codeNum >= 4000 && codeNum < 5000) return Category.PERMISSION;
        if (codeNum >= 5000 && codeNum < 6000) return Category.CONFIGURATION;
        if (codeNum >= 6000 && codeNum < 7000) return Category.VALIDATION;
        if (codeNum >= 7000 && codeNum < 8000) return Category.INTERNAL;
        if (codeNum >= 8000 && codeNum < 9000) return Category.EXTERNAL;
        return Category.UNKNOWN;
    }

    /**
     * Get error count for specific error code
     */
    public static int getErrorCount(@NonNull ErrorCode code) {
        AtomicInteger count = errorCounts.get(code);
        return count != null ? count.get() : 0;
    }

    /**
     * Get error count for specific category
     */
    public static int getCategoryErrorCount(@NonNull Category category) {
        AtomicInteger count = categoryCounts.get(category);
        return count != null ? count.get() : 0;
    }

    /**
     * Get total error count
     */
    public static int getTotalErrorCount() {
        return errorCounts.values().stream().mapToInt(AtomicInteger::get).sum();
    }

    /**
     * Reset error statistics
     */
    public static void resetStatistics() {
        errorCounts.clear();
        categoryCounts.clear();
    }

    /**
     * Get stack trace as string
     */
    @NonNull
    public static String getStackTraceString(@NonNull Throwable throwable) {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        throwable.printStackTrace(pw);
        return sw.toString();
    }

    /**
     * Get root cause of exception chain
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
     * Create wrapped AppException from any throwable
     */
    @NonNull
    public static AppException wrap(@NonNull Throwable throwable) {
        if (throwable instanceof AppException) {
            return (AppException) throwable;
        }

        ErrorCode code = classifyException(throwable);
        Category category = classifyCategory(throwable);
        Severity severity = classifySeverity(throwable);

        return new AppException(code, category, severity, throwable);
    }

    /**
     * Execute a runnable with error handling
     */
    public static void safeExecute(@NonNull Runnable action, @NonNull String source) {
        try {
            action.run();
        } catch (Exception e) {
            handle(e, source);
        }
    }

    /**
     * Execute a supplier with error handling and default value
     */
    @Nullable
    public static <T> T safeGet(@NonNull java.util.function.Supplier<T> supplier,
                                @Nullable T defaultValue, @NonNull String source) {
        try {
            return supplier.get();
        } catch (Exception e) {
            handle(e, source);
            return defaultValue;
        }
    }
}
