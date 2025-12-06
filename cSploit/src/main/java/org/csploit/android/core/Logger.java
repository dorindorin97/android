package org.csploit.android.core;

import android.util.Log;

import java.io.PrintWriter;
import java.io.StringWriter;

/**
 * Enhanced Logger utility for cSploit.
 * Provides structured logging with automatic class/method name detection.
 */
public class Logger {
  private static final String TAG = "CSPLOIT";
  private static final String mClassName = Logger.class.getName();
  
  // Enable/disable verbose logging
  private static volatile boolean sDebugEnabled = true;

  private static void log(int priority, String message) {
    log(priority, message, null);
  }

  private static void log(int priority, String message, Throwable throwable) {
    // Skip debug logs if disabled
    if (!sDebugEnabled && priority <= Log.DEBUG) {
      return;
    }

    StackTraceElement[] els = Thread.currentThread().getStackTrace();
    String className = "unknown";
    String methodName = "unknown";
    int lineNumber = -1;

    for (StackTraceElement element : els) {
      String currClassName = element.getClassName();
      if (currClassName.startsWith("org.csploit.android.") && !currClassName.equals(mClassName)) {
        className = currClassName.replace("org.csploit.android.", "");
        methodName = element.getMethodName();
        lineNumber = element.getLineNumber();
        break;
      }
    }

    if (message == null) {
      message = "(null)";
    }

    String logTag = TAG + "[" + className + "." + methodName + ":" + lineNumber + "]";
    
    if (throwable != null) {
      String stackTrace = getStackTraceString(throwable);
      Log.println(priority, logTag, message + "\n" + stackTrace);
    } else {
      Log.println(priority, logTag, message);
    }
  }

  /**
   * Convert throwable to string representation
   */
  private static String getStackTraceString(Throwable throwable) {
    if (throwable == null) {
      return "";
    }
    StringWriter sw = new StringWriter();
    PrintWriter pw = new PrintWriter(sw);
    throwable.printStackTrace(pw);
    return sw.toString();
  }

  /**
   * Set whether debug logging is enabled
   * @param enabled true to enable debug logging
   */
  public static void setDebugEnabled(boolean enabled) {
    sDebugEnabled = enabled;
  }

  /**
   * Check if debug logging is enabled
   * @return true if debug logging is enabled
   */
  public static boolean isDebugEnabled() {
    return sDebugEnabled;
  }

  public static void verbose(String message) {
    log(Log.VERBOSE, message);
  }

  public static void debug(String message) {
    log(Log.DEBUG, message);
  }

  public static void info(String message) {
    log(Log.INFO, message);
  }

  public static void warning(String message) {
    log(Log.WARN, message);
  }

  public static void error(String message) {
    log(Log.ERROR, message);
  }

  /**
   * Log error with exception
   * @param message error message
   * @param throwable exception to log
   */
  public static void error(String message, Throwable throwable) {
    log(Log.ERROR, message, throwable);
  }

  /**
   * Log exception only
   * @param throwable exception to log
   */
  public static void exception(Throwable throwable) {
    log(Log.ERROR, "Exception occurred", throwable);
  }

  /**
   * Log with custom tag (useful for specific components)
   * @param tag custom tag
   * @param message log message
   */
  public static void debugWithTag(String tag, String message) {
    if (!sDebugEnabled) {
      return;
    }
    Log.d(TAG + "[" + tag + "]", message != null ? message : "(null)");
  }
}
