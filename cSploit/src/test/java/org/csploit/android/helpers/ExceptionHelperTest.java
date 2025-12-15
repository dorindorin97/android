package org.csploit.android.helpers;

import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.*;

import java.io.IOException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;

/**
 * Unit tests for ExceptionHelper
 */
public class ExceptionHelperTest {

    @Before
    public void setUp() {
        // Enable debug logging for tests
        LoggingHelper.setDebugEnabled(true);
    }

    @Test
    public void testGetRootCause_singleException() {
        Exception e = new IOException("Test error");
        Throwable root = ExceptionHelper.getRootCause(e);
        assertSame(e, root);
    }

    @Test
    public void testGetRootCause_chainedException() {
        IOException root = new IOException("Root cause");
        RuntimeException middle = new RuntimeException("Middle", root);
        Exception outer = new Exception("Outer", middle);
        
        Throwable result = ExceptionHelper.getRootCause(outer);
        assertSame(root, result);
    }

    @Test
    public void testGetRootCauseMessage() {
        Exception e = new IOException("Test error message");
        String message = ExceptionHelper.getRootCauseMessage(e);
        assertEquals("Test error message", message);
    }

    @Test
    public void testGetRootCauseMessage_nullMessage() {
        Exception e = new NullPointerException();
        String message = ExceptionHelper.getRootCauseMessage(e);
        assertEquals("NullPointerException", message);
    }

    @Test
    public void testCategorize_timeout() {
        SocketTimeoutException e = new SocketTimeoutException("Connection timed out");
        assertEquals(ExceptionHelper.ExceptionCategory.TIMEOUT, ExceptionHelper.categorize(e));
    }

    @Test
    public void testCategorize_network() {
        UnknownHostException e = new UnknownHostException("Unknown host");
        assertEquals(ExceptionHelper.ExceptionCategory.NETWORK, ExceptionHelper.categorize(e));
    }

    @Test
    public void testCategorize_io() {
        IOException e = new IOException("File not found");
        assertEquals(ExceptionHelper.ExceptionCategory.IO, ExceptionHelper.categorize(e));
    }

    @Test
    public void testCategorize_security() {
        SecurityException e = new SecurityException("Permission denied");
        assertEquals(ExceptionHelper.ExceptionCategory.SECURITY, ExceptionHelper.categorize(e));
    }

    @Test
    public void testCategorize_validation() {
        IllegalArgumentException e = new IllegalArgumentException("Invalid argument");
        assertEquals(ExceptionHelper.ExceptionCategory.VALIDATION, ExceptionHelper.categorize(e));
    }

    @Test
    public void testCategorize_null() {
        assertEquals(ExceptionHelper.ExceptionCategory.UNKNOWN, ExceptionHelper.categorize(null));
    }

    @Test
    public void testIsNetworkException_true() {
        assertTrue(ExceptionHelper.isNetworkException(new UnknownHostException()));
        assertTrue(ExceptionHelper.isNetworkException(new ConnectException()));
    }

    @Test
    public void testIsNetworkException_false() {
        assertFalse(ExceptionHelper.isNetworkException(new IllegalArgumentException()));
        assertFalse(ExceptionHelper.isNetworkException(null));
    }

    @Test
    public void testIsRetryable_timeout() {
        assertTrue(ExceptionHelper.isRetryable(new SocketTimeoutException()));
    }

    @Test
    public void testIsRetryable_network() {
        assertTrue(ExceptionHelper.isRetryable(new ConnectException()));
    }

    @Test
    public void testIsRetryable_notRetryable() {
        assertFalse(ExceptionHelper.isRetryable(new IllegalArgumentException()));
        assertFalse(ExceptionHelper.isRetryable(new NullPointerException()));
    }

    @Test
    public void testGetUserFriendlyMessage_timeout() {
        String message = ExceptionHelper.getUserFriendlyMessage(new SocketTimeoutException());
        assertTrue(message.contains("timed out"));
    }

    @Test
    public void testGetUserFriendlyMessage_network() {
        String message = ExceptionHelper.getUserFriendlyMessage(new UnknownHostException());
        assertTrue(message.contains("Network") || message.contains("connection"));
    }

    @Test
    public void testGetUserFriendlyMessage_null() {
        String message = ExceptionHelper.getUserFriendlyMessage(null);
        assertNotNull(message);
        assertTrue(message.contains("Unknown"));
    }

    @Test
    public void testGetStackTraceString() {
        Exception e = new IOException("Test");
        String trace = ExceptionHelper.getStackTraceString(e);
        assertNotNull(trace);
        assertTrue(trace.contains("IOException"));
        assertTrue(trace.contains("Test"));
    }

    @Test
    public void testGetCondensedStackTrace() {
        Exception e = new IOException("Test");
        String trace = ExceptionHelper.getCondensedStackTrace(e, 3);
        assertNotNull(trace);
        // Should be limited
        String[] lines = trace.split("\n");
        assertTrue(lines.length <= 10); // Limited lines plus "more" message
    }

    @Test
    public void testWrapIfNeeded_runtime() {
        RuntimeException e = new RuntimeException("Test");
        RuntimeException result = ExceptionHelper.wrapIfNeeded(e);
        assertSame(e, result);
    }

    @Test
    public void testWrapIfNeeded_checked() {
        IOException e = new IOException("Test");
        RuntimeException result = ExceptionHelper.wrapIfNeeded(e);
        assertNotSame(e, result);
        assertSame(e, result.getCause());
    }

    @Test
    public void testGetErrorCode_network() {
        assertEquals("ERR_DNS", ExceptionHelper.getErrorCode(new UnknownHostException()));
        assertEquals("ERR_CONNECT", ExceptionHelper.getErrorCode(new ConnectException()));
    }

    @Test
    public void testGetErrorCode_timeout() {
        assertEquals("ERR_TIMEOUT", ExceptionHelper.getErrorCode(new SocketTimeoutException()));
    }

    @Test
    public void testGetErrorCode_null() {
        assertEquals("ERR_UNKNOWN", ExceptionHelper.getErrorCode(null));
    }

    @Test
    public void testContainsType_found() {
        IOException root = new IOException("Root");
        RuntimeException outer = new RuntimeException("Outer", root);
        
        assertTrue(ExceptionHelper.containsType(outer, IOException.class));
        assertTrue(ExceptionHelper.containsType(outer, RuntimeException.class));
    }

    @Test
    public void testContainsType_notFound() {
        IOException e = new IOException("Test");
        assertFalse(ExceptionHelper.containsType(e, SecurityException.class));
    }

    @Test
    public void testContainsType_null() {
        assertFalse(ExceptionHelper.containsType(null, IOException.class));
    }
}
