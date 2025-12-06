package org.csploit.android.helpers;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Unit tests for InputSanitizer
 */
public class InputSanitizerTest {

    // ==================== Shell Sanitization Tests ====================

    @Test
    public void testSanitizeForShell_RemovesDangerousChars() {
        assertEquals("ls", InputSanitizer.sanitizeForShell("ls; rm -rf /"));
        assertEquals("echo hello", InputSanitizer.sanitizeForShell("echo hello | cat"));
        assertEquals("test", InputSanitizer.sanitizeForShell("test`id`"));
        assertEquals("cmd", InputSanitizer.sanitizeForShell("cmd$(whoami)"));
        assertEquals("safe", InputSanitizer.sanitizeForShell("safe"));
    }

    @Test
    public void testSanitizeForShell_HandlesNullAndEmpty() {
        assertEquals("", InputSanitizer.sanitizeForShell(null));
        assertEquals("", InputSanitizer.sanitizeForShell(""));
    }

    @Test
    public void testEscapeForShell() {
        assertEquals("test", InputSanitizer.escapeForShell("test"));
        assertEquals("it'\"'\"'s", InputSanitizer.escapeForShell("it's"));
        assertEquals("", InputSanitizer.escapeForShell(null));
    }

    @Test
    public void testContainsShellDangerousChars() {
        assertTrue(InputSanitizer.containsShellDangerousChars("test;cmd"));
        assertTrue(InputSanitizer.containsShellDangerousChars("test|cmd"));
        assertTrue(InputSanitizer.containsShellDangerousChars("test`cmd`"));
        assertTrue(InputSanitizer.containsShellDangerousChars("test$(cmd)"));
        assertFalse(InputSanitizer.containsShellDangerousChars("safe-input_123"));
        assertFalse(InputSanitizer.containsShellDangerousChars(null));
        assertFalse(InputSanitizer.containsShellDangerousChars(""));
    }

    // ==================== Path Sanitization Tests ====================

    @Test
    public void testSanitizeFilePath_RemovesTraversal() {
        assertEquals("/etc/passwd", InputSanitizer.sanitizeFilePath("../../../etc/passwd"));
        assertEquals("/etc/passwd", InputSanitizer.sanitizeFilePath("....//....//etc/passwd"));
        assertEquals("file.txt", InputSanitizer.sanitizeFilePath("file.txt"));
        assertEquals("/home/user/file.txt", InputSanitizer.sanitizeFilePath("/home/user/file.txt"));
    }

    @Test
    public void testSanitizeFilePath_HandlesNullAndEmpty() {
        assertEquals("", InputSanitizer.sanitizeFilePath(null));
        assertEquals("", InputSanitizer.sanitizeFilePath(""));
    }

    @Test
    public void testContainsPathTraversal() {
        assertTrue(InputSanitizer.containsPathTraversal("../secret"));
        assertTrue(InputSanitizer.containsPathTraversal("..\\secret"));
        assertTrue(InputSanitizer.containsPathTraversal("foo/../bar"));
        assertFalse(InputSanitizer.containsPathTraversal("/home/user/file.txt"));
        assertFalse(InputSanitizer.containsPathTraversal(null));
    }

    @Test
    public void testExtractSafeFilename() {
        assertEquals("file.txt", InputSanitizer.extractSafeFilename("/path/to/file.txt"));
        assertEquals("file.txt", InputSanitizer.extractSafeFilename("C:\\path\\to\\file.txt"));
        assertEquals("_file_.txt", InputSanitizer.extractSafeFilename("<file>.txt"));
        assertEquals("test.txt", InputSanitizer.extractSafeFilename("../test.txt"));
        assertEquals("", InputSanitizer.extractSafeFilename(null));
    }

    // ==================== SQL Sanitization Tests ====================

    @Test
    public void testSanitizeForSql() {
        assertEquals("test", InputSanitizer.sanitizeForSql("test"));
        assertEquals("O''''Reilly", InputSanitizer.sanitizeForSql("O''Reilly"));
        assertEquals("test", InputSanitizer.sanitizeForSql("test; DROP TABLE users;"));
        assertEquals("", InputSanitizer.sanitizeForSql(null));
    }

    // ==================== Network Sanitization Tests ====================

    @Test
    public void testSanitizeHostname() {
        assertEquals("example.com", InputSanitizer.sanitizeHostname("example.com"));
        assertEquals("192.168.1.1", InputSanitizer.sanitizeHostname("192.168.1.1"));
        assertEquals("sub.example.com", InputSanitizer.sanitizeHostname("sub.example.com"));
        assertEquals("", InputSanitizer.sanitizeHostname("example.com; cat /etc/passwd"));
        assertEquals("", InputSanitizer.sanitizeHostname(null));
    }

    @Test
    public void testSanitizePort() {
        assertEquals("80", InputSanitizer.sanitizePort("80"));
        assertEquals("443", InputSanitizer.sanitizePort("443"));
        assertEquals("8080", InputSanitizer.sanitizePort("8080"));
        assertEquals("", InputSanitizer.sanitizePort("0"));
        assertEquals("", InputSanitizer.sanitizePort("70000"));
        assertEquals("", InputSanitizer.sanitizePort("abc"));
        assertEquals("", InputSanitizer.sanitizePort(null));
    }

    // ==================== URL Sanitization Tests ====================

    @Test
    public void testSanitizeUrlParam() {
        assertEquals("hello%20world", InputSanitizer.sanitizeUrlParam("hello world"));
        assertEquals("test%26param", InputSanitizer.sanitizeUrlParam("test&param"));
        assertEquals("", InputSanitizer.sanitizeUrlParam(null));
        assertEquals("", InputSanitizer.sanitizeUrlParam(""));
    }

    // ==================== HTML Sanitization Tests ====================

    @Test
    public void testSanitizeHtml() {
        assertEquals("&lt;script&gt;alert(1)&lt;&#x2F;script&gt;",
                InputSanitizer.sanitizeHtml("<script>alert(1)</script>"));
        assertEquals("&lt;img src=&#x27;x&#x27; onerror=&#x27;alert(1)&#x27;&gt;",
                InputSanitizer.sanitizeHtml("<img src='x' onerror='alert(1)'>"));
        assertEquals("safe text", InputSanitizer.sanitizeHtml("safe text"));
        assertEquals("", InputSanitizer.sanitizeHtml(null));
    }

    // ==================== Validation Tests ====================

    @Test
    public void testIsSafeAlphanumeric() {
        assertTrue(InputSanitizer.isSafeAlphanumeric("test123"));
        assertTrue(InputSanitizer.isSafeAlphanumeric("test_name"));
        assertTrue(InputSanitizer.isSafeAlphanumeric("test-name"));
        assertTrue(InputSanitizer.isSafeAlphanumeric("test.name"));
        assertFalse(InputSanitizer.isSafeAlphanumeric("test name"));
        assertFalse(InputSanitizer.isSafeAlphanumeric("test;cmd"));
        assertFalse(InputSanitizer.isSafeAlphanumeric(null));
        assertFalse(InputSanitizer.isSafeAlphanumeric(""));
    }

    // ==================== Control Character Tests ====================

    @Test
    public void testStripControlChars() {
        assertEquals("test", InputSanitizer.stripControlChars("test\u0000"));
        assertEquals("hello world", InputSanitizer.stripControlChars("hello\u0001 world"));
        assertEquals("test\n", InputSanitizer.stripControlChars("test\n")); // newline preserved
        assertEquals("", InputSanitizer.stripControlChars(null));
    }

    // ==================== Length Limit Tests ====================

    @Test
    public void testLimitLength() {
        assertEquals("test", InputSanitizer.limitLength("test", 10));
        assertEquals("hello", InputSanitizer.limitLength("hello world", 5));
        assertEquals("", InputSanitizer.limitLength("test", 0));
        assertEquals("", InputSanitizer.limitLength(null, 10));
    }
}
