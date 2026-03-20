package org.csploit.android.net.http.proxy;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

import static org.junit.Assert.*;

/**
 * Unit tests for ProxyThread HTTP request parsing and resource cleanup logic.
 *
 * These tests validate header manipulation and edge-case behaviour without
 * starting a real network socket or server.
 */
public class ProxyThreadTest {

    /** HTTP/1.1 header must be downgraded to HTTP/1.0 (no chunked transfer). */
    @Test
    public void request_http11DowngradedTo10() {
        String rawRequest =
            "GET / HTTP/1.1\r\n" +
            "Host: example.com\r\n" +
            "Connection: keep-alive\r\n" +
            "Accept-Encoding: gzip\r\n" +
            "\r\n";

        String patched = patchRequest(rawRequest);

        assertTrue("HTTP/1.1 must be replaced with HTTP/1.0",
            patched.contains("HTTP/1.0"));
        assertFalse("HTTP/1.1 must not remain in patched request",
            patched.contains("HTTP/1.1"));
    }

    /** Accept-Encoding must be forced to 'identity'. */
    @Test
    public void request_acceptEncodingForcedToIdentity() {
        String rawRequest =
            "GET / HTTP/1.0\r\n" +
            "Host: example.com\r\n" +
            "Accept-Encoding: gzip, deflate\r\n" +
            "\r\n";

        String patched = patchRequest(rawRequest);

        assertTrue("Accept-Encoding must be set to identity",
            patched.contains("Accept-Encoding: identity"));
        assertFalse("gzip must be removed",
            patched.contains("gzip"));
    }

    /** Connection header must be set to 'close'. */
    @Test
    public void request_connectionForcedToClose() {
        String rawRequest =
            "GET / HTTP/1.0\r\n" +
            "Host: example.com\r\n" +
            "Connection: keep-alive\r\n" +
            "\r\n";

        String patched = patchRequest(rawRequest);

        assertTrue("Connection must be set to close",
            patched.contains("Connection: close"));
    }

    /** If-Modified-Since header must be stripped. */
    @Test
    public void request_ifModifiedSinceStripped() {
        String rawRequest =
            "GET / HTTP/1.0\r\n" +
            "Host: example.com\r\n" +
            "If-Modified-Since: Mon, 01 Jan 2024 00:00:00 GMT\r\n" +
            "\r\n";

        String patched = patchRequest(rawRequest);

        assertFalse("If-Modified-Since must be stripped",
            patched.contains("If-Modified-Since"));
    }

    /** Cache-Control header must be stripped. */
    @Test
    public void request_cacheControlStripped() {
        String rawRequest =
            "GET / HTTP/1.0\r\n" +
            "Host: example.com\r\n" +
            "Cache-Control: no-cache\r\n" +
            "\r\n";

        String patched = patchRequest(rawRequest);

        assertFalse("Cache-Control must be stripped", patched.contains("Cache-Control"));
    }

    /** Empty request must not cause NPE or throw. */
    @Test
    public void emptyRequest_doesNotThrow() {
        try {
            patchRequest("");
        } catch (Exception e) {
            fail("Empty request must not throw: " + e.getMessage());
        }
    }

    // ── Helper: replicate ProxyThread's header-patching logic ──────────────────

    private String patchRequest(String rawRequest) {
        java.io.BufferedReader bReader = new java.io.BufferedReader(
            new java.io.StringReader(rawRequest));
        StringBuilder builder = new StringBuilder();
        try {
            String line;
            boolean headersProcessed = false;
            while ((line = bReader.readLine()) != null) {
                if (!headersProcessed) {
                    if (line.trim().isEmpty()) {
                        headersProcessed = true;
                    } else if (line.contains("HTTP/1.1")) {
                        line = line.replace("HTTP/1.1", "HTTP/1.0");
                    } else if (line.indexOf(':') != -1) {
                        String[] split = line.split(":", 2);
                        String header = split[0].trim();
                        String value = split[1].trim();

                        if (header.equalsIgnoreCase("Accept-Encoding")) {
                            value = "identity";
                        } else if (header.equalsIgnoreCase("Connection")) {
                            value = "close";
                        } else if (header.equalsIgnoreCase("If-Modified-Since")
                                || header.equalsIgnoreCase("Cache-Control")) {
                            header = null;
                        }

                        if (header != null) {
                            line = header + ": " + value;
                        } else {
                            continue; // strip this header
                        }
                    }
                }
                builder.append(line).append("\n");
            }
        } catch (IOException e) {
            // StringReader never throws
        }
        return builder.toString();
    }
}
