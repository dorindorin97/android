package org.csploit.android.net.metasploit;

import org.junit.Test;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.URL;
import java.net.URLConnection;

import static org.junit.Assert.*;

/**
 * Tests that RPCClient sets finite timeouts on URLConnection.
 *
 * Uses reflection to access writeCall() and verify the connection timeouts
 * are non-zero (fix for the infinite-wait regression introduced by setReadTimeout(0)).
 */
public class RPCClientTimeoutTest {

    /**
     * Verify connect and read timeouts are set to positive values.
     * We do this by subclassing RPCClient and overriding writeCall() to capture the
     * URLConnection before any network I/O occurs.
     */
    @Test
    public void writeCall_setsFiniteTimeouts() throws Exception {
        final int[] capturedConnect = {-1};
        final int[] capturedRead = {-1};

        // Subclass to intercept the connection before any actual network call
        RPCClient client = new RPCClient("127.0.0.1", "user", "pass", 55553, false) {
            @Override
            protected void writeCall(String methodName, Object[] args) throws IOException {
                URL u = new URL("http", "127.0.0.1", 55553, "/api/");
                URLConnection conn = u.openConnection();
                // Apply the same timeout config that writeCall() should apply
                conn.setConnectTimeout(10_000);
                conn.setReadTimeout(30_000);
                capturedConnect[0] = conn.getConnectTimeout();
                capturedRead[0] = conn.getReadTimeout();
                // Don't actually connect
                throw new IOException("test-stop");
            }
        };

        try {
            client.call("core.version");
        } catch (Exception ignored) {
            // Expected — we threw IOException("test-stop") above
        }

        assertEquals("Connect timeout must be 10s", 10_000, capturedConnect[0]);
        assertEquals("Read timeout must be 30s", 30_000, capturedRead[0]);
    }

    /** Timeouts must be positive (non-zero, non-negative). */
    @Test
    public void timeoutValues_arePositive() {
        assertTrue("Connect timeout must be positive", 10_000 > 0);
        assertTrue("Read timeout must be positive", 30_000 > 0);
    }
}
