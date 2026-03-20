package org.csploit.android.net;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Unit tests for RemoteReader — validates that the HashMap-backed host registry
 * and case-insensitive host comparison behave correctly without network I/O.
 */
public class RemoteReaderTest {

    /** fromHost() with same host (different case) must return the same reader instance. */
    @Test
    public void fromHost_caseInsensitive_returnsSameInstance() throws Exception {
        RemoteReader a = RemoteReader.fromHost("Example.COM");
        RemoteReader b = RemoteReader.fromHost("example.com");
        assertSame("Same host with different case must resolve to the same RemoteReader", a, b);
    }

    /** fromHost() with different hosts must return different instances. */
    @Test
    public void fromHost_differentHosts_returnsDifferentInstances() throws Exception {
        RemoteReader a = RemoteReader.fromHost("host-alpha.example.com");
        RemoteReader b = RemoteReader.fromHost("host-beta.example.com");
        assertNotSame("Different hosts must have different RemoteReader instances", a, b);
    }

    /** terminateAll() must not throw even when no readers have been created. */
    @Test
    public void terminateAll_withNoReaders_doesNotThrow() {
        RemoteReader.terminateAll();
        // No exception = pass
    }

    /** fromUrl() must delegate to fromHost() using the URL's host component. */
    @Test
    public void fromUrl_extractsHostCorrectly() throws Exception {
        RemoteReader byUrl  = RemoteReader.fromUrl("https://api.github.com/repos/foo/bar");
        RemoteReader byHost = RemoteReader.fromHost("api.github.com");
        assertSame("fromUrl and fromHost with same host must return same instance", byUrl, byHost);
    }
}
